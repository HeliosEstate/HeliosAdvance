// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// QA's own SSH client, written from RFC 4253, RFC 4252, RFC 4254, RFC 5647, RFC 8308, RFC 8731,
// and the extensions kex-strict-c-v00@openssh.com and ping@openssh.com, on the standard library
// alone, apart from the engine's code and from the library the engine is built on. It sends what
// the page's oracle client will not: any message in any order.
package ssh_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// Message numbers, RFC 4250 section 4.1, and those of the ping@openssh.com extension.
const (
	messageDisconnect          = 1
	messageIgnore              = 2
	messageDebug               = 4
	messageServiceRequest      = 5
	messageServiceAccept       = 6
	messageExtensionInfo       = 7
	messageKexInit             = 20
	messageNewKeys             = 21
	messageKexInit30           = 30
	messageKexReply31          = 31
	messageUserauthRequest     = 50
	messageUserauthFailure     = 51
	messageUserauthSuccess     = 52
	messageGlobalRequest       = 80
	messageRequestSuccess      = 81
	messageRequestFailure      = 82
	messageChannelOpen         = 90
	messageChannelConfirmation = 91
	messageChannelOpenFailure  = 92
	messageWindowAdjust        = 93
	messageChannelData         = 94
	messageExtendedData        = 95
	messageChannelEOF          = 96
	messageChannelClose        = 97
	messageChannelRequest      = 98
	messageChannelSuccess      = 99
	messageChannelFailure      = 100
	messagePing                = 192
	messagePong                = 193
)

const (
	clientVersion      = "SSH-2.0-QAClient"
	strictClientMarker = "kex-strict-c-v00@openssh.com"
	extensionMarker    = "ext-info-c"
	// clientWindow is what the client lets the engine send before it adjusts; a client that never
	// reads grants less.
	clientWindow    = 1 << 20
	clientMaxPacket = 32768
	packetMost      = 256 * 1024
	gcmTagSize      = 16
)

// kexOffer is the client's KEXINIT: the lists it sends, each comma-joined on the wire.
type kexOffer struct {
	kex, hostKeys, ciphers, macs, compression []string
}

func defaultOffer(kex string, strict bool) kexOffer {
	kexList := []string{kex, extensionMarker}
	if strict {
		kexList = append(kexList, strictClientMarker)
	}
	return kexOffer{
		kex:         kexList,
		hostKeys:    []string{ed25519Name},
		ciphers:     []string{"aes128-gcm@openssh.com"},
		macs:        []string{"hmac-sha2-256-etm@openssh.com"},
		compression: []string{"none"},
	}
}

// gcmDirection is one direction's AES-GCM state (RFC 5647, as OpenSSH's aes128-gcm@openssh.com):
// the packet length is sent in clear as the additional data, and the nonce's last 8 bytes count
// the packets.
type gcmDirection struct {
	aead  cipher.AEAD
	nonce [12]byte
}

func (direction *gcmDirection) advance() {
	counter := binary.BigEndian.Uint64(direction.nonce[4:])
	binary.BigEndian.PutUint64(direction.nonce[4:], counter+1)
}

// rawClient is one connection to the engine, at whatever stage a row needs it.
type rawClient struct {
	t             *testing.T
	connection    *net.TCPConn
	serverVersion []byte
	pending       []byte
	sendCipher    *gcmDirection
	receiveCipher *gcmDirection
	sessionID     []byte
	hostKey       []byte
	// serverKexInit is the server's KEXINIT payload as sent.
	serverKexInit []byte
	clientKexInit []byte
	// windowToServer is how much channel data the engine still lets this client send.
	windowToServer uint32
	// windowFromServer is how much the client has let the engine send since it last adjusted.
	windowFromServer uint32
	adjustWindow     bool
	// engineChannel is the number the engine gave the session in its confirmation, which every
	// message about the channel must carry: the engine may number it other than 0, as when a
	// channel it refused still held 0.
	engineChannel uint32
	// received holds the channel data and when each byte arrived, for the timed rows.
	received   []byte
	receivedAt []time.Time
}

// dialRaw connects and sends the client's version line; it reads nothing.
func dialRaw(t *testing.T, address string) *rawClient {
	t.Helper()
	dialer := net.Dialer{Timeout: testrun.Patient(testrun.HangBound)}
	connection, err := dialer.DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatalf("dialing %s: %v", address, err)
	}
	tcp, ok := connection.(*net.TCPConn)
	if !ok {
		t.Fatalf("dialing %s gave no TCP connection", address)
	}
	t.Cleanup(func() { _ = tcp.Close() })
	return &rawClient{t: t, connection: tcp, adjustWindow: true}
}

func (client *rawClient) write(data []byte) {
	client.t.Helper()
	if err := client.connection.SetWriteDeadline(time.Now().Add(testrun.Patient(testrun.HangBound))); err != nil {
		client.t.Fatalf("setting the write deadline: %v", err)
	}
	if _, err := client.connection.Write(data); err != nil {
		client.t.Fatalf("writing to the engine: %v", err)
	}
}

// fill reads until count bytes are pending, by deadline.
func (client *rawClient) fill(count int, deadline time.Time) error {
	buffer := make([]byte, 65536)
	for len(client.pending) < count {
		if err := client.connection.SetReadDeadline(deadline); err != nil {
			return err
		}
		read, err := client.connection.Read(buffer)
		client.pending = append(client.pending, buffer[:read]...)
		if err != nil && len(client.pending) < count {
			return err
		}
	}
	return nil
}

func (client *rawClient) take(count int) []byte {
	taken := slices.Clone(client.pending[:count])
	client.pending = client.pending[count:]
	return taken
}

// readVersion reads the engine's first line, CR LF included, by deadline.
func (client *rawClient) readVersion(deadline time.Time) ([]byte, error) {
	for {
		if index := bytes.Index(client.pending, []byte("\r\n")); index >= 0 {
			client.serverVersion = client.take(index + 2)
			return client.serverVersion, nil
		}
		if len(client.pending) > 255 {
			return nil, fmt.Errorf("no version line in %q", client.pending)
		}
		if err := client.fill(len(client.pending)+1, deadline); err != nil {
			return nil, err
		}
	}
}

func (client *rawClient) sendVersion() {
	client.t.Helper()
	client.write([]byte(clientVersion + "\r\n"))
}

// sendPacket frames payload as RFC 4253 section 6 has it, encrypted once keys are in use.
func (client *rawClient) sendPacket(payload []byte) {
	client.t.Helper()
	client.write(client.frame(payload))
}

// sendTogether frames each payload in order and sends them in one write, so that the engine's
// library reads them as they came, with nothing between.
func (client *rawClient) sendTogether(payloads ...[]byte) {
	client.t.Helper()
	var framed []byte
	for _, payload := range payloads {
		framed = append(framed, client.frame(payload)...)
	}
	client.write(framed)
}

func (client *rawClient) frame(payload []byte) []byte {
	block := 8
	lengthCounted := 4
	if client.sendCipher != nil {
		block = 16
		lengthCounted = 0
	}
	padding := block - (lengthCounted+1+len(payload))%block
	if padding < 4 {
		padding += block
	}
	body := make([]byte, 0, 1+len(payload)+padding)
	body = append(body, wireByte(padding))
	body = append(body, payload...)
	pad := make([]byte, padding)
	_, _ = rand.Read(pad)
	body = append(body, pad...)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], wireLength(len(body)))
	if client.sendCipher == nil {
		return append(length[:], body...)
	}
	sealed := client.sendCipher.aead.Seal(nil, client.sendCipher.nonce[:], body, length[:])
	client.sendCipher.advance()
	return append(length[:], sealed...)
}

// readPacket returns the next packet's payload, whatever its type, by deadline.
func (client *rawClient) readPacket(deadline time.Time) ([]byte, error) {
	if err := client.fill(4, deadline); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(client.pending[:4])
	if length < 5 || length > packetMost {
		return nil, fmt.Errorf("a packet length of %d", length)
	}
	extra := 0
	if client.receiveCipher != nil {
		extra = gcmTagSize
	}
	if err := client.fill(4+int(length)+extra, deadline); err != nil {
		return nil, err
	}
	header := client.take(4)
	body := client.take(int(length) + extra)
	if client.receiveCipher != nil {
		opened, err := client.receiveCipher.aead.Open(nil, client.receiveCipher.nonce[:], body, header)
		if err != nil {
			return nil, fmt.Errorf("a packet that does not decrypt: %w", err)
		}
		client.receiveCipher.advance()
		body = opened
	}
	padding := int(body[0])
	if padding+1 > len(body) {
		return nil, fmt.Errorf("a padding of %d in a packet of %d", padding, len(body))
	}
	return body[1 : len(body)-padding], nil
}

// wireLength is a length as SSH writes it; nothing a row builds comes near 4 GiB.
func wireLength(count int) uint32 {
	if count < 0 || count > math.MaxUint32 {
		panic("a length beyond what SSH can write")
	}
	return uint32(count)
}

// wireByte is a padding length, at most a block and its 4 bytes.
func wireByte(count int) byte {
	if count < 0 || count > math.MaxUint8 {
		panic("a padding beyond a byte")
	}
	return byte(count)
}

// wire is a payload under construction, RFC 4251 section 5's types.
type wire struct{ data []byte }

func message(kind byte) *wire { return &wire{data: []byte{kind}} }

func (out *wire) byteValue(value byte) *wire { out.data = append(out.data, value); return out }

func (out *wire) boolean(value bool) *wire {
	if value {
		return out.byteValue(1)
	}
	return out.byteValue(0)
}

func (out *wire) uint32Value(value uint32) *wire {
	out.data = binary.BigEndian.AppendUint32(out.data, value)
	return out
}

func (out *wire) text(value string) *wire { return out.bytesValue([]byte(value)) }

func (out *wire) bytesValue(value []byte) *wire {
	out.uint32Value(wireLength(len(value)))
	out.data = append(out.data, value...)
	return out
}

func (out *wire) mpint(value []byte) *wire {
	number := new(big.Int).SetBytes(value).Bytes()
	if len(number) > 0 && number[0]&0x80 != 0 {
		number = append([]byte{0}, number...)
	}
	return out.bytesValue(number)
}

// reader reads one payload's fields in order; a short payload fails the row.
type reader struct {
	t    *testing.T
	data []byte
}

func (parser *reader) byteValue() byte {
	parser.t.Helper()
	if len(parser.data) < 1 {
		parser.t.Fatalf("a payload too short for a byte")
	}
	value := parser.data[0]
	parser.data = parser.data[1:]
	return value
}

func (parser *reader) boolean() bool { return parser.byteValue() != 0 }

func (parser *reader) uint32Value() uint32 {
	parser.t.Helper()
	if len(parser.data) < 4 {
		parser.t.Fatalf("a payload too short for a uint32")
	}
	value := binary.BigEndian.Uint32(parser.data)
	parser.data = parser.data[4:]
	return value
}

func (parser *reader) bytesValue() []byte {
	parser.t.Helper()
	length := parser.uint32Value()
	if wireLength(len(parser.data)) < length {
		parser.t.Fatalf("a payload too short for a string of %d", length)
	}
	value := parser.data[:length]
	parser.data = parser.data[length:]
	return value
}

func (parser *reader) text() string { return string(parser.bytesValue()) }

// kexInit is a KEXINIT's fields, RFC 4253 section 7.1.
type kexInit struct {
	cookie                                 []byte
	kex, hostKeys                          string
	ciphersOut, ciphersIn, macsOut, macsIn string
	compressionOut, compressionIn          string
	languagesOut, languagesIn              string
	firstFollows                           bool
	reserved                               uint32
	rest                                   []byte
}

func parseKexInit(t *testing.T, payload []byte) kexInit {
	t.Helper()
	parser := &reader{t: t, data: payload}
	if kind := parser.byteValue(); kind != messageKexInit {
		t.Fatalf("the engine's first packet was message %d, want KEXINIT", kind)
	}
	if len(parser.data) < 16 {
		t.Fatalf("a KEXINIT too short for its cookie")
	}
	parsed := kexInit{cookie: parser.data[:16]}
	parser.data = parser.data[16:]
	parsed.kex = parser.text()
	parsed.hostKeys = parser.text()
	parsed.ciphersOut = parser.text()
	parsed.ciphersIn = parser.text()
	parsed.macsOut = parser.text()
	parsed.macsIn = parser.text()
	parsed.compressionOut = parser.text()
	parsed.compressionIn = parser.text()
	parsed.languagesOut = parser.text()
	parsed.languagesIn = parser.text()
	parsed.firstFollows = parser.boolean()
	parsed.reserved = parser.uint32Value()
	parsed.rest = parser.data
	return parsed
}

func joined(list []string) string {
	out := ""
	for index, name := range list {
		if index > 0 {
			out += ","
		}
		out += name
	}
	return out
}

// sendKexInit sends the client's KEXINIT and keeps it for the exchange hash.
func (client *rawClient) sendKexInit(offer kexOffer) {
	client.t.Helper()
	cookie := make([]byte, 16)
	_, _ = rand.Read(cookie)
	out := message(messageKexInit)
	out.data = append(out.data, cookie...)
	out.text(joined(offer.kex)).text(joined(offer.hostKeys)).
		text(joined(offer.ciphers)).text(joined(offer.ciphers)).
		text(joined(offer.macs)).text(joined(offer.macs)).
		text(joined(offer.compression)).text(joined(offer.compression)).
		text("").text("").boolean(false).uint32Value(0)
	client.clientKexInit = out.data
	client.sendPacket(out.data)
}

// readServerKexInit reads the version line and then the engine's KEXINIT.
func (client *rawClient) readServerKexInit(deadline time.Time) kexInit {
	client.t.Helper()
	if client.serverVersion == nil {
		if _, err := client.readVersion(deadline); err != nil {
			client.t.Fatalf("reading the engine's version line: %v", err)
		}
	}
	payload, err := client.readPacket(deadline)
	if err != nil {
		client.t.Fatalf("reading the engine's KEXINIT: %v", err)
	}
	client.serverKexInit = payload
	return parseKexInit(client.t, payload)
}

// keyExchange is one way to agree on a secret: its first message, and how to read the reply.
type keyExchange struct {
	name    string
	initial []byte
	// finish returns the secret as the exchange hash encodes it, from the server's reply.
	finish func(reply []byte) (sharedForHash func(*wire) *wire, err error)
}

func curveExchange(t *testing.T, name string) keyExchange {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("an X25519 key: %v", err)
	}
	return keyExchange{
		name:    name,
		initial: private.PublicKey().Bytes(),
		finish: func(reply []byte) (func(*wire) *wire, error) {
			public, err := ecdh.X25519().NewPublicKey(reply)
			if err != nil {
				return nil, err
			}
			secret, err := private.ECDH(public)
			if err != nil {
				return nil, err
			}
			// RFC 8731 section 3.1: the secret is an mpint.
			return func(out *wire) *wire { return out.mpint(secret) }, nil
		},
	}
}

func hybridExchange(t *testing.T) keyExchange {
	t.Helper()
	decapsulation, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("an ML-KEM key: %v", err)
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("an X25519 key: %v", err)
	}
	initial := append(slices.Clone(decapsulation.EncapsulationKey().Bytes()), private.PublicKey().Bytes()...)
	return keyExchange{
		name:    "mlkem768x25519-sha256",
		initial: initial,
		finish: func(reply []byte) (func(*wire) *wire, error) {
			if len(reply) != mlkem.CiphertextSize768+32 {
				return nil, fmt.Errorf("a hybrid reply of %d bytes", len(reply))
			}
			postQuantum, err := decapsulation.Decapsulate(reply[:mlkem.CiphertextSize768])
			if err != nil {
				return nil, err
			}
			public, err := ecdh.X25519().NewPublicKey(reply[mlkem.CiphertextSize768:])
			if err != nil {
				return nil, err
			}
			classical, err := private.ECDH(public)
			if err != nil {
				return nil, err
			}
			// The hybrid's secret is the hash of both, sent as a string, not an mpint.
			combined := sha256.Sum256(append(slices.Clone(postQuantum), classical...))
			return func(out *wire) *wire { return out.bytesValue(combined[:]) }, nil
		},
	}
}

// finishKeyExchange sends the exchange's first message, verifies the engine's signed reply,
// switches both directions to AES-128-GCM, and resets the sequence for strict key exchange.
func (client *rawClient) finishKeyExchange(exchange keyExchange, deadline time.Time) error {
	client.t.Helper()
	client.sendPacket(message(messageKexInit30).bytesValue(exchange.initial).data)
	payload, err := client.nextIgnoring(deadline)
	if err != nil {
		return fmt.Errorf("reading the key exchange's reply: %w", err)
	}
	parser := &reader{t: client.t, data: payload}
	if kind := parser.byteValue(); kind != messageKexReply31 {
		return fmt.Errorf("the key exchange's reply was message %d", kind)
	}
	hostKey := parser.bytesValue()
	serverPart := parser.bytesValue()
	signature := parser.bytesValue()
	shared, err := exchange.finish(serverPart)
	if err != nil {
		return fmt.Errorf("the engine's key exchange part: %w", err)
	}
	hashInput := (&wire{}).bytesValue([]byte(clientVersion)).
		bytesValue(bytes.TrimSuffix(client.serverVersion, []byte("\r\n"))).
		bytesValue(client.clientKexInit).bytesValue(client.serverKexInit).
		bytesValue(hostKey).bytesValue(exchange.initial).bytesValue(serverPart)
	shared(hashInput)
	exchangeHash := sha256.Sum256(hashInput.data)
	if err := verifyHostSignature(client.t, hostKey, signature, exchangeHash[:]); err != nil {
		return err
	}
	client.hostKey = hostKey
	if client.sessionID == nil {
		client.sessionID = exchangeHash[:]
	}
	client.sendPacket([]byte{messageNewKeys})
	payload, err = client.nextIgnoring(deadline)
	if err != nil {
		return fmt.Errorf("reading the engine's NEWKEYS: %w", err)
	}
	if payload[0] != messageNewKeys {
		return fmt.Errorf("message %d where NEWKEYS belongs", payload[0])
	}
	derive := func(letter byte, size int) []byte {
		secret := shared(&wire{}).data
		first := sha256.Sum256(slices.Concat(secret, exchangeHash[:], []byte{letter}, client.sessionID))
		key := first[:]
		for len(key) < size {
			more := sha256.Sum256(slices.Concat(secret, exchangeHash[:], key))
			key = append(key, more[:]...)
		}
		return key[:size]
	}
	client.sendCipher = newGCM(client.t, derive('C', 16), derive('A', 12))
	client.receiveCipher = newGCM(client.t, derive('D', 16), derive('B', 12))
	return nil
}

func newGCM(t *testing.T, key, nonce []byte) *gcmDirection {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("an AES key: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("a GCM: %v", err)
	}
	direction := &gcmDirection{aead: aead}
	copy(direction.nonce[:], nonce)
	return direction
}

func verifyHostSignature(t *testing.T, hostKey, signature, signed []byte) error {
	t.Helper()
	keyReader := &reader{t: t, data: hostKey}
	if name := keyReader.text(); name != ed25519Name {
		return fmt.Errorf("a host key of type %q", name)
	}
	public := keyReader.bytesValue()
	signatureReader := &reader{t: t, data: signature}
	if name := signatureReader.text(); name != ed25519Name {
		return fmt.Errorf("a signature of type %q", name)
	}
	if len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, signed, signatureReader.bytesValue()) {
		return errors.New("the engine's signature over the exchange hash does not verify")
	}
	return nil
}

// nextIgnoring returns the next packet that is not IGNORE or DEBUG.
func (client *rawClient) nextIgnoring(deadline time.Time) ([]byte, error) {
	for {
		payload, err := client.readPacket(deadline)
		if err != nil {
			return nil, err
		}
		if len(payload) == 0 {
			return nil, errors.New("an empty payload")
		}
		if payload[0] != messageIgnore && payload[0] != messageDebug {
			return payload, nil
		}
	}
}

// next returns the next message a row reads, leaving out what the engine's library may send of
// its own at any time: window adjustments (taken into the window here), extension info, ping
// replies, IGNORE and DEBUG. Channel data is recorded and adjusted for, and returned.
func (client *rawClient) next(deadline time.Time) ([]byte, error) {
	for {
		payload, err := client.nextIgnoring(deadline)
		if err != nil {
			return nil, err
		}
		switch payload[0] {
		case messageWindowAdjust:
			parser := &reader{t: client.t, data: payload[1:]}
			parser.uint32Value()
			client.windowToServer += parser.uint32Value()
			continue
		case messageExtensionInfo, messagePong:
			continue
		case messageChannelData:
			parser := &reader{t: client.t, data: payload[1:]}
			parser.uint32Value()
			data := parser.bytesValue()
			now := time.Now()
			client.received = append(client.received, data...)
			for range data {
				client.receivedAt = append(client.receivedAt, now)
			}
			client.windowFromServer += wireLength(len(data))
			if client.adjustWindow && client.windowFromServer > clientWindow/2 {
				client.sendPacket(message(messageWindowAdjust).uint32Value(client.engineChannel).uint32Value(client.windowFromServer).data)
				client.windowFromServer = 0
			}
		}
		return payload, nil
	}
}

// handshake runs version, key exchange, NEWKEYS and the ssh-userauth service.
func (client *rawClient) handshake(exchange keyExchange, strict bool) {
	client.t.Helper()
	deadline := time.Now().Add(testrun.Patient(testrun.HangBound))
	client.sendVersion()
	client.readServerKexInit(deadline)
	client.sendKexInit(defaultOffer(exchange.name, strict))
	if err := client.finishKeyExchange(exchange, deadline); err != nil {
		client.t.Fatalf("the key exchange: %v", err)
	}
	client.sendPacket(message(messageServiceRequest).text("ssh-userauth").data)
	payload, err := client.next(deadline)
	if err != nil || payload[0] != messageServiceAccept {
		client.t.Fatalf("the ssh-userauth service: %v, %v", payload, err)
	}
}

// signIn asks for the method none under user, and fails the row unless it is accepted.
func (client *rawClient) signIn(user string) {
	client.t.Helper()
	client.sendPacket(message(messageUserauthRequest).text(user).text("ssh-connection").text("none").data)
	payload, err := client.next(time.Now().Add(testrun.Patient(testrun.HangBound)))
	if err != nil || payload[0] != messageUserauthSuccess {
		client.t.Fatalf("signing in with none as %q: %v, %v", user, payload, err)
	}
}

// openSession opens a session channel as the client's channel 0 and returns the engine's
// message: a confirmation or a failure.
func (client *rawClient) openChannel(kind string, number uint32, extra []byte) []byte {
	client.t.Helper()
	out := message(messageChannelOpen).text(kind).uint32Value(number).uint32Value(clientWindow).uint32Value(clientMaxPacket)
	out.data = append(out.data, extra...)
	client.sendPacket(out.data)
	payload, err := client.next(time.Now().Add(testrun.Patient(testrun.HangBound)))
	if err != nil {
		client.t.Fatalf("opening a %s channel: %v", kind, err)
	}
	if payload[0] == messageChannelConfirmation {
		parser := &reader{t: client.t, data: payload[1:]}
		parser.uint32Value()
		client.engineChannel = parser.uint32Value()
		client.windowToServer = parser.uint32Value()
	}
	return payload
}

// request sends a channel request on the engine's session channel and, when it wants a reply,
// returns it.
func (client *rawClient) request(kind string, wantReply bool, extra []byte) []byte {
	client.t.Helper()
	out := message(messageChannelRequest).uint32Value(client.engineChannel).text(kind).boolean(wantReply)
	out.data = append(out.data, extra...)
	client.sendPacket(out.data)
	if !wantReply {
		return nil
	}
	payload, err := client.next(time.Now().Add(testrun.Patient(testrun.HangBound)))
	if err != nil {
		client.t.Fatalf("the %s request's reply: %v", kind, err)
	}
	return payload
}

func ptyRequest(term string, modes []byte) []byte {
	return (&wire{}).text(term).uint32Value(80).uint32Value(24).uint32Value(640).uint32Value(480).bytesValue(modes).data
}

// sendData sends channel data on the engine's session channel.
func (client *rawClient) sendData(data string) {
	client.t.Helper()
	client.sendPacket(message(messageChannelData).uint32Value(client.engineChannel).text(data).data)
}

func (client *rawClient) sendExtended(data string) {
	client.t.Helper()
	client.sendPacket(message(messageExtendedData).uint32Value(client.engineChannel).uint32Value(1).text(data).data)
}

// readData reads until the channel data received holds count bytes, by deadline, and fails the
// row on any message that is not channel data.
func (client *rawClient) readData(count int, deadline time.Time) {
	client.t.Helper()
	for len(client.received) < count {
		payload, err := client.next(deadline)
		if err != nil {
			client.t.Fatalf("after %q, waiting for %d bytes: %v", client.received, count, err)
		}
		if payload[0] != messageChannelData {
			client.t.Fatalf("after %q, message %d where channel data belongs", client.received, payload[0])
		}
	}
}

// expectEnd reads until the connection ends, by deadline, and returns the messages it saw and
// when it ended.
func (client *rawClient) expectEnd(deadline time.Time) ([]byte, time.Time) {
	client.t.Helper()
	var kinds []byte
	for {
		payload, err := client.next(deadline)
		if err != nil {
			if errors.Is(err, io.EOF) || isReset(err) {
				return kinds, time.Now()
			}
			client.t.Fatalf("waiting for the end, after messages %v: %v", kinds, err)
		}
		kinds = append(kinds, payload[0])
	}
}

// ready runs a whole sign-in and opens the session channel, as most rows begin.
func readyClient(t *testing.T, address, user string) *rawClient {
	t.Helper()
	client := dialRaw(t, address)
	client.handshake(curveExchange(t, "curve25519-sha256"), true)
	client.signIn(user)
	if reply := client.openChannel("session", 0, nil); reply[0] != messageChannelConfirmation {
		t.Fatalf("the session channel: message %d", reply[0])
	}
	return client
}
