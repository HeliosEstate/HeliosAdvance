// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// What the program's Telnet over TLS rows check against, written apart from the engine's code:
// the certificate and key files openssl makes for the run, OpenSSL's s_client and how it words a
// handshake, and QA's own Telnet caller over a crypto/tls client, with a tap on the TCP
// connection beneath that reads the TLS records' types.
package main_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// The Telnet over TLS options, as the page names them.
const (
	tlsCertificateOption = "-tls-cert"
	tlsKeyOption         = "-tls-key"
	tlsPortOption        = "-tls-port"
)

// tlsMostBytes is the longest file the page's lines accept.
const tlsMostBytes = 65536

// opensslPath finds the openssl the rows run, once; a missing one fails every row that needs it.
var opensslPath = sync.OnceValues(func() (string, error) { return exec.LookPath("openssl") })

// subjectNames are the names every certificate the run makes holds, so QA's caller verifies the
// engine's certificate as a caller's client does: localhost, the loopback addresses, and the
// canary server name a row asks for.
const subjectNames = "subjectAltName=DNS:localhost,DNS:" + canary + ".test,IP:127.0.0.1,IP:::1"

// trusted is every certificate the run has made that a caller may trust: each self-signed one,
// and each intermediate that signed a leaf.
var trusted struct {
	mutex        sync.Mutex
	certificates []*x509.Certificate
}

// trust adds the certificate at path to those QA's caller trusts.
func trust(t *testing.T, path string) {
	t.Helper()
	parsed, err := x509.ParseCertificate(readPEMBlocks(t, path)[0].Bytes)
	if err != nil {
		t.Fatalf("a fault in the test: openssl's certificate does not parse: %v", err)
	}
	trusted.mutex.Lock()
	defer trusted.mutex.Unlock()
	trusted.certificates = append(trusted.certificates, parsed)
}

// trustedPool is every certificate the run has made so far, for a caller's verification.
func trustedPool() *x509.CertPool {
	trusted.mutex.Lock()
	defer trusted.mutex.Unlock()
	pool := x509.NewCertPool()
	for _, certificate := range trusted.certificates {
		pool.AddCert(certificate)
	}
	return pool
}

// tlsKeyKind is a key as the sysop makes one with openssl genpkey, its arguments as the sysop
// types them.
type tlsKeyKind struct {
	name      string
	arguments string
}

var (
	tlsRSA1024    = tlsKeyKind{"RSA 1024", "-algorithm RSA -pkeyopt rsa_keygen_bits:1024"}
	tlsRSA2047    = tlsKeyKind{"RSA 2047", "-algorithm RSA -pkeyopt rsa_keygen_bits:2047"}
	tlsRSA2048    = tlsKeyKind{"RSA 2048", "-algorithm RSA -pkeyopt rsa_keygen_bits:2048"}
	tlsRSA4096    = tlsKeyKind{"RSA 4096", "-algorithm RSA -pkeyopt rsa_keygen_bits:4096"}
	tlsP256       = tlsKeyKind{"ECDSA P-256", "-algorithm EC -pkeyopt ec_paramgen_curve:P-256"}
	tlsP384       = tlsKeyKind{"ECDSA P-384", "-algorithm EC -pkeyopt ec_paramgen_curve:P-384"}
	tlsP521       = tlsKeyKind{"ECDSA P-521", "-algorithm EC -pkeyopt ec_paramgen_curve:P-521"}
	tlsEd25519    = tlsKeyKind{"Ed25519", "-algorithm ED25519"}
	tlsRSAPSS2048 = tlsKeyKind{"RSA-PSS 2048", "-algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048"}
)

// tlsFiles are a certificate file and a key file, as the sysop names them.
type tlsFiles struct {
	certificate, key string
}

// options are the command-line options that turn Telnet over TLS on with these files, at a port
// the system picks, with Telnet's at one too.
func (files tlsFiles) options(extra ...string) []string {
	return append([]string{portOption, "0", tlsCertificateOption, files.certificate, tlsKeyOption, files.key, tlsPortOption, "0"}, extra...)
}

// runOpenSSL runs openssl in the folder given; a missing openssl or a failed run fails the row.
func runOpenSSL(t *testing.T, folder string, arguments ...string) {
	t.Helper()
	path, err := opensslPath()
	if err != nil {
		t.Fatalf("openssl is not on this machine's PATH, and these rows need it: %v", err)
	}
	command := exec.CommandContext(t.Context(), path, arguments...)
	command.Dir = folder
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("openssl %q: %v\n%s", arguments, err, output)
	}
}

// makeTLSKey has openssl make a key of the kind, with only its owner able to read it.
func makeTLSKey(t *testing.T, kind tlsKeyKind) string {
	t.Helper()
	folder := t.TempDir()
	runOpenSSL(t, folder, append(append([]string{"genpkey"}, strings.Fields(kind.arguments)...), "-out", "key.pem")...)
	path := filepath.Join(folder, "key.pem")
	setMode(t, path, 0o600)
	return path
}

// selfSigned has openssl make a self-signed certificate for the key.
func selfSigned(t *testing.T, keyPath string) string {
	t.Helper()
	folder := t.TempDir()
	runOpenSSL(t, folder, "req", "-x509", "-new", "-key", keyPath, "-out", "certificate.pem", "-days", "1", "-subj", "/CN=localhost", "-addext", subjectNames)
	trust(t, filepath.Join(folder, "certificate.pem"))
	return filepath.Join(folder, "certificate.pem")
}

// goodTLSFiles is a key of the kind and a self-signed certificate for it.
func goodTLSFiles(t *testing.T, kind tlsKeyKind) tlsFiles {
	t.Helper()
	key := makeTLSKey(t, kind)
	return tlsFiles{certificate: selfSigned(t, key), key: key}
}

// tlsChain is a certificate file holding a leaf and the intermediate that signed it, the leaf's
// key, and each certificate's DER as the caller must receive it.
type tlsChain struct {
	files              tlsFiles
	leaf, intermediate []byte
}

// makeTLSChain has openssl make an intermediate that may sign and a leaf it signs, ECDSA P-256.
func makeTLSChain(t *testing.T) tlsChain {
	t.Helper()
	folder := t.TempDir()
	intermediateKey := makeTLSKey(t, tlsP256)
	runOpenSSL(t, folder, "req", "-x509", "-new", "-key", intermediateKey, "-out", "intermediate.pem", "-days", "1",
		"-subj", "/CN=Helios QA intermediate", "-addext", "basicConstraints=critical,CA:TRUE",
		"-addext", "keyUsage=critical,keyCertSign")
	leafKey := makeTLSKey(t, tlsP256)
	runOpenSSL(t, folder, "req", "-new", "-key", leafKey, "-out", "leaf.csr", "-subj", "/CN=localhost", "-addext", subjectNames)
	runOpenSSL(t, folder, "x509", "-req", "-in", "leaf.csr", "-CA", "intermediate.pem", "-CAkey", intermediateKey,
		"-set_serial", "2", "-days", "1", "-copy_extensions", "copy", "-out", "leaf.pem")
	trust(t, filepath.Join(folder, "intermediate.pem"))
	leaf := readPEMBlocks(t, filepath.Join(folder, "leaf.pem"))[0].Bytes
	intermediate := readPEMBlocks(t, filepath.Join(folder, "intermediate.pem"))[0].Bytes
	path := writePEMBlocks(t, certificateBlock(leaf), certificateBlock(intermediate))
	return tlsChain{files: tlsFiles{certificate: path, key: leafKey}, leaf: leaf, intermediate: intermediate}
}

// certificateBlockType is the PEM type of a block holding an X.509 certificate.
const certificateBlockType = "CERTIFICATE"

func certificateBlock(der []byte) *pem.Block {
	return &pem.Block{Type: certificateBlockType, Bytes: der}
}

// notCertificate is a CERTIFICATE block that holds no X.509 certificate.
func notCertificate() *pem.Block {
	return certificateBlock([]byte(canary + " is not a certificate"))
}

// readPEMBlocks reads every PEM block of a file the test made.
func readPEMBlocks(t *testing.T, path string) []*pem.Block {
	t.Helper()
	text := readTLSFile(t, path)
	var blocks []*pem.Block
	for {
		var block *pem.Block
		block, text = pem.Decode(text)
		if block == nil {
			return blocks
		}
		blocks = append(blocks, block)
	}
}

// writePEMBlocks writes the blocks, in order, to a new file only its owner may read.
func writePEMBlocks(t *testing.T, blocks ...*pem.Block) string {
	t.Helper()
	var text []byte
	for _, block := range blocks {
		text = append(text, pem.EncodeToMemory(block)...)
	}
	return writeTLSFile(t, text)
}

// writeTLSFile writes the bytes to a new file only its owner may read.
func writeTLSFile(t *testing.T, text []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "file.pem")
	if err := os.WriteFile(path, text, 0o600); err != nil {
		t.Fatal(err)
	}
	setMode(t, path, 0o600)
	return path
}

func readTLSFile(t *testing.T, path string) []byte {
	t.Helper()
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return text
}

// joinTLSFiles is the files' bytes one after the other, in a new file.
func joinTLSFiles(t *testing.T, paths ...string) string {
	t.Helper()
	var text []byte
	for _, path := range paths {
		text = append(text, readTLSFile(t, path)...)
	}
	return writeTLSFile(t, text)
}

// withSurroundingText is the file with text before and after its blocks.
func withSurroundingText(t *testing.T, path string) string {
	t.Helper()
	return writeTLSFile(t, bytes.Join([][]byte{[]byte("text before the blocks\n"), readTLSFile(t, path), []byte("text after them\n")}, nil))
}

// encryptedKey is the key protected by the passphrase secret: as a PKCS#8 ENCRYPTED PRIVATE KEY
// block, or, with legacy, as an RSA PRIVATE KEY block with the old PEM header.
func encryptedKey(t *testing.T, keyPath string, legacy bool) string {
	t.Helper()
	folder := t.TempDir()
	if legacy {
		runOpenSSL(t, folder, "rsa", "-in", keyPath, "-aes256", "-traditional", "-passout", "pass:secret", "-out", "key.pem")
	} else {
		runOpenSSL(t, folder, "pkcs8", "-topk8", "-in", keyPath, "-passout", "pass:secret", "-out", "key.pem")
	}
	path := filepath.Join(folder, "key.pem")
	setMode(t, path, 0o600)
	return path
}

// paddedTo is a copy of the file with random text before its blocks, so it is exactly size
// bytes long: text outside the blocks, which PEM allows.
func paddedTo(t *testing.T, path string, size int) string {
	t.Helper()
	text := readTLSFile(t, path)
	if len(text)+1 >= size {
		t.Fatalf("%s is already %d bytes, too long to pad to %d", path, len(text), size)
	}
	raw := make([]byte, size-len(text)-1)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
	for index := range raw {
		raw[index] = letters[int(raw[index])%len(letters)]
	}
	padded := append(append(raw, '\n'), text...)
	return writeTLSFile(t, padded)
}

// sClient is one run of OpenSSL's s_client, the oracle for the TLS table, run with -msg so every
// record it sends and receives is named.
type sClient struct {
	command *exec.Cmd
	input   io.WriteCloser
	mutex   sync.Mutex
	output  []string
	lines   chan string
	exited  chan struct{}
}

// startSClient connects s_client to the address, with -ign_eof so it reads on after its input
// ends, killed when the test ends.
func startSClient(t *testing.T, address string, options ...string) *sClient {
	t.Helper()
	return runSClient(t, address, append([]string{"-ign_eof"}, options...))
}

// startSClientCommands is startSClient without -ign_eof, under which s_client reads no command
// such as R from its input: it sends the letter as data instead.
func startSClientCommands(t *testing.T, address string, options ...string) *sClient {
	t.Helper()
	return runSClient(t, address, options)
}

func runSClient(t *testing.T, address string, options []string) *sClient {
	t.Helper()
	path, err := opensslPath()
	if err != nil {
		t.Fatalf("openssl is not on this machine's PATH, and these rows need it: %v", err)
	}
	command := exec.CommandContext(t.Context(), path, append([]string{"s_client", "-connect", address, "-msg"}, options...)...)
	command.WaitDelay = testrun.Patient(testrun.HangBound)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	command.Stdout = writer
	command.Stderr = writer
	if err := command.Start(); err != nil {
		t.Fatalf("starting s_client: %v", err)
	}
	client := &sClient{command: command, input: input, lines: make(chan string, 1024), exited: make(chan struct{})}
	go func() {
		_ = command.Wait()
		_ = writer.Close()
	}()
	go func() {
		defer close(client.exited)
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimRight(scanner.Text(), "\r")
			client.mutex.Lock()
			client.output = append(client.output, line)
			client.mutex.Unlock()
			select {
			case client.lines <- line:
			default:
			}
		}
		_, _ = io.Copy(io.Discard, reader)
	}()
	t.Cleanup(client.stop)
	return client
}

// stop ends s_client if it still runs, and waits for its output to end.
func (client *sClient) stop() {
	_ = client.input.Close()
	select {
	case <-client.exited:
	default:
		_ = client.command.Process.Kill()
		<-client.exited
	}
}

func (client *sClient) text() string {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	return strings.Join(client.output, "\n")
}

// waitFor waits, by the deadline, for a line s_client prints that holds the text, and returns it.
func (client *sClient) waitFor(t *testing.T, text string, deadline time.Time) string {
	t.Helper()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	for {
		select {
		case line := <-client.lines:
			if strings.Contains(line, text) {
				return line
			}
		case <-client.exited:
			for {
				select {
				case line := <-client.lines:
					if strings.Contains(line, text) {
						return line
					}
					continue
				default:
				}
				break
			}
			t.Fatalf("s_client ended before it printed %q:\n%s", text, client.text())
		case <-timer.C:
			t.Fatalf("s_client had not printed %q by the deadline:\n%s", text, client.text())
		}
	}
}

// handshakeText waits for s_client to sum up its handshake, taken or refused, then ends it and
// returns what it printed.
func (client *sClient) handshakeText(t *testing.T) string {
	t.Helper()
	client.waitFor(t, "Cipher is", time.Now().Add(testrun.Patient(testrun.HangBound)))
	client.stop()
	return client.text()
}

// typeAfterPrompt waits for s_client to sum up its handshake, then until the engine has written
// the prompt, and types the name on s_client's input. On Windows s_client shows what it receives
// only when it ends, if its output is a pipe, so the prompt cannot be waited on: the engine
// writes it once negotiation's 3 seconds pass after the handshake, which s_client answers
// nothing of, and the name is typed a margin after that. A name typed before the prompt would
// fall in negotiation, which keeps no data byte.
func (client *sClient) typeAfterPrompt(t *testing.T, name string) {
	t.Helper()
	client.waitFor(t, "Cipher is", time.Now().Add(testrun.Patient(testrun.HangBound)))
	pause(t, negotiationLimit+testrun.Patient(margin))
	client.send(t, name+"\n")
}

func (client *sClient) send(t *testing.T, text string) {
	t.Helper()
	if _, err := io.WriteString(client.input, text); err != nil {
		t.Fatalf("writing to s_client: %v", err)
	}
}

// finish closes s_client's input and waits, by the hang bound, for it to end, which it does when
// the engine closes, and returns everything it printed.
func (client *sClient) finish(t *testing.T) string {
	t.Helper()
	_ = client.input.Close()
	timer := time.NewTimer(testrun.Patient(testrun.HangBound))
	defer timer.Stop()
	select {
	case <-client.exited:
	case <-timer.C:
		t.Fatalf("s_client had not ended within %v:\n%s", testrun.Patient(testrun.HangBound), client.text())
	}
	return client.text()
}

// handshakeSeen is what s_client printed of one handshake.
type handshakeSeen struct {
	text                       string
	protocol, cipher, group    string
	serverAlerts, clientAlerts []string
	serverMessages             []string
	connected                  bool
}

// The curves by the names the TLS table uses, which TLS 1.3's s_client prints and TLS 1.2's
// OpenSSL name is read into.
const (
	curveP256 = "P-256"
	curveP384 = "P-384"
	curveP521 = "P-521"
)

var (
	sClientSummary   = regexp.MustCompile(`(?m)^New, (TLSv1(?:\.[0-3])?|\(NONE\)), Cipher is (\S+)`)
	negotiatedGroup  = regexp.MustCompile(`(?m)^Negotiated TLS1\.3 group: (\S+)`)
	temporaryKey     = regexp.MustCompile(`(?m)^(?:Peer|Server) Temp Key: (X25519|X448|ECDH, (\S+)),`)
	receivedAlert    = regexp.MustCompile(`(?m)^<<< TLS [0-9.]+, Alert \[length 0002\], (fatal|warning) (\S+)`)
	sentAlert        = regexp.MustCompile(`(?m)^>>> TLS [0-9.]+, Alert \[length 0002\], (fatal|warning) (\S+)`)
	receivedMessage  = regexp.MustCompile(`(?m)^<<< TLS [0-9.]+, Handshake \[length [0-9a-f]+\], (\S+)`)
	opensslCurveName = map[string]string{"prime256v1": curveP256, "secp384r1": curveP384, "secp521r1": curveP521}
)

// readHandshake reads s_client's output, as OpenSSL 3.5 words it in TLS 1.3 and TLS 1.2 alike:
// the protocol, cipher and key exchange agreed, and the alerts and handshake messages up to its
// summing up of the handshake; what follows is the call, not the handshake.
func readHandshake(text string) handshakeSeen {
	seen := handshakeSeen{text: text, connected: strings.Contains(text, "CONNECTED(")}
	handshakeText := text
	if match := sClientSummary.FindStringSubmatchIndex(text); match != nil {
		seen.protocol, seen.cipher = text[match[2]:match[3]], text[match[4]:match[5]]
		handshakeText = text[:match[0]]
	}
	if match := negotiatedGroup.FindStringSubmatch(text); match != nil && match[1] != "<NULL>" {
		seen.group = match[1]
	} else if match := temporaryKey.FindStringSubmatch(text); match != nil {
		seen.group = match[1]
		if match[2] != "" {
			seen.group = opensslCurveName[match[2]]
			if seen.group == "" {
				seen.group = match[2]
			}
		}
	}
	for _, match := range receivedAlert.FindAllStringSubmatch(handshakeText, -1) {
		seen.serverAlerts = append(seen.serverAlerts, match[1]+" "+match[2])
	}
	for _, match := range sentAlert.FindAllStringSubmatch(handshakeText, -1) {
		seen.clientAlerts = append(seen.clientAlerts, match[1]+" "+match[2])
	}
	for _, match := range receivedMessage.FindAllStringSubmatch(handshakeText, -1) {
		seen.serverMessages = append(seen.serverMessages, match[1])
	}
	return seen
}

// expectTaken checks s_client agreed the protocol, the cipher and, when one is named, the key
// exchange, with no fatal alert either way during the handshake.
func expectTaken(t *testing.T, seen handshakeSeen, protocol, cipher, group string) {
	t.Helper()
	if seen.protocol != protocol || (cipher != "" && seen.cipher != cipher) || (group != "" && seen.group != group) {
		t.Fatalf("s_client agreed %s, %s and %q, want %s, %s and %q:\n%s", seen.protocol, seen.cipher, seen.group, protocol, cipher, group, seen.text)
	}
	for _, alert := range append(append([]string{}, seen.serverAlerts...), seen.clientAlerts...) {
		if strings.HasPrefix(alert, "fatal") {
			t.Fatalf("s_client's handshake met the alert %q:\n%s", alert, seen.text)
		}
	}
}

// expectRefusedWith checks the engine refused the case with the one fatal alert given and wrote
// no handshake message. A case s_client could not offer, or refused itself, is a fault in the
// test: the engine was never asked.
func expectRefusedWith(t *testing.T, seen handshakeSeen, alert string) {
	t.Helper()
	if !seen.connected {
		t.Fatalf("a fault in the test: s_client never connected, so it could not offer the case:\n%s", seen.text)
	}
	for _, sent := range seen.clientAlerts {
		if strings.HasPrefix(sent, "fatal") {
			t.Fatalf("a fault in the test: s_client refused the case itself, with %q:\n%s", sent, seen.text)
		}
	}
	if len(seen.serverAlerts) != 1 || seen.serverAlerts[0] != "fatal "+alert {
		t.Fatalf("the engine sent the alerts %q, want fatal %s alone:\n%s", seen.serverAlerts, alert, seen.text)
	}
	if len(seen.serverMessages) != 0 || seen.protocol != "(NONE)" {
		t.Fatalf("the engine sent %q and agreed %s where it was to refuse:\n%s", seen.serverMessages, seen.protocol, seen.text)
	}
}

// The TLS record types, from RFC 8446 section 5.1.
const (
	alertRecord           byte = 21
	handshakeRecord       byte = 22
	applicationDataRecord byte = 23
)

// recordTypes reads data as TLS records and returns each whole record's type and how many bytes
// trail the last whole record.
func recordTypes(data []byte) (types []byte, trailing int) {
	for len(data) >= 5 {
		length := int(data[3])<<8 | int(data[4])
		if len(data) < 5+length {
			break
		}
		types = append(types, data[0])
		data = data[5+length:]
	}
	return types, len(data)
}

// tap is a TLS caller's TCP connection: every byte the engine sends is kept as it arrived, the
// start of every write noted, and, with damage set, the next write sent with its last byte
// changed.
type tap struct {
	*net.TCPConn
	mutex    sync.Mutex
	received []byte
	writes   []time.Time
	damage   bool
}

func (connection *tap) Read(buffer []byte) (int, error) {
	got, err := connection.TCPConn.Read(buffer)
	connection.mutex.Lock()
	connection.received = append(connection.received, buffer[:got]...)
	connection.mutex.Unlock()
	return got, err
}

func (connection *tap) Write(buffer []byte) (int, error) {
	connection.mutex.Lock()
	connection.writes = append(connection.writes, time.Now())
	if connection.damage {
		connection.damage = false
		buffer = bytes.Clone(buffer)
		buffer[len(buffer)-1] ^= 0x55
	}
	connection.mutex.Unlock()
	return connection.TCPConn.Write(buffer)
}

func (connection *tap) receivedSoFar() []byte {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	return bytes.Clone(connection.received)
}

func (connection *tap) lastWrite() time.Time {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	return connection.writes[len(connection.writes)-1]
}

func (connection *tap) damageNext() {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	connection.damage = true
}

// tlsCaller is QA's own Telnet caller over a crypto/tls client, written apart from the engine's
// code: it verifies the engine's certificate against those the run made, as a caller's client
// verifies it against those it trusts.
type tlsCaller struct {
	// raw is the TCP connection beneath, as dialed.
	raw caller
	tap *tap
	tls *tls.Conn
	// lastFlight is when the caller began the last write of its handshake: the engine's
	// handshake cannot complete before that write reaches it.
	lastFlight time.Time
}

// tlsConfig offers the one version given, a zero version both the table names, and verifies the
// engine's certificate for localhost.
func tlsConfig(version uint16) *tls.Config {
	config := &tls.Config{RootCAs: trustedPool(), ServerName: "localhost", MinVersion: tls.VersionTLS12}
	if version != 0 {
		config.MinVersion, config.MaxVersion = version, version
	}
	return config
}

// dialTLS dials the engine and makes the caller's handshake, by the hang bound.
func dialTLS(t *testing.T, address string, config *tls.Config) tlsCaller {
	t.Helper()
	return handshakeOver(t, dial(t, address), config)
}

// handshakeOver makes the caller's handshake over a connection already dialed.
func handshakeOver(t *testing.T, raw caller, config *tls.Config) tlsCaller {
	t.Helper()
	tapped := &tap{TCPConn: raw.connection}
	connection := tls.Client(tapped, config)
	ctx, cancel := context.WithTimeout(t.Context(), testrun.Patient(testrun.HangBound))
	defer cancel()
	if err := connection.HandshakeContext(ctx); err != nil {
		t.Fatalf("the caller's handshake failed: %v", err)
	}
	return tlsCaller{raw: raw, tap: tapped, tls: connection, lastFlight: tapped.lastWrite()}
}

// expectTLSServed dials the address over TLS and checks the engine sends the opening inside the
// channel by the margin.
func expectTLSServed(t *testing.T, address string) tlsCaller {
	t.Helper()
	call := dialTLS(t, address, tlsConfig(0))
	call.readExactly(t, opening, time.Now().Add(testrun.Patient(margin)))
	return call
}

// expectTLSServedOnceFreed dials over TLS until a caller is served. The lines do not say when,
// after a connection closes, its place in the count is freed, so a caller closed at once as one
// over the cap, its handshake ended with nothing from the engine, is tried again, by the hang
// bound; any other end of the handshake fails the row.
func expectTLSServedOnceFreed(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(testrun.Patient(testrun.HangBound))
	for {
		raw := dial(t, address)
		tapped := &tap{TCPConn: raw.connection}
		connection := tls.Client(tapped, tlsConfig(0))
		ctx, cancel := context.WithTimeout(t.Context(), testrun.Patient(testrun.HangBound))
		err := connection.HandshakeContext(ctx)
		cancel()
		if err == nil {
			call := tlsCaller{raw: raw, tap: tapped, tls: connection, lastFlight: tapped.lastWrite()}
			call.readExactly(t, opening, time.Now().Add(testrun.Patient(margin)))
			return
		}
		if !isEnd(err) {
			t.Fatalf("the caller's handshake ended with %v, want a service, or a close at once with nothing written", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("no TLS caller was served within %v: the place was never freed", testrun.Patient(testrun.HangBound))
		}
		_ = raw.connection.Close()
		pause(t, 20*time.Millisecond)
	}
}

func (call tlsCaller) send(t *testing.T, data []byte) {
	t.Helper()
	_ = call.tls.SetWriteDeadline(time.Now().Add(testrun.Patient(testrun.HangBound)))
	if _, err := call.tls.Write(data); err != nil {
		t.Fatalf("the caller's write failed: %v", err)
	}
}

// readExactly reads exactly the wanted bytes inside the channel, which must come by the deadline.
func (call tlsCaller) readExactly(t *testing.T, want []byte, deadline time.Time) {
	t.Helper()
	_ = call.tls.SetReadDeadline(deadline)
	received := make([]byte, len(want))
	got, err := io.ReadFull(call.tls, received)
	if err != nil || !bytes.Equal(received, want) {
		t.Fatalf("the caller got %q and %v, want %q", received[:got], err, want)
	}
	_ = call.tls.SetReadDeadline(time.Time{})
}

// readToEnd reads inside the channel until it ends or the deadline passes.
func (call tlsCaller) readToEnd(deadline time.Time) ([]byte, error) {
	_ = call.tls.SetReadDeadline(deadline)
	var received []byte
	chunk := make([]byte, 512)
	for {
		got, err := call.tls.Read(chunk)
		received = append(received, chunk[:got]...)
		if err != nil {
			return received, err
		}
	}
}
