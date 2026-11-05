// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package telnets_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/telnet"
	"github.com/heliosestate/heliosadvance/internal/telnets"
	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// Telnet's bytes and limits, from RFC 854 and Part 4's lines, written here so a changed constant
// in the engine cannot move a test with it.
const (
	iac         byte = 255
	dont        byte = 254
	doVerb      byte = 253
	wont        byte = 252
	will        byte = 251
	abortOutput byte = 245
	dataMark    byte = 242

	echo   byte = 1
	sga    byte = 3
	binary byte = 0

	telnetTypeOption byte = 24
	windowSizeOption byte = 31
	speedOption      byte = 32
	environOption    byte = 39

	negotiationLimit = 3 * time.Second
)

var (
	// opening is the eight requests Part 4's line gives, in order.
	opening = []byte{iac, will, echo, iac, will, sga, iac, will, binary, iac, doVerb, binary,
		iac, doVerb, telnetTypeOption, iac, doVerb, windowSizeOption, iac, doVerb, environOption, iac, doVerb, speedOption}
	// answers answers all eight, ECHO, SGA and BINARY agreed and the four terminal options
	// refused, so that no SEND follows.
	answers = []byte{iac, doVerb, echo, iac, doVerb, sga, iac, doVerb, binary, iac, will, binary,
		iac, wont, telnetTypeOption, iac, wont, windowSizeOption, iac, wont, environOption, iac, wont, speedOption}
)

// margin is how late past a moment an event may come on the slowest runner: the margin the
// Telnet unit's tests measured on 2026-10-16, which a TLS record's work on loopback stays well
// inside.
const margin = 750 * time.Millisecond

// early is how far before its deadline a runner's clock may wake a wait.
const early = 20 * time.Millisecond

// quiet is how long a row that checks nothing comes waits for it.
const quiet = 300 * time.Millisecond

// The TLS record types, from RFC 8446 section 5.1.
const (
	changeCipherSpecRecord byte = 20
	alertRecord            byte = 21
	handshakeRecord        byte = 22
	applicationDataRecord  byte = 23
)

// recordTypes reads data as TLS records, header by header, and returns each record's type and
// how many bytes trail the last whole record: a record cut short, or bytes that are no record.
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

// tap is the caller's TCP connection beneath its TLS client: every byte the engine sends is kept
// as it arrived, so a row can read the records' types, and the start of every write is noted, so
// a row can tell when the caller's last handshake flight began. With damage set, the next write
// goes out with its last byte changed.
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

// receivedSoFar is every byte the engine has sent the caller so far.
func (connection *tap) receivedSoFar() []byte {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	return bytes.Clone(connection.received)
}

// lastWrite is when the caller's latest write began.
func (connection *tap) lastWrite() time.Time {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	return connection.writes[len(connection.writes)-1]
}

// damageNext changes the last byte of the caller's next write.
func (connection *tap) damageNext() {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	connection.damage = true
}

// tlsCaller is QA's own Telnet caller over a crypto/tls client, written apart from the engine's
// code: it verifies the engine's certificate against those the run made, as a caller's client
// verifies it against those it trusts.
type tlsCaller struct {
	tap *tap
	tls *tls.Conn
	// lastFlight is when the caller began the last write of its handshake: the engine's
	// handshake cannot complete before that write reaches it.
	lastFlight time.Time
}

// clientConfig offers the one version given, and verifies the engine's certificate for localhost.
func clientConfig(version uint16) *tls.Config {
	return &tls.Config{RootCAs: trustedPool(), ServerName: "localhost", MinVersion: version, MaxVersion: version}
}

// handshake makes the caller's TLS handshake over its end of the connection, by the hang bound.
func handshake(t *testing.T, client *net.TCPConn, config *tls.Config) tlsCaller {
	t.Helper()
	tapped := &tap{TCPConn: client}
	connection := tls.Client(tapped, config)
	ctx, cancel := context.WithTimeout(t.Context(), testrun.Patient(testrun.HangBound))
	defer cancel()
	if err := connection.HandshakeContext(ctx); err != nil {
		t.Fatalf("the caller's handshake failed: %v", err)
	}
	return tlsCaller{tap: tapped, tls: connection, lastFlight: tapped.lastWrite()}
}

// send writes the caller's bytes inside the channel.
func (call tlsCaller) send(t *testing.T, data []byte) {
	t.Helper()
	_ = call.tls.SetWriteDeadline(time.Now().Add(testrun.Patient(testrun.HangBound)))
	if _, err := call.tls.Write(data); err != nil {
		t.Fatalf("the caller's write failed: %v", err)
	}
}

// readExactly reads exactly the wanted bytes inside the channel, which must come by the
// deadline.
func (call tlsCaller) readExactly(t *testing.T, want []byte, deadline time.Time) {
	t.Helper()
	_ = call.tls.SetReadDeadline(deadline)
	received := make([]byte, len(want))
	got, err := io.ReadFull(call.tls, received)
	if err != nil || !bytes.Equal(received, want) {
		t.Fatalf("the caller got % x and %v, want % x", received[:got], err, want)
	}
	_ = call.tls.SetReadDeadline(time.Time{})
}

// readToEnd reads inside the channel until it ends or the deadline passes, and returns what came
// and why it stopped.
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

// pair is one loopback connection: the client end QA's caller holds and the server end handed to
// Accept.
type pair struct {
	client, server *net.TCPConn
	// dialed is a moment before the server end existed.
	dialed time.Time
}

// connect opens a loopback listener on a port the operating system picks, dials it and accepts,
// and closes both ends when the test ends.
func connect(t *testing.T) pair {
	t.Helper()
	listening, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on loopback: %v", err)
	}
	defer func() { _ = listening.Close() }()
	dialed := time.Now()
	clientEnd, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", listening.Addr().String())
	if err != nil {
		t.Fatalf("dialing loopback: %v", err)
	}
	serverEnd, err := listening.Accept()
	if err != nil {
		t.Fatalf("accepting on loopback: %v", err)
	}
	client, clientIsTCP := clientEnd.(*net.TCPConn)
	server, serverIsTCP := serverEnd.(*net.TCPConn)
	if !clientIsTCP || !serverIsTCP {
		t.Fatalf("loopback connection is not TCP: %T, %T", clientEnd, serverEnd)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return pair{client: client, server: server, dialed: dialed}
}

// accepted is what one Accept call returned, and when.
type accepted struct {
	line     *telnet.Line
	err      error
	returned time.Time
}

// acceptOn calls Accept on its own goroutine, as the shared execution path does.
func acceptOn(ctx context.Context, connection *net.TCPConn, certificate *telnets.Certificate) <-chan accepted {
	done := make(chan accepted, 1)
	go func() {
		line, err := telnets.Accept(ctx, connection, certificate)
		done <- accepted{line: line, err: err, returned: time.Now()}
	}()
	return done
}

// waitAccepted waits for Accept to return by the deadline; a result already in wins over a
// deadline the test came late to.
func waitAccepted(t *testing.T, done <-chan accepted, deadline time.Time) accepted {
	t.Helper()
	return waitAcceptedTelling(t, done, deadline, nil)
}

// waitAcceptedTelling is waitAccepted whose failure also gives what detail says, so a row whose
// Accept never returns can show where it stopped; nil adds nothing.
func waitAcceptedTelling(t *testing.T, done <-chan accepted, deadline time.Time, detail func() string) accepted {
	t.Helper()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case got := <-done:
		return got
	case <-timer.C:
		select {
		case got := <-done:
			return got
		default:
			if detail != nil {
				t.Fatalf("Accept had not returned by the deadline.\n%s", detail())
			}
			t.Fatalf("Accept had not returned by the deadline")
			return accepted{}
		}
	}
}

// readCertificate reads good files of the kind, failing the row if ReadCertificate refuses them.
func readCertificate(t *testing.T, files tlsFiles) *telnets.Certificate {
	t.Helper()
	certificate, err := telnets.ReadCertificate(files.certificate, files.key)
	if err != nil || certificate == nil {
		t.Fatalf("ReadCertificate gave %v and %v for good files, want a Certificate", certificate, err)
	}
	return certificate
}

// acceptedCaller is a Line Accept made for QA's caller over the version given, the opening read
// inside the channel and answered; it returns the caller and the Line.
func acceptedCaller(t *testing.T, version uint16) (pair, tlsCaller, *telnet.Line) {
	t.Helper()
	connection := connect(t)
	done := acceptOn(t.Context(), connection.server, readCertificate(t, goodFiles(t, ecdsaP256)))
	call := handshake(t, connection.client, clientConfig(version))
	call.readExactly(t, opening, time.Now().Add(testrun.Patient(margin)))
	call.send(t, answers)
	got := waitAccepted(t, done, time.Now().Add(testrun.Patient(margin)))
	if got.err != nil || got.line == nil {
		t.Fatalf("Accept gave %v and %v, want a Line", got.line, got.err)
	}
	return connection, call, got.line
}

// rawToEnd reads the TCP connection beneath until it ends or the deadline passes.
func rawToEnd(connection *net.TCPConn, deadline time.Time) ([]byte, error) {
	_ = connection.SetReadDeadline(deadline)
	var received []byte
	chunk := make([]byte, 4096)
	for {
		got, err := connection.Read(chunk)
		received = append(received, chunk[:got]...)
		if err != nil {
			return received, err
		}
	}
}

// isEnd is a read the other end ended: end of stream, or a reset.
func isEnd(err error) bool {
	return errors.Is(err, io.EOF) || isReset(err)
}

// isReset tells a connection reset or abort, as Linux and Windows report it.
func isReset(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return slices.Contains([]syscall.Errno{syscall.ECONNRESET, syscall.EPIPE, 10053, 10054}, errno)
}

// expectNotClosed checks the engine's end is still open: a byte the test writes there reaches the
// caller.
func expectNotClosed(t *testing.T, connection pair) {
	t.Helper()
	_ = connection.server.SetWriteDeadline(time.Now().Add(testrun.Patient(testrun.HangBound)))
	if _, err := connection.server.Write([]byte("z")); err != nil {
		t.Fatalf("a write to the server's end failed, so something closed it: %v", err)
	}
	_ = connection.client.SetReadDeadline(time.Now().Add(testrun.Patient(margin)))
	for {
		buffer := make([]byte, 64)
		got, err := connection.client.Read(buffer)
		if bytes.HasSuffix(buffer[:got], []byte("z")) {
			return
		}
		if err != nil {
			t.Fatalf("the caller never received the test's byte through the server's end: %v", err)
		}
	}
}

// expectWithin checks a moment falls in its window and logs how far into it it came. Under the
// race detector only too soon fails.
func expectWithin(t *testing.T, what string, moment, notBefore, notAfter time.Time) {
	t.Helper()
	t.Logf("%s came %v into its window of %v", what, moment.Sub(notBefore), notAfter.Sub(notBefore))
	if moment.Before(notBefore.Add(-early)) {
		t.Fatalf("%s came %v too soon", what, notBefore.Sub(moment))
	}
	if moment.After(notAfter) {
		if testrun.Race {
			t.Logf("under the race detector, timing is not judged: %s came %v late", what, moment.Sub(notAfter))
		} else {
			t.Fatalf("%s came %v too late", what, moment.Sub(notAfter))
		}
	}
}

// wait waits on the clock or the test's end; used only between a caller's probing steps.
func wait(ctx context.Context, until time.Time) {
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}

// errNoUrgentData is receiveUrgent finding no urgent byte by its deadline.
var errNoUrgentData = errors.New("no urgent data by the deadline")

// isDeadline is a read that gave up at its deadline.
func isDeadline(err error) bool {
	return errors.Is(err, os.ErrDeadlineExceeded)
}
