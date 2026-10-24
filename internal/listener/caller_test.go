// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The scripted Telnet caller the Listener's tests drive the engine with, written from RFC 854 and
// RFC 1143 apart from the engine's code, with its own byte values, the greeting and the limits
// as the page's lines state them, and none of the engine's constants.
package listener_test

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/listener"
)

const (
	iac    byte = 255
	dont   byte = 254
	doVerb byte = 253
	wont   byte = 252
	will   byte = 251
	nop    byte = 241
	ayt    byte = 246

	subnegotiationBegin byte = 250
	subnegotiationEnd   byte = 240

	echo byte = 1
	sga  byte = 3

	telnetTypeOption byte = 24
	windowSizeOption byte = 31
)

// The page's limits, written here so a changed constant in the engine cannot move a test with it.
const (
	greeting         = "Hello Helios Advance BBS!\r\n"
	negotiationLimit = 3 * time.Second
	closingWaitLimit = 3 * time.Second
	connectionCap    = 100
)

// margin is how late past a limit an event may come on the slowest runner, under the race
// detector and with every test running in parallel. On 2026-10-16 the three runners woke a
// deadline at most 1.2 ms late and moved bytes over loopback in under 0.5 ms, forty connections
// at once; the rest is room for the engine's own work under load.
const margin = 750 * time.Millisecond

// early is how far before its deadline a runner's clock may wake a wait.
const early = 20 * time.Millisecond

var (
	opening = []byte{iac, will, echo, iac, will, sga}
	answers = join(request(doVerb, echo), request(doVerb, sga))
)

func request(verb, option byte) []byte {
	return []byte{iac, verb, option}
}

func join(parts ...[]byte) []byte {
	var joined []byte
	for _, part := range parts {
		joined = append(joined, part...)
	}
	return joined
}

func repeated(part []byte, count int) []byte {
	var joined []byte
	for range count {
		joined = append(joined, part...)
	}
	return joined
}

// startEngine opens the given number of listening sockets on 127.0.0.1, on ports the operating
// system picks, starts the Listener on them, and stops it when the test ends.
func startEngine(t *testing.T, sockets int) []string {
	t.Helper()
	var listening []*net.TCPListener
	var addresses []string
	for range sockets {
		opened, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listening on loopback: %v", err)
		}
		socket, isTCP := opened.(*net.TCPListener)
		if !isTCP {
			t.Fatalf("the listening socket is a %T", opened)
		}
		listening = append(listening, socket)
		addresses = append(addresses, socket.Addr().String())
	}
	engine, err := listener.Start(listening)
	if err != nil {
		for _, socket := range listening {
			_ = socket.Close()
		}
		t.Fatalf("Start refused: %v", err)
	}
	t.Cleanup(engine.Stop)
	return addresses
}

// caller is one scripted caller's connection.
type caller struct {
	connection *net.TCPConn
	// dialed is a moment before the engine accepted, so before anything the engine did for it.
	dialed time.Time
	// connected is when the dial returned.
	connected time.Time
}

// dial connects a caller, closed when the test ends.
func dial(t *testing.T, address string) caller {
	t.Helper()
	dialed := time.Now()
	opened, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatalf("dialing the engine: %v", err)
	}
	connection, isTCP := opened.(*net.TCPConn)
	if !isTCP {
		t.Fatalf("the caller's connection is a %T", opened)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return caller{connection: connection, dialed: dialed, connected: time.Now()}
}

// send writes the caller's bytes and returns when they went.
func (call caller) send(t *testing.T, data []byte) time.Time {
	t.Helper()
	_ = call.connection.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := call.connection.Write(data); err != nil {
		t.Fatalf("the caller's write failed: %v", err)
	}
	return time.Now()
}

// readOpening reads the engine's six opening bytes, which must come by the deadline.
func (call caller) readOpening(t *testing.T, deadline time.Time) time.Time {
	t.Helper()
	_ = call.connection.SetReadDeadline(deadline)
	received := make([]byte, len(opening))
	got, err := io.ReadFull(call.connection, received)
	if err != nil || !slices.Equal(received, opening) {
		t.Fatalf("the opening was % x and %v, want % x", received[:got], err, opening)
	}
	_ = call.connection.SetReadDeadline(time.Time{})
	return time.Now()
}

// isReset tells a connection reset or abort, as Linux and Windows report it.
func isReset(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return slices.Contains([]syscall.Errno{syscall.ECONNRESET, syscall.EPIPE, 10053, 10054}, errno)
}

// served dials and reports whether the engine served the caller (sent the opening) or closed it
// at once, writing nothing. Anything else fails the test. The caller sends nothing.
func served(t *testing.T, address string) (bool, caller) {
	t.Helper()
	call := dial(t, address)
	_ = call.connection.SetReadDeadline(call.connected.Add(margin))
	received := make([]byte, len(opening))
	got, err := io.ReadFull(call.connection, received)
	switch {
	case err == nil && slices.Equal(received, opening):
		return true, call
	case got == 0 && (errors.Is(err, io.EOF) || isReset(err)):
		return false, call
	default:
		t.Fatalf("a caller was neither served nor closed at once: % x, %v", received[:got], err)
		return false, call
	}
}

// expectRefused checks a new caller is closed at once without a byte written to it.
func expectRefused(t *testing.T, address string) {
	t.Helper()
	if isServed, _ := served(t, address); isServed {
		t.Fatalf("a caller over the cap was served")
	}
}

// expectServedBy dials until a caller is served, which must happen by the deadline: a caller
// refused before then is tried again.
func expectServedBy(t *testing.T, address string, deadline time.Time) time.Time {
	t.Helper()
	for {
		if isServed, call := served(t, address); isServed {
			if call.connected.After(deadline) {
				t.Fatalf("no caller was served until %v past the deadline", call.connected.Sub(deadline))
			}
			t.Logf("a caller was served %v before the deadline", deadline.Sub(call.connected))
			return call.connected
		}
		if time.Now().After(deadline) {
			t.Fatalf("every caller was refused until the deadline")
		}
		wait(t, time.Now().Add(20*time.Millisecond))
	}
}

// wait blocks until the moment comes or the test ends. It waits on the clock only where the
// clock is what a line is about.
func wait(t *testing.T, until time.Time) {
	t.Helper()
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
	}
}

// recording is everything the engine sends a caller, each chunk with the moment it arrived,
// read on its own goroutine until end of stream.
type recording struct {
	mutex    sync.Mutex
	received []byte
	arrived  []time.Time
	end      error
	ended    time.Time
	done     chan struct{}
}

// record starts reading the caller's connection; it gives up at the deadline.
func (call caller) record(deadline time.Time) *recording {
	stream := &recording{done: make(chan struct{})}
	_ = call.connection.SetReadDeadline(deadline)
	go func() {
		defer close(stream.done)
		chunk := make([]byte, 4096)
		for {
			got, err := call.connection.Read(chunk)
			now := time.Now()
			stream.mutex.Lock()
			for range got {
				stream.arrived = append(stream.arrived, now)
			}
			stream.received = append(stream.received, chunk[:got]...)
			if err != nil {
				stream.end, stream.ended = err, now
			}
			stream.mutex.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return stream
}

// expectStream waits for end of stream and checks every byte the caller received, and that the
// stream ended in order.
func (stream *recording) expectStream(t *testing.T, want []byte) {
	t.Helper()
	<-stream.done
	if !errors.Is(stream.end, io.EOF) {
		t.Fatalf("the stream did not end in order: %v, after % x", stream.end, stream.received)
	}
	if !slices.Equal(stream.received, want) {
		t.Fatalf("the stream was\n% x\nwant\n% x", stream.received, want)
	}
}

// at is when the byte at offset arrived; the stream must have ended.
func (stream *recording) arrivedAt(t *testing.T, offset int) time.Time {
	t.Helper()
	<-stream.done
	if offset >= len(stream.arrived) {
		t.Fatalf("the stream holds %d bytes, none at %d", len(stream.arrived), offset)
	}
	return stream.arrived[offset]
}

// expectWithin checks a moment falls in its window and logs how far into it it came.
func expectWithin(t *testing.T, what string, moment, notBefore, notAfter time.Time) {
	t.Helper()
	if moment.Before(notBefore.Add(-early)) {
		t.Fatalf("%s came %v too soon", what, notBefore.Sub(moment))
	}
	if moment.After(notAfter) {
		t.Fatalf("%s came %v too late", what, moment.Sub(notAfter))
	}
	t.Logf("%s: %v after the window opened", what, moment.Sub(notBefore))
}

// engineClosed watches Linux's table of IPv4 TCP sockets for the engine's end of a connection,
// found by its two ports, and returns when the engine closed it, the socket having lost its
// owner (its inode 0) or gone, and when the engine shut its sending side, the owned socket
// having left ESTABLISHED: after the last look that saw it ESTABLISHED and by the first that
// did not, both zero if it did not before the close. A look can come late on a loaded runner,
// so the shutdown is known only between the two. It fails if it never saw the socket owned, so
// a wrong match cannot pass for a close.
func engineClosed(t *testing.T, engineAddress, callerAddress string, deadline time.Time) (closed, shutAfter, shutBy time.Time) {
	t.Helper()
	port := func(address string) string {
		_, number, err := net.SplitHostPort(address)
		value, convErr := strconv.Atoi(number)
		if err != nil || convErr != nil {
			t.Fatalf("the address %q has no port", address)
		}
		return fmt.Sprintf("%04X", value)
	}
	local, remote := port(engineAddress), port(callerAddress)
	seen := false
	var lastEstablished time.Time
	for time.Now().Before(deadline) {
		looked := time.Now()
		table, err := os.ReadFile("/proc/net/tcp")
		if err != nil {
			t.Fatalf("reading the socket table: %v", err)
		}
		owned, present, established := false, false, false
		for line := range strings.SplitSeq(string(table), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 10 || !strings.HasSuffix(fields[1], ":"+local) || !strings.HasSuffix(fields[2], ":"+remote) {
				continue
			}
			present = true
			owned = fields[9] != "0"
			// The table's state 01 is ESTABLISHED.
			established = fields[3] == "01"
		}
		now := time.Now()
		switch {
		case present && owned && established:
			seen = true
			lastEstablished = looked
		case present && owned:
			seen = true
			if shutBy.IsZero() {
				shutAfter, shutBy = lastEstablished, now
			}
		case seen:
			return now, shutAfter, shutBy
		}
		wait(t, time.Now().Add(10*time.Millisecond))
	}
	if !seen {
		t.Fatalf("the engine's end of %s to %s was never in the socket table", callerAddress, engineAddress)
	}
	t.Fatalf("the engine had not closed the connection by the deadline")
	return time.Time{}, time.Time{}, time.Time{}
}

// awaitReset writes a byte at a time until a write fails with a reset, which is how a caller
// whose bytes the engine has not read sees the engine close, and returns when. A write that
// waits is not a failure: the engine is not reading.
func (call caller) awaitReset(t *testing.T, deadline time.Time) time.Time {
	t.Helper()
	for time.Now().Before(deadline) {
		_ = call.connection.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
		_, err := call.connection.Write([]byte("x"))
		switch {
		case err == nil, errors.Is(err, os.ErrDeadlineExceeded):
			wait(t, time.Now().Add(20*time.Millisecond))
		case isReset(err):
			return time.Now()
		default:
			t.Fatalf("the caller's write failed other than by a reset: %v", err)
		}
	}
	t.Fatalf("the engine had not closed the connection by the deadline")
	return time.Time{}
}

// flood sends option requests and never reads, until its own writes stop going through: the
// engine's replies have filled the buffers, so a write of the engine's waits.
func (call caller) flood(t *testing.T) {
	t.Helper()
	_ = call.connection.SetReadBuffer(4096)
	requests := repeated(request(doVerb, telnetTypeOption), 1024)
	for {
		_ = call.connection.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
		_, err := call.connection.Write(requests)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return
		}
		if err != nil {
			t.Errorf("flooding: %v", err)
			return
		}
	}
}
