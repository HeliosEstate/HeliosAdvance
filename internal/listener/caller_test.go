// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The scripted Telnet caller the Listener's tests drive the engine with, written from RFC 854 and
// RFC 1143 apart from the engine's code, with its own byte values, the greeting and the limits
// as the page's lines state them, and none of the engine's constants.
package listener_test

import (
	"context"
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
	"github.com/heliosestate/heliosadvance/internal/telnet"

	"github.com/heliosestate/heliosadvance/internal/testrun"
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

	binary byte = 0
	echo   byte = 1
	sga    byte = 3

	telnetTypeOption byte = 24
	windowSizeOption byte = 31
	speedOption      byte = 32
	environOption    byte = 39
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

// wideMargin is margin for a claim whose nearest fault is 3 seconds or more away: a caller served
// only after another's 3 seconds of negotiation, a stop that lets the closing wait run, a caller
// over the cap closed only after negotiation, a place freed only after the closing wait. Under
// twice the usual load, with the race detector, the runners delivered an opening 1.02 seconds
// into its window (ubuntu-latest, 2026-10-25), past margin; 1.5 seconds is half that gap. A
// window whose nearest fault is closer keeps margin: a closing wait or a ceiling 900 ms too long
// is such a fault. A window that opens after the fault's 3 seconds began closes at windowEnd.
const wideMargin = 1500 * time.Millisecond

// progressLimit bounds a wait whose line claims no time: the bytes a row needs before its next
// step. Only a hang should reach it: under twice the usual load such a wait has come at most
// 1.1 seconds late (2026-10-25). It is the one hang bound every package uses, as are the
// recordings that hold most of these calls. The line's own time, where it has one, is checked
// apart.
var progressLimit = testrun.Patient(testrun.HangBound)

// early is how far before its deadline a runner's clock may wake a wait.
const early = 20 * time.Millisecond

var (
	// opening is the eight requests Part 4's line gives, in order.
	opening = join(
		request(will, echo), request(will, sga), request(will, binary), request(doVerb, binary),
		request(doVerb, telnetTypeOption), request(doVerb, windowSizeOption),
		request(doVerb, environOption), request(doVerb, speedOption))
	// answers answers all eight, ECHO, SGA and BINARY agreed and the four terminal options
	// refused, so that no SEND follows and nothing but the call itself reaches the caller.
	answers = join(
		request(doVerb, echo), request(doVerb, sga), request(doVerb, binary), request(will, binary),
		request(wont, telnetTypeOption), request(wont, windowSizeOption),
		request(wont, environOption), request(wont, speedOption))
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

// openTelnet is Telnet's kind as the program pairs it: the real Accept, giving a nil KindConnection
// on an error, never one holding a nil Line.
func openTelnet(ctx context.Context, connection *net.TCPConn) (listener.KindConnection, error) {
	line, err := telnet.Accept(ctx, connection)
	if err != nil {
		return nil, err
	}
	return line, nil
}

// startEngine opens the given number of listening sockets on 127.0.0.1, on ports the operating
// system picks, starts the Listener on them as one Telnet kind, and stops it when the test ends.
func startEngine(t *testing.T, sockets int) []string {
	t.Helper()
	return startKind(t, sockets, openTelnet)
}

// startKind is startEngine with the kind's Open given.
func startKind(t *testing.T, sockets int, open listener.Open) []string {
	t.Helper()
	_, addresses := startListener(t, sockets, open)
	return addresses
}

// startListener is startKind, also returning the Listener, for the rows that stop it themselves.
// Each Listener it makes has a count of its own.
func startListener(t *testing.T, sockets int, open listener.Open) (*listener.Listener, []string) {
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
	engine, err := listener.New(listening, open, listener.NewCount())
	if err != nil {
		for _, socket := range listening {
			_ = socket.Close()
		}
		t.Fatalf("New refused: %v", err)
	}
	t.Cleanup(engine.Stop)
	engine.Start()
	return engine, addresses
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

// sending is when a caller's write began and when it returned. The engine can act on the bytes
// before the writer's goroutine reads the clock again, on a loaded runner by tens of
// milliseconds (ubuntu-latest, 2026-10-26, a greeting 64 ms before the write's return), so a
// window on what the engine does with them opens from began and closes from done.
type sending struct {
	began, done time.Time
}

// send writes the caller's bytes and returns when the write began and when it returned.
func (call caller) send(t *testing.T, data []byte) sending {
	t.Helper()
	_ = call.connection.SetWriteDeadline(time.Now().Add(testrun.Patient(testrun.HangBound)))
	began := time.Now()
	if _, err := call.connection.Write(data); err != nil {
		t.Fatalf("the caller's write failed: %v", err)
	}
	return sending{began: began, done: time.Now()}
}

// readOpening reads the engine's 24 opening bytes, which must come by the deadline.
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

// fillSilently fills the cap with silent callers, dialed in turn across the addresses, then reads
// every one's opening by one progressLimit from the last dial. Each opening's wait is bounded by
// the set-up as a whole, so an engine that holds every opening back fails the row in seconds,
// not once per caller.
func fillSilently(t *testing.T, addresses []string) []caller {
	t.Helper()
	callers := make([]caller, connectionCap)
	for index := range callers {
		callers[index] = dial(t, addresses[index%len(addresses)])
	}
	deadline := time.Now().Add(progressLimit)
	for _, call := range callers {
		call.readOpening(t, deadline)
	}
	return callers
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
// at once, writing nothing, and when the opening or the close arrived. Anything else fails the
// test. The caller sends nothing. A close that comes only after negotiation's 3 seconds is the
// nearest fault, so the wait is wideMargin, stretched under the race detector: there it is 6
// seconds, so such a close counts as at once, and only a run without it tells the two apart.
func served(t *testing.T, address string) (bool, caller, time.Time) {
	t.Helper()
	call := dial(t, address)
	_ = call.connection.SetReadDeadline(call.connected.Add(testrun.Patient(wideMargin)))
	received := make([]byte, len(opening))
	got, err := io.ReadFull(call.connection, received)
	arrived := time.Now()
	switch {
	case err == nil && slices.Equal(received, opening):
		return true, call, arrived
	case got == 0 && (errors.Is(err, io.EOF) || isReset(err)):
		return false, call, arrived
	default:
		t.Fatalf("a caller was neither served nor closed at once: % x, %v", received[:got], err)
		return false, call, arrived
	}
}

// expectRefused checks a new caller is closed at once without a byte written to it.
func expectRefused(t *testing.T, address string) {
	t.Helper()
	if isServed, _, _ := served(t, address); isServed {
		t.Fatalf("a caller over the cap was served")
	}
}

// expectRefusedUntil checks a new caller is closed at once while every place is held, as every
// place is until the moment held, less early, since the engine's timers may wake that much
// before their time: a caller served whose opening arrives before then is one over the cap. A
// caller served after it says nothing of the cap, since a place may rightly have come back
// first: the engine can accept a caller late on a loaded runner (287 ms after its dial, while
// the cap was full, ubuntu-24.04-arm, 2026-10-26). A probe dialed at or after that moment did
// not reach the row's case, and fails as a test fault whatever its outcome. Under the race
// detector the two faults of timing are logged instead, and a caller served too soon still fails.
func expectRefusedUntil(t *testing.T, address string, held time.Time) {
	t.Helper()
	isServed, call, arrived := served(t, address)
	switch {
	case !call.dialed.Before(held.Add(-early)):
		if testrun.Race {
			t.Logf("under the race detector, timing is not judged: the probe was dialed %v after a place could come back, so it tells nothing of the cap", call.dialed.Sub(held.Add(-early)))
		} else {
			t.Fatalf("test fault: the probe was dialed %v after a place could come back, so it tells nothing of the cap", call.dialed.Sub(held.Add(-early)))
		}
	case !isServed:
	case arrived.Before(held.Add(-early)):
		t.Fatalf("a caller over the cap was served, %v before a place could come back", held.Sub(arrived))
	default:
		if testrun.Race {
			t.Logf("under the race detector, timing is not judged: cannot tell a caller over the cap from one served after a place could come back: dialed %v before, served %v after", held.Sub(call.dialed), arrived.Sub(held))
		} else {
			t.Fatalf("cannot tell a caller over the cap from one served after a place could come back: dialed %v before, served %v after", held.Sub(call.dialed), arrived.Sub(held))
		}
	}
}

// helloAndClose fills the cap with callers waiting at the prompt, then types their names
// together and closes each once it has seen the shutdown. It returns when the names' writes
// began, before which no closing wait can start, and when the last close was made. Set up
// first, the hundred's closing waits start together, however long a runner took to dial them.
func helloAndClose(t *testing.T, address string) (released, closed time.Time) {
	t.Helper()
	callers, streams := fillAtPrompt(t, address)
	released = sendNames(t, callers)
	for index, stream := range streams {
		// End of stream is the shutdown: the caller is now in Close's wait.
		stream.expectStream(t, join(opening, asked, echoed("n")))
		_ = callers[index].connection.Close()
	}
	return released, time.Now()
}

// fillAtPrompt fills the cap with callers that answered and wait at the prompt, each recorded
// from its connect. Each recording may run 60 seconds from that connect, however long the set-up
// takes, until sendNames bounds them.
func fillAtPrompt(t *testing.T, address string) ([]caller, []*recording) {
	t.Helper()
	callers := make([]caller, connectionCap)
	streams := make([]*recording, connectionCap)
	for index := range callers {
		callers[index] = dial(t, address)
		streams[index] = callers[index].record(callers[index].connected.Add(nameLimit))
		callers[index].send(t, answers)
		streams[index].waitFor(t, len(opening)+len(asked), time.Now().Add(progressLimit))
	}
	return callers, streams
}

// sendNames types every caller's name, returning when the first write began, and holds the rest
// of each recording to progressLimit, so an engine that never shuts down fails in seconds.
func sendNames(t *testing.T, callers []caller) time.Time {
	t.Helper()
	released := time.Now()
	for _, call := range callers {
		call.send(t, []byte("n\r"))
		_ = call.connection.SetReadDeadline(released.Add(progressLimit))
	}
	return released
}

// windowEnd closes a window that opens at from, for a claim whose nearest fault comes no sooner
// than fault: wideMargin after from, or half the way to the fault where that is sooner. A fault
// whose 3 seconds start before the window opens is nearer than 3 seconds by however late the row
// opened it (a stop that lands into the closing wait it should cut short), and the window must
// stay clear of it. Where a step before the window ran so late that half the way is under
// margin, the row cannot tell the two apart and fails. The step may be the test's or the
// engine's: a broken engine that holds a call back makes it late too (a serial engine's silent
// caller, an opening held for the caller's first byte), so the failure blames neither. Under the
// race detector, which judges no upper bound on time, it logs instead and closes the window at
// margin, the narrowest it gives otherwise, so that a row that dials until its window ends still
// dials.
func windowEnd(t *testing.T, from, fault time.Time) time.Time {
	t.Helper()
	half := fault.Sub(from) / 2
	if half < margin {
		if testrun.Race {
			t.Logf("under the race detector, timing is not judged: cannot tell the window from its nearest fault, %v apart", fault.Sub(from))
			return from.Add(margin)
		}
		t.Fatalf("cannot tell the window from its nearest fault, %v apart: a step before the window ran late, in the test or in the engine", fault.Sub(from))
	}
	return from.Add(min(wideMargin, half))
}

// expectServedBy dials until a caller is served, which must happen by the deadline: a caller
// refused before then is tried again. Served is when the opening arrived, not when the dial
// connected: a caller's connect completes before the engine accepts it. Under the race detector
// a late caller is logged, not failed, and the dials go on for the deadline's time stretched, so
// only a place that never comes back fails.
func expectServedBy(t *testing.T, address string, deadline time.Time) {
	t.Helper()
	// Its window runs from the call to the deadline, so a margin can be read from any run.
	called := time.Now()
	giveUp := deadline
	if testrun.Race {
		// From whichever is later, the deadline or now: a test that reached here late has no time
		// of its own left to stretch.
		giveUp = time.Now()
		if deadline.After(giveUp) {
			giveUp = deadline
		}
		giveUp = giveUp.Add(testrun.Patient(wideMargin))
	}
	for {
		if isServed, _, arrived := served(t, address); isServed {
			t.Logf("a caller's service came %v into its window of %v", arrived.Sub(called), deadline.Sub(called))
			if arrived.After(deadline) {
				if testrun.Race {
					t.Logf("under the race detector, timing is not judged: no caller was served until %v past the deadline", arrived.Sub(deadline))
					return
				}
				t.Fatalf("no caller was served until %v past the deadline", arrived.Sub(deadline))
			}
			return
		}
		if time.Now().After(giveUp) {
			t.Fatalf("every caller was refused until %v, %v past the deadline", giveUp.Format(time.RFC3339Nano), giveUp.Sub(deadline))
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

// expectWithin checks a moment falls in its window and logs how far into it it came. Under the
// race detector, which slows the engine by an amount nobody controls, only too soon fails.
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
