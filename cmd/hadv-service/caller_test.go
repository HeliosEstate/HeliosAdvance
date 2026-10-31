// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The scripted Telnet caller the program's tests drive it with, written from RFC 854 and RFC 1143
// apart from the engine's code, with its own byte values, the greeting and the limits as the
// page's lines state them, and none of the engine's constants.
package main_test

import (
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

const (
	iac    byte = 255
	dont   byte = 254
	doVerb byte = 253
	wont   byte = 252
	will   byte = 251

	subnegotiationBegin byte = 250
	subnegotiationEnd   byte = 240

	binary byte = 0
	echo   byte = 1
	sga    byte = 3

	telnetTypeOption byte = 24
	windowSizeOption byte = 31
	speedOption      byte = 32
	environOption    byte = 39
	// unknownOption is on neither side of the tables, so the engine refuses it.
	unknownOption byte = 25
)

// The page's limits and greeting, written here so a changed constant in the engine cannot move
// a test with it.
const (
	greeting         = "Hello Helios Advance BBS!\r\n"
	negotiationLimit = 3 * time.Second
	closingWait      = 3 * time.Second
	connectionCap    = 100
)

// margin is how late past a moment an event may come on the slowest runner, as the listener's
// tests measured it on 2026-10-16: deadlines woke at most 1.2 ms late and loopback moved bytes
// in under 0.5 ms; the rest is room for the engine's work under the race detector.
const margin = 750 * time.Millisecond

// early is how far before its deadline a runner's clock may wake a wait.
const early = 20 * time.Millisecond

var (
	// opening is the eight requests Part 4's line gives, in order.
	opening = []byte{iac, will, echo, iac, will, sga, iac, will, binary, iac, doVerb, binary,
		iac, doVerb, telnetTypeOption, iac, doVerb, windowSizeOption, iac, doVerb, environOption, iac, doVerb, speedOption}
	// answers answers all eight, ECHO, SGA and BINARY agreed and the four terminal options
	// refused, so that no SEND follows.
	answers = []byte{iac, doVerb, echo, iac, doVerb, sga, iac, doVerb, binary, iac, will, binary,
		iac, wont, telnetTypeOption, iac, wont, windowSizeOption, iac, wont, environOption, iac, wont, speedOption}
)

// caller is one scripted caller's connection.
type caller struct {
	connection *net.TCPConn
	connected  time.Time
}

// dial connects a caller, closed when the test ends.
func dial(t *testing.T, address string) caller {
	t.Helper()
	opened, err := (&net.Dialer{Timeout: testrun.Patient(10 * time.Second)}).DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatalf("dialing the engine at %s: %v", address, err)
	}
	connection, isTCP := opened.(*net.TCPConn)
	if !isTCP {
		t.Fatalf("the caller's connection is a %T", opened)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return caller{connection: connection, connected: time.Now()}
}

// send writes the caller's bytes.
func (call caller) send(t *testing.T, data []byte) {
	t.Helper()
	_ = call.connection.SetWriteDeadline(time.Now().Add(testrun.Patient(5 * time.Second)))
	if _, err := call.connection.Write(data); err != nil {
		t.Fatalf("the caller's write failed: %v", err)
	}
}

// expectServed dials the address and checks the engine sends the opening by the margin.
func expectServed(t *testing.T, address string) caller {
	t.Helper()
	call := dial(t, address)
	call.readExactly(t, opening, call.connected.Add(testrun.Patient(margin)))
	return call
}

// served dials the address and tells whether the engine sent the opening by the margin, or
// closed the connection at once without writing to it, as it does while it is full.
func served(t *testing.T, address string) bool {
	t.Helper()
	call := dial(t, address)
	_ = call.connection.SetReadDeadline(call.connected.Add(testrun.Patient(margin)))
	received := make([]byte, len(opening))
	got, err := io.ReadFull(call.connection, received)
	switch {
	case err == nil && slices.Equal(received, opening):
		return true
	case got == 0 && (errors.Is(err, io.EOF) || isReset(err)):
		_ = call.connection.Close()
		return false
	case errors.Is(err, os.ErrDeadlineExceeded):
		t.Fatalf("the engine neither served nor closed a new caller at %s within the margin", address)
	}
	t.Fatalf("a new caller at %s got % x and %v, want the opening or a close", address, received[:got], err)
	return false
}

// readExactly reads exactly the wanted bytes, which must come by the deadline.
func (call caller) readExactly(t *testing.T, want []byte, deadline time.Time) {
	t.Helper()
	_ = call.connection.SetReadDeadline(deadline)
	received := make([]byte, len(want))
	got, err := io.ReadFull(call.connection, received)
	if err != nil || !slices.Equal(received, want) {
		t.Fatalf("the caller got % x and %v, want % x", received[:got], err, want)
	}
	_ = call.connection.SetReadDeadline(time.Time{})
}

// expectEnd reads until the engine ends the stream, which must come in the window with nothing
// more sent, and returns when.
func (call caller) expectEnd(t *testing.T, notBefore, notAfter time.Time) time.Time {
	t.Helper()
	// A test that comes here past its window cannot tell when the engine closed: a close already
	// made is read at once, but its moment is gone. It still reads, briefly, so a close never
	// made stays the engine's fault.
	readBy := notAfter
	late := time.Since(notAfter)
	if late > 0 {
		readBy = time.Now().Add(testrun.Patient(margin))
	}
	_ = call.connection.SetReadDeadline(readBy)
	chunk := make([]byte, 256)
	got, err := call.connection.Read(chunk)
	ended := time.Now()
	switch {
	case got > 0:
		t.Fatalf("the caller got % x where the engine was to close the connection", chunk[:got])
	case errors.Is(err, os.ErrDeadlineExceeded):
		t.Fatalf("the engine had not closed the connection %v after the window opened", readBy.Sub(notBefore))
	case !errors.Is(err, io.EOF) && !isReset(err):
		t.Fatalf("the caller's read failed other than by the engine closing: %v", err)
	}
	if late > 0 {
		if testrun.Race {
			t.Logf("under the race detector, timing is not judged: the test came %v past its window to read the close", late)
			return ended
		}
		t.Fatalf("cannot tell when the engine closed the connection: the test came %v past its window to read it", late)
	}
	expectWithin(t, "the close", ended, notBefore, notAfter)
	return ended
}

// awaitReset writes a byte at a time until a write fails with a reset, which is how a caller
// whose sending side the engine has already shut down sees the engine close, and returns when.
func (call caller) awaitReset(t *testing.T, notBefore, notAfter time.Time) time.Time {
	t.Helper()
	for time.Now().Before(notAfter) {
		_ = call.connection.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
		_, err := call.connection.Write([]byte("x"))
		switch {
		case err == nil, errors.Is(err, os.ErrDeadlineExceeded):
			pause(t, 10*time.Millisecond)
		case isReset(err):
			ended := time.Now()
			expectWithin(t, "the close", ended, notBefore, notAfter)
			return ended
		default:
			t.Fatalf("the caller's write failed other than by a reset: %v", err)
		}
	}
	t.Fatalf("the engine had not closed the connection by the end of the window")
	return time.Time{}
}

// pause waits on the clock or the test's end. It is used only between a caller's probing writes
// or dials, where the gap is the probe's resolution.
func pause(t *testing.T, length time.Duration) {
	t.Helper()
	timer := time.NewTimer(length)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
	}
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

// isReset tells a connection reset or abort, as Linux and Windows report it.
func isReset(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return slices.Contains([]syscall.Errno{syscall.ECONNRESET, syscall.EPIPE, 10053, 10054}, errno)
}

// isRefused tells a refused connection, as Linux and Windows report it.
func isRefused(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return slices.Contains([]syscall.Errno{syscall.ECONNREFUSED, 10061}, errno)
}
