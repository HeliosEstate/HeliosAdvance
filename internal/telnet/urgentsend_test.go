// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// QA's rows on the urgent byte's own send: in package telnet, so that the connection is wrapped
// as Accept wraps it and WriteUrgent is given the urgent byte alone. Through a Line, a Synch's
// IAC goes out first in the ordinary write, which is the write that waits on a full connection,
// so no row from outside reaches the urgent send's wait. Every wait here is bounded: a send no
// deadline or wake reaches fails its own row, not the package's timeout. The file name ends in
// no operating system, so the rows run on every runner.
package telnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// sendMargin is the margin the Telnet unit's other timed rows use.
const sendMargin = 750 * time.Millisecond

// sendBound is how long past its expected return a row waits for WriteUrgent before it resets
// the caller, which ends any send, and fails.
const sendBound = 3 * time.Second

// sendPair is a loopback pair with urgent data kept in line on both ends, the caller's included,
// since Windows resets a caller that does not read its urgent data and lets it pile up.
func sendPair(t *testing.T) (*acceptedConn, *net.TCPConn) {
	t.Helper()
	listening, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on loopback: %v", err)
	}
	defer func() { _ = listening.Close() }()
	callerEnd, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", listening.Addr().String())
	if err != nil {
		t.Fatalf("dialing loopback: %v", err)
	}
	engineEnd, err := listening.Accept()
	if err != nil {
		t.Fatalf("accepting on loopback: %v", err)
	}
	caller, callerIsTCP := callerEnd.(*net.TCPConn)
	engine, engineIsTCP := engineEnd.(*net.TCPConn)
	if !callerIsTCP || !engineIsTCP {
		t.Fatalf("loopback connection is not TCP: %T, %T", callerEnd, engineEnd)
	}
	t.Cleanup(func() {
		_ = caller.Close()
		_ = engine.Close()
	})
	for _, end := range []*net.TCPConn{caller, engine} {
		if err := keepUrgentInLine(end); err != nil {
			t.Fatalf("keeping urgent data in line: %v", err)
		}
	}
	// Small buffers, so that a caller that does not read stops the engine's writes sooner.
	if err := caller.SetReadBuffer(4096); err != nil {
		t.Fatalf("setting the caller's receive buffer: %v", err)
	}
	if err := engine.SetWriteBuffer(4096); err != nil {
		t.Fatalf("setting the engine's send buffer: %v", err)
	}
	return &acceptedConn{TCPConn: engine}, caller
}

// fillConnection writes until an ordinary write waits out its deadline, the caller not reading,
// so that the urgent byte after it finds no room.
func fillConnection(t *testing.T, engine *acceptedConn) {
	t.Helper()
	chunk := bytes.Repeat([]byte{'x'}, 64<<10)
	for range 4096 {
		if err := engine.SetWriteDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			t.Fatalf("setting the write deadline while filling: %v", err)
		}
		_, err := engine.Write(chunk)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return
		}
		if err != nil {
			t.Fatalf("filling: %v", err)
		}
	}
	t.Fatalf("filling: no write ever waited")
}

// readAll reads what the caller is sent until a second passes with nothing, and returns the last
// byte read and the count.
func readAll(caller *net.TCPConn) (last byte, count int, err error) {
	buffer := make([]byte, 64<<10)
	for {
		if err := caller.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return last, count, err
		}
		read, err := caller.Read(buffer)
		if got := buffer[:read]; len(got) > 0 {
			last, count = got[len(got)-1], count+len(got)
		}
		if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, io.EOF) {
			return last, count, nil
		}
		if err != nil {
			return last, count, err
		}
	}
}

// sendResult is WriteUrgent's result, when it was called and when it came.
type sendResult struct {
	count    int
	err      error
	began    time.Time
	returned time.Time
}

// sendReach is how long before the moment that ends or opens it a send on a full connection must
// have begun, to be waiting by then: such a send blocks at once.
const sendReach = 100 * time.Millisecond

// sendBounded calls WriteUrgent with DM alone on its own goroutine and waits for it no later than
// until. Past until, the caller resets, which ends the send, and the row fails.
func sendBounded(t *testing.T, engine *acceptedConn, caller *net.TCPConn, until time.Time) sendResult {
	t.Helper()
	done := make(chan sendResult, 1)
	go func() {
		began := time.Now()
		count, err := engine.WriteUrgent([]byte{TelnetDM})
		done <- sendResult{count: count, err: err, began: began, returned: time.Now()}
	}()
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case result := <-done:
		return result
	case <-timer.C:
		_ = caller.SetLinger(0)
		_ = caller.Close()
		result := <-done
		t.Fatalf("WriteUrgent was still waiting at the row's bound: no deadline or wake reached the urgent send (after the caller's reset it returned %d, %v)", result.count, result.err)
		return sendResult{}
	}
}

// expectWokenAt fails the row unless WriteUrgent gave os.ErrDeadlineExceeded with nothing sent,
// no earlier than from and earlier than from plus the margin.
func expectWokenAt(t *testing.T, result sendResult, from time.Time) {
	t.Helper()
	if !errors.Is(result.err, os.ErrDeadlineExceeded) || result.count != 0 {
		t.Fatalf("WriteUrgent returned %d, %v, want 0 and os.ErrDeadlineExceeded", result.count, result.err)
	}
	t.Logf("WriteUrgent's return came %v into its window of %v", result.returned.Sub(from), sendMargin)
	if result.returned.Before(from) {
		t.Fatalf("WriteUrgent returned %v before its expected time, want within [0, %v)", from.Sub(result.returned), sendMargin)
	}
	if !result.returned.Before(from.Add(sendMargin)) {
		if testrun.Race {
			t.Logf("under the race detector, timing is not judged: WriteUrgent came %v late", result.returned.Sub(from.Add(sendMargin)))
		} else {
			t.Fatalf("WriteUrgent returned %v after its expected time, want within [0, %v)", result.returned.Sub(from), sendMargin)
		}
	}
}

func TestUrgentSend(t *testing.T) {
	t.Parallel()
	t.Run("While a Synch's write on a Line Accept made waits for room, a passed write deadline or the context ending shall wake it, as it wakes every other write, on Linux and on Windows.", func(t *testing.T) {
		t.Parallel()
		for _, row := range []struct {
			name string
			// full fills the connection first, so the urgent byte waits for room.
			full bool
			// sent is whether the byte is to be sent; otherwise the send is to be woken.
			sent bool
			// deadline is the write deadline, from when the row sets it.
			deadline time.Duration
			// arrange starts whatever is to end or open the send besides the deadline, and returns
			// the moment it comes and what to check once the send has returned.
			arrange func(t *testing.T, engine *acceptedConn, caller *net.TCPConn, set time.Time) (time.Time, func(*testing.T))
		}{
			{
				name:     "the urgent byte alone on a full connection, its write deadline 500 ms away: os.ErrDeadlineExceeded at that deadline, nothing sent",
				full:     true,
				deadline: 500 * time.Millisecond,
				arrange: func(_ *testing.T, _ *acceptedConn, _ *net.TCPConn, set time.Time) (time.Time, func(*testing.T)) {
					return set.Add(500 * time.Millisecond), nil
				},
			},
			{
				name:     "the same, its deadline 10 seconds away, a long-passed deadline set from another goroutine at 500 ms: os.ErrDeadlineExceeded then",
				full:     true,
				deadline: testrun.Patient(10 * time.Second),
				arrange: func(t *testing.T, engine *acceptedConn, _ *net.TCPConn, _ time.Time) (time.Time, func(*testing.T)) {
					t.Helper()
					wakeAt := time.Now().Add(500 * time.Millisecond)
					woken := make(chan struct{})
					wake := time.AfterFunc(time.Until(wakeAt), func() {
						defer close(woken)
						_ = engine.SetWriteDeadline(time.Unix(1, 0))
					})
					t.Cleanup(func() {
						if !wake.Stop() {
							<-woken
						}
					})
					return wakeAt, nil
				},
			},
			{
				name:     "the same, its deadline 10 seconds away, the context the wake is registered with cancelled at 500 ms: os.ErrDeadlineExceeded then",
				full:     true,
				deadline: testrun.Patient(10 * time.Second),
				arrange: func(t *testing.T, engine *acceptedConn, _ *net.TCPConn, _ time.Time) (time.Time, func(*testing.T)) {
					t.Helper()
					ctx, cancel := context.WithCancel(t.Context())
					release := wakeOnEnd(ctx, engine)
					t.Cleanup(release)
					cancelAt := time.Now().Add(500 * time.Millisecond)
					stop := time.AfterFunc(time.Until(cancelAt), cancel)
					t.Cleanup(func() { stop.Stop(); cancel() })
					return cancelAt, nil
				},
			},
			{
				name:     "the same, its deadline 10 seconds away, the caller reading from 500 ms: the byte sent with no error once room opens, DM the last byte read",
				full:     true,
				sent:     true,
				deadline: testrun.Patient(10 * time.Second),
				arrange: func(t *testing.T, _ *acceptedConn, caller *net.TCPConn, _ time.Time) (time.Time, func(*testing.T)) {
					t.Helper()
					read := make(chan struct{})
					var last byte
					var readErr error
					readAt := time.Now().Add(500 * time.Millisecond)
					reader := time.AfterFunc(time.Until(readAt), func() {
						defer close(read)
						last, _, readErr = readAll(caller)
					})
					t.Cleanup(func() {
						if !reader.Stop() {
							<-read
						}
					})
					return readAt, func(t *testing.T) {
						t.Helper()
						<-read
						if readErr != nil || last != TelnetDM {
							t.Fatalf("the caller's last byte was %#x (error %v), want DM %#x", last, readErr, TelnetDM)
						}
					}
				},
			},
			{
				name:     "the urgent byte alone on an empty connection, its write deadline already passed: os.ErrDeadlineExceeded at once, nothing sent",
				deadline: -time.Second,
				arrange: func(_ *testing.T, _ *acceptedConn, caller *net.TCPConn, set time.Time) (time.Time, func(*testing.T)) {
					return set, func(t *testing.T) {
						t.Helper()
						if _, count, err := readAll(caller); err != nil || count != 0 {
							t.Fatalf("the caller received %d bytes (error %v), want none", count, err)
						}
					}
				},
			},
		} {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				engine, caller := sendPair(t)
				if row.full {
					fillConnection(t, engine)
				}
				set := time.Now()
				if err := engine.SetWriteDeadline(set.Add(row.deadline)); err != nil {
					t.Fatalf("setting the write deadline: %v", err)
				}
				moment, after := row.arrange(t, engine, caller, set)
				until := moment.Add(testrun.Patient(sendMargin + sendBound))
				if row.sent {
					until = time.Now().Add(testrun.Patient(testrun.HangBound))
				}
				result := sendBounded(t, engine, caller, until)
				// The moment that ends or opens the send was fixed before the send began: a send
				// begun too near it was not yet waiting when it came, and the row did not reach its
				// case.
				if row.full && !result.began.Before(moment.Add(-sendReach)) {
					when := fmt.Sprintf("%v after", result.began.Sub(moment))
					if lead := moment.Sub(result.began); lead > 0 {
						when = fmt.Sprintf("only %v before", lead)
					}
					if testrun.Race {
						t.Logf("under the race detector, timing is not judged: the send began %s the moment meant to find it waiting, where it needs to begin %v before it, so the row judges nothing", when, sendReach)
						return
					}
					t.Fatalf("did not reach its case: the send began %s the moment meant to find it waiting, where it needs to begin %v before it", when, sendReach)
				}
				if row.sent {
					if result.err != nil || result.count != 1 {
						t.Fatalf("WriteUrgent returned %d, %v, want 1 and no error", result.count, result.err)
					}
				} else {
					expectWokenAt(t, result, moment)
				}
				if after != nil {
					after(t)
				}
			})
		}
	})
}
