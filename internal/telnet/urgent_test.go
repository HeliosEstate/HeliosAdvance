// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests of the urgent byte's own send, in package telnet so that the connection is wrapped as
// Accept wraps it and WriteUrgent is called with the urgent byte alone: any wait is then the
// urgent send's, never the ordinary write of the bytes before it. The file name ends in no
// operating system, so the rows run on every runner.
package telnet

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// urgentPair is a loopback pair with urgent data kept in line on both ends: on the caller's end
// too, since Windows resets a caller that does not read its urgent data and lets it pile up.
func urgentPair(t *testing.T) (*acceptedConn, *net.TCPConn) {
	t.Helper()
	listening, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on loopback: %v", err)
	}
	defer func() { _ = listening.Close() }()
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
	if err := keepUrgentInLine(client); err != nil {
		t.Fatalf("keeping urgent data in line on the caller's end: %v", err)
	}
	if err := keepUrgentInLine(server); err != nil {
		t.Fatalf("keeping urgent data in line on the server's end: %v", err)
	}
	// Small buffers, so that a caller that does not read stops the server's writes sooner.
	if err := client.SetReadBuffer(4096); err != nil {
		t.Fatalf("setting the caller's receive buffer: %v", err)
	}
	if err := server.SetWriteBuffer(4096); err != nil {
		t.Fatalf("setting the server's send buffer: %v", err)
	}
	return &acceptedConn{TCPConn: server}, client
}

// fillUntilWaiting writes until a write waits, with the caller not reading, so that the next write
// finds no room.
func fillUntilWaiting(t *testing.T, server *acceptedConn) {
	t.Helper()
	chunk := bytes.Repeat([]byte{'x'}, 64<<10)
	for range 4096 {
		if err := server.SetWriteDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			t.Fatalf("setting the write deadline while filling: %v", err)
		}
		_, err := server.Write(chunk)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return
		}
		if err != nil {
			t.Fatalf("filling: %v", err)
		}
	}
	t.Fatalf("filling: the writes never waited")
}

// drainUntilIdle reads what the caller is sent until a second passes with nothing, and returns the
// last byte read.
func drainUntilIdle(client *net.TCPConn) (last byte, count int, err error) {
	buffer := make([]byte, 64<<10)
	for {
		if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return last, count, err
		}
		read, err := client.Read(buffer)
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

func TestUrgentWaitsForRoom(t *testing.T) {
	t.Parallel()
	const line = "While a Synch's write on a Line Accept made waits for room, a passed write deadline or the context ending shall wake it, as it wakes every other write, on Linux and on Windows."
	passed := time.Unix(1, 0)
	rows := []struct {
		name string
		// filled is whether the connection is full before the urgent byte.
		filled bool
		// deadline is how far from the call the write deadline is; negative for a passed one.
		deadline time.Duration
		// wakeAfter, when set, sets a long-passed deadline from a second goroutine, as wakeOnEnd.
		wakeAfter time.Duration
		// drainAfter, when set, has the caller start reading then.
		drainAfter time.Duration
		wantErr    error
		// within bounds the time the call may take: at least atLeast, less than below.
		atLeast, below time.Duration
	}{
		{
			name:   "the connection filled, the caller not reading, the deadline 500 ms away: ErrDeadlineExceeded at that deadline",
			filled: true, deadline: 500 * time.Millisecond,
			wantErr: os.ErrDeadlineExceeded, atLeast: 400 * time.Millisecond, below: 3 * time.Second,
		},
		{
			name:   "filled, the deadline 10 seconds away, a long-passed deadline set from a second goroutine at 500 ms: ErrDeadlineExceeded then",
			filled: true, deadline: testrun.Patient(10 * time.Second), wakeAfter: 500 * time.Millisecond,
			wantErr: os.ErrDeadlineExceeded, atLeast: 400 * time.Millisecond, below: 3 * time.Second,
		},
		{
			name:   "filled, the deadline 10 seconds away, the caller reading from 500 ms: the byte sent with no error once room opens",
			filled: true, deadline: testrun.Patient(10 * time.Second), drainAfter: 500 * time.Millisecond,
			atLeast: 400 * time.Millisecond, below: 5 * time.Second,
		},
		{
			name:     "an empty connection with the deadline already passed: ErrDeadlineExceeded at once, and nothing sent",
			deadline: -time.Second,
			wantErr:  os.ErrDeadlineExceeded, below: 400 * time.Millisecond,
		},
	}
	for _, row := range rows {
		t.Run(line+"/"+row.name, func(t *testing.T) {
			t.Parallel()
			server, client := urgentPair(t)
			if row.filled {
				fillUntilWaiting(t, server)
			}
			if err := server.SetWriteDeadline(time.Now().Add(row.deadline)); err != nil {
				t.Fatalf("setting the write deadline: %v", err)
			}
			var drained chan struct{}
			var lastRead byte
			var drainErr error
			// A fatal row returns early, and a timer function left running would still write the
			// row's variables and touch its connections after the row ended.
			var drainTimer, wakeTimer *time.Timer
			var woken chan struct{}
			t.Cleanup(func() {
				if drainTimer != nil && !drainTimer.Stop() {
					<-drained
				}
				if wakeTimer != nil && !wakeTimer.Stop() {
					<-woken
				}
			})
			if row.drainAfter > 0 {
				drained = make(chan struct{})
				drainTimer = time.AfterFunc(row.drainAfter, func() {
					defer close(drained)
					lastRead, _, drainErr = drainUntilIdle(client)
				})
			}
			if row.wakeAfter > 0 {
				woken = make(chan struct{})
				wakeTimer = time.AfterFunc(row.wakeAfter, func() {
					defer close(woken)
					_ = server.SetWriteDeadline(passed)
				})
			}
			type urgentResult struct {
				count int
				err   error
			}
			// A send no deadline wakes never returns; the row's own bound fails it by name instead
			// of leaving the test binary to its timeout.
			finished := make(chan urgentResult, 1)
			started := time.Now()
			go func() {
				sent, sendErr := server.WriteUrgent([]byte{TelnetDM})
				finished <- urgentResult{sent, sendErr}
			}()
			var result urgentResult
			select {
			case result = <-finished:
			case <-time.After(testrun.Patient(row.below + 2*time.Second)):
				// A send that never returns holds the connection's write lock, so closing the
				// server's end would block behind it; resetting the caller's end completes the
				// send with an error.
				_ = client.SetLinger(0)
				_ = client.Close()
				select {
				case <-finished:
				case <-time.After(testrun.Patient(5 * time.Second)):
					t.Fatalf("WriteUrgent was still waiting after %v and resetting the caller's end did not wake it", time.Since(started))
				}
				t.Fatalf("WriteUrgent was still waiting after %v, want it back in less than %v", time.Since(started), row.below)
			}
			count, err := result.count, result.err
			took := time.Since(started)
			if !errors.Is(err, row.wantErr) {
				t.Fatalf("WriteUrgent returned (%d, %v), want error %v", count, err, row.wantErr)
			}
			t.Logf("WriteUrgent's return came %v into its window of %v", took-row.atLeast, row.below-row.atLeast)
			if took < row.atLeast {
				t.Fatalf("WriteUrgent took %v, want at least %v and less than %v", took, row.atLeast, row.below)
			}
			if took >= row.below {
				if testrun.Race {
					t.Logf("under the race detector, timing is not judged: WriteUrgent took %v, %v past its bound", took, took-row.below)
				} else {
					t.Fatalf("WriteUrgent took %v, want at least %v and less than %v", took, row.atLeast, row.below)
				}
			}
			switch {
			case row.wantErr == nil && count != 1:
				t.Fatalf("WriteUrgent returned count %d, want 1", count)
			case row.wantErr != nil && count != 0:
				t.Fatalf("WriteUrgent returned count %d with an error, want 0", count)
			}
			if drained != nil {
				<-drained
				if drainErr != nil {
					t.Fatalf("the caller's read: %v", drainErr)
				}
				if lastRead != TelnetDM {
					t.Fatalf("the last byte the caller read is %#x, want DM %#x", lastRead, TelnetDM)
				}
				return
			}
			if !row.filled {
				if _, got, drainErr := drainUntilIdle(client); drainErr != nil || got != 0 {
					t.Fatalf("the caller received %d bytes (error %v), want none", got, drainErr)
				}
			}
		})
	}
}
