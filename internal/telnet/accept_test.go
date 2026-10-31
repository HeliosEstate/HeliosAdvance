// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Accept, Telnet's way in for the shared execution path, and the Line's own close, called through
// their exported names on loopback connections, with QA's scripted caller on the other end.
package telnet_test

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/telnet"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// closingWaitLimit is the contract's closing wait, as its line states it.
const closingWaitLimit = 3 * time.Second

// accepted is what one Accept call returned, and when.
type accepted struct {
	line     *telnet.Line
	err      error
	returned time.Time
}

// acceptOn calls Accept on its own goroutine, as the shared execution path does.
func acceptOn(ctx context.Context, connection *net.TCPConn) <-chan accepted {
	done := make(chan accepted, 1)
	go func() {
		line, err := telnet.Accept(ctx, connection)
		done <- accepted{line: line, err: err, returned: time.Now()}
	}()
	return done
}

func waitAccepted(t *testing.T, done <-chan accepted, limit time.Duration) accepted {
	t.Helper()
	select {
	case got := <-done:
		return got
	case <-time.After(limit):
		t.Fatalf("Accept had not returned after %v", limit)
		return accepted{}
	}
}

// acceptedLine is a Line Accept made for a caller that answered the eight, the opening read.
func acceptedLine(t *testing.T) (connected, *telnet.Line) {
	t.Helper()
	pair := connect(t)
	done := acceptOn(t.Context(), pair.server.TCPConn)
	expectOpening(t, pair.client, time.Now().Add(testrun.Patient(margin)))
	write(t, pair.client, answers)
	got := waitAccepted(t, done, testrun.Patient(margin))
	if got.err != nil || got.line == nil {
		t.Fatalf("Accept gave %v and %v, want a Line", got.line, got.err)
	}
	return pair, got.line
}

type closed struct {
	err      error
	returned time.Time
}

func closeOn(ctx context.Context, line *telnet.Line) <-chan closed {
	done := make(chan closed, 1)
	go func() {
		err := line.Close(ctx)
		done <- closed{err: err, returned: time.Now()}
	}()
	return done
}

func waitClosed(t *testing.T, done <-chan closed, limit time.Duration) closed {
	t.Helper()
	select {
	case got := <-done:
		return got
	case <-time.After(limit):
		t.Fatalf("Close had not returned after %v", limit)
		return closed{}
	}
}

// expectEndOfStream is the caller's read ending in order, at once.
func expectEndOfStream(t *testing.T, client net.Conn) {
	t.Helper()
	received, err := readToEnd(client, time.Now().Add(testrun.Patient(margin)))
	if !errors.Is(err, io.EOF) || len(received) != 0 {
		t.Fatalf("the caller read % x and %v, want end of stream at once", received, err)
	}
}

// expectNotShutDown is the caller's read still waiting: no end of stream, nothing sent.
func expectNotShutDown(t *testing.T, client net.Conn) {
	t.Helper()
	_ = client.SetReadDeadline(time.Now().Add(quiet))
	buffer := make([]byte, 16)
	got, err := client.Read(buffer)
	if got > 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the caller read % x and %v, want nothing and no end", buffer[:got], err)
	}
}

func TestAccept(t *testing.T) {
	t.Parallel()

	t.Run("If SO_OOBINLINE cannot be set, then Accept shall return ErrConnectionFailed and a nil Line without writing to the connection.", func(t *testing.T) {
		t.Parallel()
		t.Run("a connection already closed: ErrConnectionFailed and no Line, where an open one gives a Line", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			_ = pair.server.Close()
			got := waitAccepted(t, acceptOn(t.Context(), pair.server.TCPConn), testrun.Patient(margin))
			if got.line != nil || !errors.Is(got.err, telnet.ErrConnectionFailed) {
				t.Fatalf("Accept gave %v and %v, want no Line and ErrConnectionFailed", got.line, got.err)
			}
			received, err := readToEnd(pair.client, time.Now().Add(testrun.Patient(margin)))
			t.Logf("the caller's read ended with %v", err)
			if len(received) != 0 {
				t.Fatalf("the caller received % x", received)
			}
			acceptedLine(t)
		})
	})

	t.Run("Once SO_OOBINLINE is set, Accept shall negotiate and return a Line as Open does, whichever Outcome negotiation ends with, or a nil Line and Open's error.", func(t *testing.T) {
		t.Parallel()
		t.Run("a caller that answers the eight: the opening, then a Line at once", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			done := acceptOn(t.Context(), pair.server.TCPConn)
			expectOpening(t, pair.client, time.Now().Add(testrun.Patient(margin)))
			sent := write(t, pair.client, answers)
			got := waitAccepted(t, done, testrun.Patient(margin))
			if got.err != nil || got.line == nil {
				t.Fatalf("Accept gave %v and %v, want a Line", got.line, got.err)
			}
			expectWithin(t, "Accept's return", got.returned, sent.began, sent.done.Add(margin))
		})
		t.Run("a silent caller: a Line 3 seconds after the opening", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			done := acceptOn(t.Context(), pair.server.TCPConn)
			expectOpening(t, pair.client, time.Now().Add(testrun.Patient(margin)))
			got := waitAccepted(t, done, negotiationLimit+testrun.Patient(2*margin))
			if got.err != nil || got.line == nil {
				t.Fatalf("Accept gave %v and %v, want a Line", got.line, got.err)
			}
			expectWithin(t, "Accept's return", got.returned, pair.dialed.Add(negotiationLimit), pair.dialed.Add(negotiationLimit+margin))
		})
		t.Run("a caller that closes during negotiation: no Line, ErrCallerClosed", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			done := acceptOn(t.Context(), pair.server.TCPConn)
			expectOpening(t, pair.client, time.Now().Add(testrun.Patient(margin)))
			_ = pair.client.CloseWrite()
			got := waitAccepted(t, done, testrun.Patient(margin))
			if got.line != nil || !errors.Is(got.err, telnet.ErrCallerClosed) || !errors.Is(got.err, io.EOF) {
				t.Fatalf("Accept gave %v and %v, want no Line and ErrCallerClosed matching io.EOF", got.line, got.err)
			}
		})
		t.Run("cancelled during negotiation: no Line, ErrDeadlineEnded", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			ctx, cancel := context.WithCancel(t.Context())
			done := acceptOn(ctx, pair.server.TCPConn)
			expectOpening(t, pair.client, time.Now().Add(testrun.Patient(margin)))
			cancel()
			got := waitAccepted(t, done, testrun.Patient(margin))
			if got.line != nil || !errors.Is(got.err, telnet.ErrDeadlineEnded) || !errors.Is(got.err, context.Canceled) {
				t.Fatalf("Accept gave %v and %v, want no Line and ErrDeadlineEnded", got.line, got.err)
			}
		})
	})
}

func TestAcceptUrgent(t *testing.T) {
	t.Parallel()

	t.Run("Accept shall keep the caller's urgent data in line, so that a Synch, IAC with DM sent as urgent data, reaches negotiation whole and, after negotiation, the caller's next character after it is read as data, and none of the data before it is discarded.", func(t *testing.T) {
		t.Parallel()
		t.Run("a Synch between the seventh and the eighth answer: Answered at the eighth, not at 3 seconds", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			done := acceptOn(t.Context(), pair.server.TCPConn)
			expectOpening(t, pair.client, time.Now().Add(testrun.Patient(margin)))
			write(t, pair.client, answers[:21])
			writeUrgent(t, pair.client, command(dataMark))
			sent := write(t, pair.client, answers[21:])
			got := waitAccepted(t, done, negotiationLimit+testrun.Patient(2*margin))
			if got.err != nil || got.line == nil {
				t.Fatalf("Accept gave %v and %v, want a Line", got.line, got.err)
			}
			expectWithin(t, "Accept's return", got.returned, sent.began, sent.done.Add(margin))
		})
		t.Run("ab, a Synch, cd after negotiation: a, b, c, d", func(t *testing.T) {
			t.Parallel()
			pair, line := acceptedLine(t)
			write(t, pair.client, []byte("ab"))
			writeUrgent(t, pair.client, command(dataMark))
			write(t, pair.client, []byte("cd"))
			expectData(t, line, []byte("abcd"))
		})
		t.Run("ab and IAC, then DM alone as urgent data, then cd: a, b, c, d", func(t *testing.T) {
			t.Parallel()
			pair, line := acceptedLine(t)
			write(t, pair.client, []byte{'a', 'b', iac})
			writeUrgent(t, pair.client, []byte{dataMark})
			write(t, pair.client, []byte("cd"))
			expectData(t, line, []byte("abcd"))
		})
	})

	t.Run("When the engine sends a Synch on a Line Accept made, the caller shall receive IAC DM with DM as TCP urgent data.", func(t *testing.T) {
		t.Parallel()
		t.Run("AO during negotiation: IAC, then DM as urgent data", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			done := acceptOn(t.Context(), pair.server.TCPConn)
			expectOpening(t, pair.client, time.Now().Add(testrun.Patient(margin)))
			write(t, pair.client, command(abortOutput))
			expectSynchs(t, pair.client, nil, 1, time.Now().Add(testrun.Patient(margin)))
			write(t, pair.client, answers)
			if got := waitAccepted(t, done, testrun.Patient(margin)); got.err != nil || got.line == nil {
				t.Fatalf("Accept gave %v and %v, want a Line", got.line, got.err)
			}
		})
		t.Run("x, IP, y after negotiation: x, then the Synch, then y", func(t *testing.T) {
			t.Parallel()
			pair, line := acceptedLine(t)
			write(t, pair.client, join([]byte("x"), command(interruptProcess), []byte("y")))
			expectData(t, line, []byte("xy"))
			expectSynchs(t, pair.client, nil, 1, time.Now().Add(testrun.Patient(margin)))
			expectQuiet(t, pair.client)
		})
	})

	t.Run("While a Synch's write on a Line Accept made waits for room, a passed write deadline or the context ending shall wake it, as it wakes every other write, on Linux and on Windows.", func(t *testing.T) {
		t.Parallel()
		// Each caller keeps its urgent data in line and never reads, so the Synch's write is the
		// one that waits: the Line's own buffer is empty, and the test filled the connection past
		// it.
		stalled := func(t *testing.T) (connected, *telnet.Line) {
			t.Helper()
			pair, line := acceptedLine(t)
			keepUrgentInLine(t, pair.client)
			fill(t, pair.server.TCPConn)
			write(t, pair.client, join(command(abortOutput), []byte("k")))
			return pair, line
		}
		// recvBounded calls RecvChar on its own goroutine and waits for it no later than until:
		// a Synch's write that no deadline wakes would otherwise hold the row, and every row after
		// it, until the package's own timeout. Past until, the caller resets, which ends any
		// send, and the row fails.
		recvBounded := func(t *testing.T, pair connected, recv func() error, until time.Time) (time.Time, error) {
			t.Helper()
			done := make(chan error, 1)
			go func() { done <- recv() }()
			timer := time.NewTimer(time.Until(until))
			defer timer.Stop()
			select {
			case err := <-done:
				return time.Now(), err
			case <-timer.C:
				reset(t, pair.client)
				err := <-done
				t.Fatalf("RecvChar was still waiting at the row's bound: the Synch's write was not woken (after the caller's reset it returned %v)", err)
				return time.Time{}, nil
			}
		}
		t.Run("RecvChar's deadline at 500 ms: os.ErrDeadlineExceeded then, and the Line writes nothing more", func(t *testing.T) {
			t.Parallel()
			pair, line := stalled(t)
			deadline := time.Now().Add(500 * time.Millisecond)
			returned, err := recvBounded(t, pair, func() error { _, err := line.RecvChar(t.Context(), deadline); return err }, time.Now().Add(testrun.Patient(testrun.HangBound)))
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("RecvChar returned %v, want os.ErrDeadlineExceeded", err)
			}
			expectWithin(t, "RecvChar's return", returned, deadline, deadline.Add(margin))
			for name, call := range map[string]func() error{
				"SendChar": func() error { return line.SendChar(t.Context(), 'x') },
				"Flush":    func() error { return line.Flush(t.Context()) },
				"RecvChar": func() error {
					_, err := line.RecvChar(t.Context(), time.Now().Add(testrun.Patient(margin)))
					return err
				},
			} {
				if err := call(); !errors.Is(err, telnet.ErrConnectionFailed) {
					t.Fatalf("%s after the Synch's write failed returned %v, want ErrConnectionFailed", name, err)
				}
			}
		})
		t.Run("the context cancelled at 500 ms: context.Canceled at once", func(t *testing.T) {
			t.Parallel()
			pair, line := stalled(t)
			ctx, cancel := context.WithCancel(t.Context())
			cancelAt := time.Now().Add(500 * time.Millisecond)
			time.AfterFunc(time.Until(cancelAt), cancel)
			returned, err := recvBounded(t, pair, func() error {
				_, err := line.RecvChar(ctx, time.Now().Add(testrun.Patient(10*time.Second)))
				return err
			}, time.Now().Add(testrun.Patient(testrun.HangBound)))
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("RecvChar returned %v, want context.Canceled", err)
			}
			expectWithin(t, "RecvChar's return", returned, cancelAt, cancelAt.Add(margin))
		})
		t.Run("the context's deadline at 500 ms, reported only later: context.DeadlineExceeded at it", func(t *testing.T) {
			t.Parallel()
			pair, line := stalled(t)
			deadline := time.Now().Add(500 * time.Millisecond)
			returned, err := recvBounded(t, pair, func() error {
				_, err := line.RecvChar(endsLate(t, deadline), deadline.Add(testrun.Patient(5*time.Second)))
				return err
			}, time.Now().Add(testrun.Patient(testrun.HangBound)))
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("RecvChar returned %v, want context.DeadlineExceeded", err)
			}
			expectWithin(t, "RecvChar's return", returned, deadline, deadline.Add(margin))
		})
		t.Run("during negotiation, the context's deadline once its write waits: Accept returns ErrDeadlineEnded then", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			keepUrgentInLine(t, pair.client)
			deadline := testrun.CaseDeadline()
			done := acceptOn(withDeadline(t, deadline), pair.server.TCPConn)
			expectOpening(t, pair.client, time.Now().Add(testrun.Patient(margin)))
			fill(t, pair.server.TCPConn)
			write(t, pair.client, join(command(abortOutput), lateAnswers))
			testrun.ExpectCaseReached(t, deadline, margin)
			got := waitAccepted(t, done, time.Until(deadline)+testrun.Patient(2*margin))
			if got.line != nil || !errors.Is(got.err, telnet.ErrDeadlineEnded) || !errors.Is(got.err, context.DeadlineExceeded) {
				t.Fatalf("Accept gave %v and %v, want no Line and ErrDeadlineEnded", got.line, got.err)
			}
			expectWithin(t, "Accept's return", got.returned, deadline, deadline.Add(margin))
		})
	})
}

func TestLineClose(t *testing.T) {
	t.Parallel()

	t.Run("Close shall shut down the sending side of the Line's connection, then read and discard until the caller closes or ClosingWaitSeconds pass, no later than the context's deadline.", func(t *testing.T) {
		t.Parallel()
		t.Run("the caller sees end of stream at once, and Close returns when it closes", func(t *testing.T) {
			t.Parallel()
			pair, line := acceptedLine(t)
			done := closeOn(t.Context(), line)
			expectEndOfStream(t, pair.client)
			callerClosed := time.Now()
			_ = pair.client.Close()
			got := waitClosed(t, done, testrun.Patient(margin+time.Second))
			if got.err != nil {
				t.Fatalf("Close gave %v, want no error", got.err)
			}
			expectWithin(t, "Close's return", got.returned, callerClosed, callerClosed.Add(margin))
		})
		t.Run("a caller that stays and sends 1 KiB every 200 ms: its bytes taken, no reset, Close returns at 3 seconds", func(t *testing.T) {
			t.Parallel()
			pair, line := acceptedLine(t)
			called := time.Now()
			done := closeOn(t.Context(), line)
			expectEndOfStream(t, pair.client)
			chunk := make([]byte, 1024)
			for time.Now().Before(called.Add(closingWaitLimit - 400*time.Millisecond)) {
				write(t, pair.client, chunk)
				wait(t.Context(), time.Now().Add(200*time.Millisecond))
			}
			got := waitClosed(t, done, closingWaitLimit+testrun.Patient(2*margin))
			if got.err != nil {
				t.Fatalf("Close gave %v, want no error", got.err)
			}
			expectWithin(t, "Close's return", got.returned, called.Add(closingWaitLimit), called.Add(closingWaitLimit+margin))
		})
		t.Run("a context deadline 1 second away: Close returns at it", func(t *testing.T) {
			t.Parallel()
			_, line := acceptedLine(t)
			deadline := time.Now().Add(time.Second)
			ctx, cancel := context.WithDeadline(t.Context(), deadline)
			t.Cleanup(cancel)
			got := waitClosed(t, closeOn(ctx, line), time.Second+testrun.Patient(2*margin))
			if !errors.Is(got.err, context.DeadlineExceeded) {
				t.Fatalf("Close gave %v, want context.DeadlineExceeded", got.err)
			}
			expectWithin(t, "Close's return", got.returned, deadline, deadline.Add(margin))
		})
	})

	t.Run("Close shall write nothing to the connection.", func(t *testing.T) {
		t.Parallel()
		t.Run("a byte queued with SendChar before Close: never sent, the stream ends empty", func(t *testing.T) {
			t.Parallel()
			pair, line := acceptedLine(t)
			sendAll(t, line, []byte("x"))
			closeOn(t.Context(), line)
			expectEndOfStream(t, pair.client)
		})
	})

	t.Run("When the caller closes, or ClosingWaitSeconds pass, Close shall return no error.", func(t *testing.T) {
		t.Parallel()
		t.Run("a silent caller: no error, 3 seconds after the call", func(t *testing.T) {
			t.Parallel()
			_, line := acceptedLine(t)
			called := time.Now()
			got := waitClosed(t, closeOn(t.Context(), line), closingWaitLimit+testrun.Patient(2*margin))
			if got.err != nil {
				t.Fatalf("Close gave %v, want no error", got.err)
			}
			expectWithin(t, "Close's return", got.returned, called.Add(closingWaitLimit), called.Add(closingWaitLimit+margin))
		})
		t.Run("a caller that resets during the wait: no error, at once", func(t *testing.T) {
			t.Parallel()
			pair, line := acceptedLine(t)
			done := closeOn(t.Context(), line)
			expectEndOfStream(t, pair.client)
			resetAt := time.Now()
			reset(t, pair.client)
			got := waitClosed(t, done, testrun.Patient(margin+time.Second))
			if got.err != nil {
				t.Fatalf("Close gave %v, want no error", got.err)
			}
			expectWithin(t, "Close's return", got.returned, resetAt, resetAt.Add(margin))
		})
	})

	t.Run("If the context has ended when Close is called, then Close shall return the context's error, wrapped, without touching the connection.", func(t *testing.T) {
		t.Parallel()
		t.Run("a cancelled context: context.Canceled, no end of stream, and the Line still carries z", func(t *testing.T) {
			t.Parallel()
			pair, line := acceptedLine(t)
			if err := line.Close(cancelled(t)); !errors.Is(err, context.Canceled) {
				t.Fatalf("Close gave %v, want context.Canceled", err)
			}
			expectNotShutDown(t, pair.client)
			sendAll(t, line, []byte("z"))
			flush(t, line)
			expectReceived(t, pair.client, []byte("z"))
		})
	})

	t.Run("If the context ends while Close waits, then Close shall return the context's error, wrapped.", func(t *testing.T) {
		t.Parallel()
		t.Run("cancelled during the wait: context.Canceled at once", func(t *testing.T) {
			t.Parallel()
			pair, line := acceptedLine(t)
			ctx, cancel := context.WithCancel(t.Context())
			done := closeOn(ctx, line)
			expectEndOfStream(t, pair.client)
			cancelledAt := time.Now()
			cancel()
			got := waitClosed(t, done, testrun.Patient(margin+time.Second))
			if !errors.Is(got.err, context.Canceled) {
				t.Fatalf("Close gave %v, want context.Canceled", got.err)
			}
			expectWithin(t, "Close's return", got.returned, cancelledAt, cancelledAt.Add(margin))
		})
	})

	t.Run("If shutting down the sending side or setting the read deadline fails, then Close shall return ErrConnectionFailed at once.", func(t *testing.T) {
		t.Parallel()
		t.Run("the connection closed under the Line: ErrConnectionFailed at once", func(t *testing.T) {
			t.Parallel()
			pair, line := acceptedLine(t)
			_ = pair.server.Close()
			called := time.Now()
			got := waitClosed(t, closeOn(t.Context(), line), testrun.Patient(margin+time.Second))
			if !errors.Is(got.err, telnet.ErrConnectionFailed) {
				t.Fatalf("Close gave %v, want ErrConnectionFailed", got.err)
			}
			expectWithin(t, "Close's return", got.returned, called, called.Add(margin))
		})
	})

	t.Run("If the Line was not made by Accept, or is nil, then Close shall return ErrConnectionFailed without touching the connection.", func(t *testing.T) {
		t.Parallel()
		t.Run("a Line Open made: ErrConnectionFailed, no end of stream, where Accept's shuts down", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			if err := line.Close(t.Context()); !errors.Is(err, telnet.ErrConnectionFailed) {
				t.Fatalf("Close on a Line Open made gave %v", err)
			}
			expectNotShutDown(t, pair.client)
			acceptedPair, acceptedLine := acceptedLine(t)
			closeOn(t.Context(), acceptedLine)
			expectEndOfStream(t, acceptedPair.client)
		})
		t.Run("nil and a zero Line: ErrConnectionFailed, where Accept's shuts down", func(t *testing.T) {
			t.Parallel()
			var none *telnet.Line
			if err := none.Close(t.Context()); !errors.Is(err, telnet.ErrConnectionFailed) {
				t.Fatalf("Close on nil gave %v", err)
			}
			if err := (&telnet.Line{}).Close(t.Context()); !errors.Is(err, telnet.ErrConnectionFailed) {
				t.Fatalf("Close on a zero Line gave %v", err)
			}
			pair, line := acceptedLine(t)
			closeOn(t.Context(), line)
			expectEndOfStream(t, pair.client)
		})
	})
}
