// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests of Negotiate over real loopback sockets, driven by the scripted caller: the opening
// requests, the replies and when they are written, how negotiation ends, each kind of failure,
// the context's deadline and cancellation, and the deadlines the connection is left with.
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
)

// early is how far before its deadline a runner's clock may wake a wait: a deadline is never
// met sooner than this.
const early = 20 * time.Millisecond

// negotiated is what one Negotiate call returned, and when.
type negotiated struct {
	outcome  telnet.Outcome
	err      error
	returned time.Time
}

// negotiating is a Negotiate call running on the server end.
type negotiating struct {
	// called is a moment before Negotiate was called, so before its opening write began.
	called time.Time
	done   <-chan negotiated
}

// negotiate calls Negotiate on its own goroutine, as the Listener does, and returns at once.
func negotiate(ctx context.Context, connection telnet.Conn) negotiating {
	done := make(chan negotiated, 1)
	called := time.Now()
	go func() {
		outcome, err := telnet.Negotiate(ctx, connection)
		done <- negotiated{outcome: outcome, err: err, returned: time.Now()}
	}()
	return negotiating{called: called, done: done}
}

// result waits for Negotiate to return, failing the test if it has not by the deadline.
func (call negotiating) result(t *testing.T, deadline time.Time) negotiated {
	t.Helper()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case got := <-call.done:
		return got
	case <-timer.C:
		t.Fatalf("Negotiate had not returned %v after it was called", time.Since(call.called))
		return negotiated{}
	}
}

// expectReturn checks what Negotiate returned and that it came within its window.
func expectReturn(t *testing.T, got negotiated, outcome telnet.Outcome, errs []error, notBefore, notAfter time.Time) {
	t.Helper()
	if len(errs) == 0 {
		if got.err != nil || got.outcome != outcome {
			t.Fatalf("Negotiate returned (%v, %v), want (%v, no error)", got.outcome, got.err, outcome)
		}
	}
	for _, want := range errs {
		if !errors.Is(got.err, want) {
			t.Fatalf("Negotiate returned %v, which is not %v", got.err, want)
		}
	}
	expectWithin(t, "Negotiate's return", got.returned, notBefore, notAfter)
}

// expectWithin checks a moment falls in its window, and logs how late past the window's start
// it came, so the runners' margins show in the test log.
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

// expectNothingWritten checks the client receives no byte, once the test has closed the server
// end.
func expectNothingWritten(t *testing.T, pair connected) {
	t.Helper()
	_ = pair.server.Close()
	expectStream(t, pair.client, nil, time.Now().Add(margin))
}

// withDeadline is a context ending at the deadline, cancelled when the test ends.
func withDeadline(t *testing.T, deadline time.Time) context.Context {
	t.Helper()
	ctx, cancel := context.WithDeadline(t.Context(), deadline)
	t.Cleanup(cancel)
	return ctx
}

// endsLate is a context whose deadline passes well before it reports its end, as any context may:
// it ends after the window a row allows for Negotiate's return, so only the clock can tell in time
// that the deadline passed. A context's own timer and the connection's deadline, set to the same
// moment, wake in either order, so without this a row tells the clock's part only by chance.
func endsLate(t *testing.T, deadline time.Time) context.Context {
	t.Helper()
	ctx, cancel := context.WithDeadline(t.Context(), deadline.Add(2*margin))
	t.Cleanup(cancel)
	return lateEnd{Context: ctx, deadline: deadline}
}

type lateEnd struct {
	context.Context
	deadline time.Time
}

func (ctx lateEnd) Deadline() (time.Time, bool) {
	return ctx.deadline, true
}

// endsOnFailure is the real server end, with the context cancelled at the moment a read or a
// reply's write fails, so the failure and the end of the context meet. A reply is any write
// after a read has returned bytes; the opening comes before any read.
type endsOnFailure struct {
	*net.TCPConn
	cancel          context.CancelFunc
	failReply       bool
	hasRead         bool
	cancelReadOnEOF bool
}

func (connection *endsOnFailure) Read(buffer []byte) (int, error) {
	got, err := connection.TCPConn.Read(buffer)
	if got > 0 {
		connection.hasRead = true
	}
	if err != nil && connection.cancelReadOnEOF {
		connection.cancel()
	}
	return got, err
}

func (connection *endsOnFailure) Write(buffer []byte) (int, error) {
	if connection.failReply && connection.hasRead {
		connection.cancel()
		_ = connection.Close()
	}
	return connection.TCPConn.Write(buffer)
}

// sweep is every option request but the answers, then the answers: WILL and WONT for every
// option, ECHO and SGA included, and DO and DONT for every other option.
func sweep() []byte {
	var requests []byte
	for _, verb := range []byte{will, wont, doVerb, dont} {
		for code := range 256 {
			option := byte(code)
			if (verb == doVerb || verb == dont) && (option == echo || option == sga) {
				continue
			}
			requests = append(requests, request(verb, option)...)
		}
	}
	return join(requests, answers)
}

// expectDeadlineAt checks a read on the server end, the client silent, waits until the deadline.
func expectReadDeadlineAt(t *testing.T, server *net.TCPConn, deadline time.Time) {
	t.Helper()
	watchdog := time.AfterFunc(time.Until(deadline.Add(margin)), func() { _ = server.Close() })
	defer watchdog.Stop()
	got, err := server.Read(make([]byte, 16))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a read after Negotiate returned gave %d bytes and %v, want a passed deadline", got, err)
	}
	expectWithin(t, "the read's deadline", time.Now(), deadline, deadline.Add(margin))
}

// expectWriteDeadlineAt checks a write on the server end, the client not reading, waits until the
// deadline.
func expectWriteDeadlineAt(t *testing.T, server *net.TCPConn, deadline time.Time) {
	t.Helper()
	watchdog := time.AfterFunc(time.Until(deadline.Add(margin)), func() { _ = server.Close() })
	defer watchdog.Stop()
	// Windows takes a large write whole into its own buffers, so the write is repeated until one
	// has to wait.
	chunk := make([]byte, 1<<20)
	var err error
	for written := 0; err == nil && written < 1<<30; written += len(chunk) {
		_, err = server.Write(chunk)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a write after Negotiate returned gave %v, want a passed deadline", err)
	}
	expectWithin(t, "the write's deadline", time.Now(), deadline, deadline.Add(margin))
}

func TestNegotiate(t *testing.T) {
	t.Parallel()
	t.Run("If the context has ended when Negotiate is called, then Negotiate shall return ErrDeadlineEnded without writing to the connection.", func(t *testing.T) {
		t.Parallel()
		t.Run("a cancelled context", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			call := negotiate(ctx, pair.server)
			got := call.result(t, call.called.Add(margin))
			expectReturn(t, got, 0, []error{telnet.ErrDeadlineEnded, context.Canceled}, call.called, call.called.Add(margin))
			expectNothingWritten(t, pair)
		})
		t.Run("a deadline already passed", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			ctx := withDeadline(t, time.Now().Add(-time.Second))
			call := negotiate(ctx, pair.server)
			got := call.result(t, call.called.Add(margin))
			expectReturn(t, got, 0, []error{telnet.ErrDeadlineEnded, context.DeadlineExceeded}, call.called, call.called.Add(margin))
			expectNothingWritten(t, pair)
		})
	})
	t.Run("When it is called, Negotiate shall write the opening requests New returns before it reads from the connection.", func(t *testing.T) {
		t.Parallel()
		t.Run("a silent caller gets the opening at once", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(10*time.Second)), pair.server)
			got := readExactly(t, pair.client, len(opening), call.called.Add(margin))
			if string(got) != string(opening) {
				t.Fatalf("the first bytes were % x, want % x", got, opening)
			}
		})
		t.Run("a caller that answers before it reads still gets the opening first", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			write(t, pair.client, answers)
			call := negotiate(withDeadline(t, time.Now().Add(10*time.Second)), pair.server)
			got := call.result(t, call.called.Add(margin))
			expectReturn(t, got, telnet.Answered, nil, call.called, call.called.Add(margin))
			_ = pair.server.CloseWrite()
			expectStream(t, pair.client, opening, time.Now().Add(margin))
		})
	})
	t.Run("When Receive appends replies and returns false, Negotiate shall write those replies before its next read.", func(t *testing.T) {
		t.Parallel()
		t.Run("a caller that waits for each reply before it sends more", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(10*time.Second)), pair.server)
			readExactly(t, pair.client, len(opening), call.called.Add(margin))
			oracle := &reading{}
			for _, ask := range [][]byte{request(doVerb, telnetTypeOption), request(will, windowSizeOption), request(dont, echo), request(doVerb, echo)} {
				sent := write(t, pair.client, ask)
				want, _ := oracle.readAll(ask)
				got := readExactly(t, pair.client, len(want), sent.Add(margin))
				if string(got) != string(want) {
					t.Fatalf("the reply to % x was % x, want % x", ask, got, want)
				}
			}
			sent := write(t, pair.client, request(doVerb, sga))
			expectReturn(t, call.result(t, sent.Add(margin)), telnet.Answered, nil, sent, sent.Add(margin))
		})
	})
	t.Run("When Receive returns true, Negotiate shall write that call's replies and, if neither that read nor that write returned an error, return Answered with no error.", func(t *testing.T) {
		t.Parallel()
		t.Run("a refusal and both answers in one write, then requests after the end", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(10*time.Second)), pair.server)
			readExactly(t, pair.client, len(opening), call.called.Add(margin))
			sent := write(t, pair.client, join(request(doVerb, telnetTypeOption), answers, request(doVerb, 25), request(will, windowSizeOption)))
			expectReturn(t, call.result(t, sent.Add(margin)), telnet.Answered, nil, sent, sent.Add(margin))
			_ = pair.server.CloseWrite()
			expectStream(t, pair.client, request(wont, telnetTypeOption), time.Now().Add(margin))
		})
		t.Run("DONT for both", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(10*time.Second)), pair.server)
			readExactly(t, pair.client, len(opening), call.called.Add(margin))
			sent := write(t, pair.client, join(request(dont, echo), request(dont, sga)))
			expectReturn(t, call.result(t, sent.Add(margin)), telnet.Answered, nil, sent, sent.Add(margin))
		})
	})
	t.Run("If NegotiationSeconds pass after Negotiate begins the opening write, before the context's deadline, while a read or a write is waiting, then Negotiate shall return TimedOut with no error.", func(t *testing.T) {
		t.Parallel()
		t.Run("a silent caller, a read waiting", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(10*time.Second)), pair.server)
			limit := call.called.Add(negotiationLimit)
			expectReturn(t, call.result(t, limit.Add(margin)), telnet.TimedOut, nil, limit, limit.Add(margin))
		})
		t.Run("a context with no deadline", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(t.Context(), pair.server)
			limit := call.called.Add(negotiationLimit)
			expectReturn(t, call.result(t, limit.Add(margin)), telnet.TimedOut, nil, limit, limit.Add(margin))
		})
		t.Run("a caller that floods and never reads, a write waiting", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(10*time.Second)), pair.server)
			flood(t, pair.client)
			limit := call.called.Add(negotiationLimit)
			expectReturn(t, call.result(t, limit.Add(margin)), telnet.TimedOut, nil, limit, limit.Add(margin))
		})
		t.Run("a caller that sends a data byte every 200 ms does not restart the 3 seconds", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(10*time.Second)), pair.server)
			limit := call.called.Add(negotiationLimit)
			for next := time.Now(); next.Before(limit.Add(-300 * time.Millisecond)); next = next.Add(200 * time.Millisecond) {
				wait(t.Context(), next)
				write(t, pair.client, []byte("x"))
			}
			expectReturn(t, call.result(t, limit.Add(margin)), telnet.TimedOut, nil, limit, limit.Add(margin))
		})
		t.Run("one answer only", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(10*time.Second)), pair.server)
			write(t, pair.client, request(doVerb, echo))
			limit := call.called.Add(negotiationLimit)
			expectReturn(t, call.result(t, limit.Add(margin)), telnet.TimedOut, nil, limit, limit.Add(margin))
		})
		t.Run("just outside: a deadline 3.5 seconds after the call", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			before := time.Now()
			call := negotiate(withDeadline(t, before.Add(3500*time.Millisecond)), pair.server)
			limit := call.called.Add(negotiationLimit)
			expectReturn(t, call.result(t, limit.Add(margin)), telnet.TimedOut, nil, limit, before.Add(3500*time.Millisecond))
		})
	})
	t.Run("If the context's deadline passes at or before NegotiationSeconds after the opening write began, while a read or a write is waiting, then Negotiate shall return ErrDeadlineEnded.", func(t *testing.T) {
		t.Parallel()
		t.Run("a deadline at 1 second, a read waiting", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := time.Now().Add(time.Second)
			call := negotiate(withDeadline(t, deadline), pair.server)
			expectReturn(t, call.result(t, deadline.Add(margin)), 0, []error{telnet.ErrDeadlineEnded, context.DeadlineExceeded}, deadline, deadline.Add(margin))
		})
		t.Run("a deadline at 1 second, a write waiting", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := time.Now().Add(time.Second)
			call := negotiate(withDeadline(t, deadline), pair.server)
			flood(t, pair.client)
			expectReturn(t, call.result(t, deadline.Add(margin)), 0, []error{telnet.ErrDeadlineEnded, context.DeadlineExceeded}, deadline, deadline.Add(margin))
		})
		t.Run("at the edge: a deadline 3 seconds after a moment before the call", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := time.Now().Add(negotiationLimit)
			call := negotiate(withDeadline(t, deadline), pair.server)
			expectReturn(t, call.result(t, deadline.Add(margin)), 0, []error{telnet.ErrDeadlineEnded, context.DeadlineExceeded}, deadline, deadline.Add(margin))
		})
		t.Run("a deadline at 1 second that the context reports ended only later, a read waiting", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := time.Now().Add(time.Second)
			call := negotiate(endsLate(t, deadline), pair.server)
			expectReturn(t, call.result(t, deadline.Add(margin)), 0, []error{telnet.ErrDeadlineEnded, context.DeadlineExceeded}, deadline, deadline.Add(margin))
		})
		t.Run("a deadline at 1 second that the context reports ended only later, a write waiting", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := time.Now().Add(time.Second)
			call := negotiate(endsLate(t, deadline), pair.server)
			flood(t, pair.client)
			expectReturn(t, call.result(t, deadline.Add(margin)), 0, []error{telnet.ErrDeadlineEnded, context.DeadlineExceeded}, deadline, deadline.Add(margin))
		})
	})
	t.Run("If the context is cancelled while a read or a write is waiting, then Negotiate shall stop waiting and return ErrDeadlineEnded.", func(t *testing.T) {
		t.Parallel()
		t.Run("cancelled at 500 ms, a read waiting", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(10*time.Second))
			defer cancel()
			call := negotiate(ctx, pair.server)
			wait(t.Context(), call.called.Add(500*time.Millisecond))
			cancelled := time.Now()
			cancel()
			expectReturn(t, call.result(t, cancelled.Add(margin)), 0, []error{telnet.ErrDeadlineEnded, context.Canceled}, cancelled, cancelled.Add(margin))
		})
		t.Run("cancelled at 500 ms, a write waiting", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			call := negotiate(ctx, pair.server)
			flood(t, pair.client)
			wait(t.Context(), call.called.Add(500*time.Millisecond))
			cancelled := time.Now()
			cancel()
			expectReturn(t, call.result(t, cancelled.Add(margin)), 0, []error{telnet.ErrDeadlineEnded, context.Canceled}, cancelled, cancelled.Add(margin))
		})
	})
	t.Run("Negotiate shall return ErrDeadlineEnded wrapping context.DeadlineExceeded when the context's deadline passed, and context.Canceled when it was cancelled, so that errors.Is matches both.", func(t *testing.T) {
		t.Parallel()
		t.Run("a deadline while waiting matches the deadline and not a cancel", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := time.Now().Add(500 * time.Millisecond)
			call := negotiate(withDeadline(t, deadline), pair.server)
			got := call.result(t, deadline.Add(margin))
			if !errors.Is(got.err, telnet.ErrDeadlineEnded) || !errors.Is(got.err, context.DeadlineExceeded) || errors.Is(got.err, context.Canceled) {
				t.Fatalf("Negotiate returned %v", got.err)
			}
		})
		t.Run("a cancel while waiting matches the cancel and not a deadline", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(10*time.Second))
			defer cancel()
			call := negotiate(ctx, pair.server)
			wait(t.Context(), call.called.Add(300*time.Millisecond))
			cancel()
			got := call.result(t, time.Now().Add(margin))
			if !errors.Is(got.err, telnet.ErrDeadlineEnded) || !errors.Is(got.err, context.Canceled) || errors.Is(got.err, context.DeadlineExceeded) {
				t.Fatalf("Negotiate returned %v", got.err)
			}
		})
		t.Run("ended before the call, each kind", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			got := negotiate(ctx, pair.server).result(t, time.Now().Add(margin))
			if !errors.Is(got.err, telnet.ErrDeadlineEnded) || !errors.Is(got.err, context.Canceled) || errors.Is(got.err, context.DeadlineExceeded) {
				t.Fatalf("Negotiate returned %v for a cancelled context", got.err)
			}
			got = negotiate(withDeadline(t, time.Now().Add(-time.Second)), pair.server).result(t, time.Now().Add(margin))
			if !errors.Is(got.err, telnet.ErrDeadlineEnded) || !errors.Is(got.err, context.DeadlineExceeded) || errors.Is(got.err, context.Canceled) {
				t.Fatalf("Negotiate returned %v for a passed deadline", got.err)
			}
		})
	})
	t.Run("If the context has ended when a read or a write fails, then Negotiate shall return ErrDeadlineEnded, whatever the failure.", func(t *testing.T) {
		t.Parallel()
		t.Run("the caller closes, and the context ends as the read meets end of file", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(10*time.Second))
			defer cancel()
			call := negotiate(ctx, &endsOnFailure{TCPConn: pair.server, cancel: cancel, cancelReadOnEOF: true})
			readExactly(t, pair.client, len(opening), call.called.Add(margin))
			closed := time.Now()
			_ = pair.client.CloseWrite()
			expectReturn(t, call.result(t, closed.Add(margin)), 0, []error{telnet.ErrDeadlineEnded, context.Canceled}, closed, closed.Add(margin))
		})
		t.Run("the context ends as a reply's write fails on a closed connection", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(10*time.Second))
			defer cancel()
			call := negotiate(ctx, &endsOnFailure{TCPConn: pair.server, cancel: cancel, failReply: true})
			readExactly(t, pair.client, len(opening), call.called.Add(margin))
			sent := write(t, pair.client, request(doVerb, telnetTypeOption))
			expectReturn(t, call.result(t, sent.Add(margin)), 0, []error{telnet.ErrDeadlineEnded, context.Canceled}, sent, sent.Add(margin))
		})
	})
	t.Run("If a read returns end of file, then Negotiate shall return ErrCallerClosed without writing that read's replies.", func(t *testing.T) {
		t.Parallel()
		t.Run("the caller shuts down its sending side at once", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(10*time.Second)), pair.server)
			readExactly(t, pair.client, len(opening), call.called.Add(margin))
			closed := time.Now()
			_ = pair.client.CloseWrite()
			expectReturn(t, call.result(t, closed.Add(margin)), 0, []error{telnet.ErrCallerClosed}, closed, closed.Add(margin))
			expectNothingWritten(t, pair)
		})
		t.Run("the caller closes in order after half a request", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(10*time.Second)), pair.server)
			readExactly(t, pair.client, len(opening), call.called.Add(margin))
			write(t, pair.client, []byte{iac, doVerb})
			closed := time.Now()
			_ = pair.client.CloseWrite()
			expectReturn(t, call.result(t, closed.Add(margin)), 0, []error{telnet.ErrCallerClosed}, closed, closed.Add(margin))
			expectNothingWritten(t, pair)
		})
		t.Run("the caller answers once, then closes whole", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(10*time.Second)), pair.server)
			readExactly(t, pair.client, len(opening), call.called.Add(margin))
			write(t, pair.client, request(doVerb, echo))
			closed := time.Now()
			_ = pair.client.Close()
			expectReturn(t, call.result(t, closed.Add(margin)), 0, []error{telnet.ErrCallerClosed}, closed, closed.Add(margin))
		})
	})
	t.Run("If a read or a write fails other than by end of file or a passed deadline, then Negotiate shall return ErrConnectionFailed.", func(t *testing.T) {
		t.Parallel()
		t.Run("the caller resets the connection while a read waits", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(10*time.Second)), pair.server)
			readExactly(t, pair.client, len(opening), call.called.Add(margin))
			broken := time.Now()
			reset(t, pair.client)
			expectReturn(t, call.result(t, broken.Add(margin)), 0, []error{telnet.ErrConnectionFailed}, broken, broken.Add(margin))
		})
		t.Run("the caller resets the connection while a write waits", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(10*time.Second)), pair.server)
			flood(t, pair.client)
			broken := time.Now()
			reset(t, pair.client)
			expectReturn(t, call.result(t, broken.Add(margin)), 0, []error{telnet.ErrConnectionFailed}, broken, broken.Add(margin))
		})
		t.Run("the server end is closed under a waiting read", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(10*time.Second)), pair.server)
			readExactly(t, pair.client, len(opening), call.called.Add(margin))
			wait(t.Context(), time.Now().Add(200*time.Millisecond))
			closed := time.Now()
			_ = pair.server.Close()
			expectReturn(t, call.result(t, closed.Add(margin)), 0, []error{telnet.ErrConnectionFailed}, closed, closed.Add(margin))
		})
	})
	t.Run("The telnet package shall send the caller no option request other than WILL ECHO, WILL SGA and the replies the tables on Receive give.", func(t *testing.T) {
		t.Parallel()
		t.Run("every option request in one write", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(10*time.Second)), pair.server)
			requests := sweep()
			sent := write(t, pair.client, requests)
			expectReturn(t, call.result(t, sent.Add(margin)), telnet.Answered, nil, call.called, sent.Add(margin))
			_ = pair.server.CloseWrite()
			expectStream(t, pair.client, join(opening, expectedReplies(requests)), time.Now().Add(margin))
		})
	})
	t.Run("Negotiate shall write nothing to the connection but the opening requests and the replies Receive appends.", func(t *testing.T) {
		t.Parallel()
		t.Run("every option request a byte at a time", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(10*time.Second)), pair.server)
			requests := join(request(doVerb, telnetTypeOption), request(will, windowSizeOption), []byte{iac, nop, 'x'}, request(dont, echo), request(doVerb, echo), request(doVerb, sga))
			for index := range requests {
				write(t, pair.client, requests[index:index+1])
			}
			got := call.result(t, time.Now().Add(margin))
			expectReturn(t, got, telnet.Answered, nil, call.called, got.returned)
			_ = pair.server.CloseWrite()
			expectStream(t, pair.client, join(opening, request(wont, telnetTypeOption), request(dont, windowSizeOption), request(will, echo)), time.Now().Add(margin))
		})
		t.Run("a request split by the 256-byte read", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(10*time.Second)), pair.server)
			readExactly(t, pair.client, len(opening), call.called.Add(margin))
			count := readBufferBytes/3 + 1
			sent := write(t, pair.client, join(repeated(request(doVerb, telnetTypeOption), count), answers))
			expectReturn(t, call.result(t, sent.Add(margin)), telnet.Answered, nil, call.called, sent.Add(margin))
			_ = pair.server.CloseWrite()
			expectStream(t, pair.client, repeated(request(wont, telnetTypeOption), count), time.Now().Add(margin))
		})
	})
	t.Run("When it returns, Negotiate shall leave the connection's read and write deadlines at the context's deadline.", func(t *testing.T) {
		t.Parallel()
		t.Run("answered: a read then waits until the context's deadline", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := time.Now().Add(2 * time.Second)
			call := negotiate(withDeadline(t, deadline), pair.server)
			write(t, pair.client, answers)
			call.result(t, deadline)
			expectReadDeadlineAt(t, pair.server, deadline)
		})
		t.Run("answered: a write to a caller that does not read waits until the context's deadline", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			_ = pair.client.SetReadBuffer(4096)
			deadline := time.Now().Add(2 * time.Second)
			call := negotiate(withDeadline(t, deadline), pair.server)
			write(t, pair.client, answers)
			call.result(t, deadline)
			expectWriteDeadlineAt(t, pair.server, deadline)
		})
		t.Run("timed out at 3 seconds: a read waits until the deadline at 5", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := time.Now().Add(5 * time.Second)
			call := negotiate(withDeadline(t, deadline), pair.server)
			got := call.result(t, deadline)
			if got.outcome != telnet.TimedOut {
				t.Fatalf("Negotiate returned (%v, %v), want TimedOut", got.outcome, got.err)
			}
			expectReadDeadlineAt(t, pair.server, deadline)
		})
		t.Run("cancelled at 500 ms: a read waits until the deadline at 2 seconds", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := time.Now().Add(2 * time.Second)
			ctx, cancel := context.WithDeadline(t.Context(), deadline)
			defer cancel()
			call := negotiate(ctx, pair.server)
			wait(t.Context(), call.called.Add(500*time.Millisecond))
			cancel()
			call.result(t, deadline)
			expectReadDeadlineAt(t, pair.server, deadline)
		})
		t.Run("the caller closed: a write to it waits until the context's deadline", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			_ = pair.client.SetReadBuffer(4096)
			deadline := time.Now().Add(2 * time.Second)
			call := negotiate(withDeadline(t, deadline), pair.server)
			readExactly(t, pair.client, len(opening), call.called.Add(margin))
			_ = pair.client.CloseWrite()
			got := call.result(t, deadline)
			if !errors.Is(got.err, telnet.ErrCallerClosed) {
				t.Fatalf("Negotiate returned %v, want ErrCallerClosed", got.err)
			}
			expectWriteDeadlineAt(t, pair.server, deadline)
		})
	})
	t.Run("If any failure not named above occurs, then Negotiate shall return ErrConnectionFailed and leave nothing behind.", func(t *testing.T) {
		t.Parallel()
		t.Run("a connection already closed", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			_ = pair.server.Close()
			call := negotiate(withDeadline(t, time.Now().Add(10*time.Second)), pair.server)
			expectReturn(t, call.result(t, call.called.Add(margin)), 0, []error{telnet.ErrConnectionFailed}, call.called, call.called.Add(margin))
			_, err := readToEnd(pair.client, time.Now().Add(margin))
			if !errors.Is(err, io.EOF) {
				t.Fatalf("the caller's end saw %v, want end of stream", err)
			}
		})
	})
}
