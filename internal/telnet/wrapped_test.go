// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests that the Line's calls return a context's end wrapped in the Telnet unit's own error, never
// the context's error bare: for a context cancelled, one whose deadline passed and was reported,
// one whose deadline the clock has passed before it reports it, and a cancel while a call waits.
package telnet_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// endedContext is one way a context has ended before a call, and the error it ended with.
type endedContext struct {
	name string
	ctx  func(t *testing.T) context.Context
	want error
}

var endedContexts = []endedContext{
	{"cancelled", cancelled, context.Canceled},
	{"its deadline passed and reported", func(t *testing.T) context.Context {
		t.Helper()
		return withDeadline(t, time.Now().Add(-time.Second))
	}, context.DeadlineExceeded},
	{"its deadline passed by the clock, not yet reported", func(t *testing.T) context.Context {
		t.Helper()
		return lateEnd{Context: context.WithoutCancel(t.Context()), deadline: time.Now().Add(-time.Second)}
	}, context.DeadlineExceeded},
}

// expectWrapped fails unless err is want wrapped: errors.Is finds it, but err is neither want
// itself nor worded as want alone.
func expectWrapped(t *testing.T, call string, err, want error) {
	t.Helper()
	//nolint:errorlint // the row tells a wrapped error from the bare one by the value itself
	if !errors.Is(err, want) || err == want || err.Error() == want.Error() {
		t.Fatalf("%s returned %#v, want %v wrapped in the unit's own error", call, err, want)
	}
}

// waitedError is the error a call running on its own goroutine returns, within a hang's bound.
func waitedError(t *testing.T, call string, returned <-chan error) error {
	t.Helper()
	bound := testrun.Patient(10 * time.Second)
	select {
	case err := <-returned:
		return err
	case <-time.After(bound):
		t.Fatalf("%s had not returned %v after its context was cancelled", call, bound)
		return nil
	}
}

func TestLineWrapsTheContextsError(t *testing.T) {
	t.Parallel()

	t.Run("If the context has ended when SendChar is called, then SendChar shall queue nothing and return the context's error, wrapped.", func(t *testing.T) {
		t.Parallel()
		for _, row := range endedContexts {
			t.Run(row.name+": the context's error, wrapped", func(t *testing.T) {
				t.Parallel()
				_, line := answeredLine(t, nil)
				expectWrapped(t, "SendChar", line.SendChar(row.ctx(t), 'x'), row.want)
			})
		}
	})

	t.Run("If the context has ended when Flush is called, or ends while it waits, then Flush shall write nothing more and return the context's error, wrapped.", func(t *testing.T) {
		t.Parallel()
		for _, row := range endedContexts {
			t.Run(row.name+", abc queued: the context's error, wrapped", func(t *testing.T) {
				t.Parallel()
				_, line := answeredLine(t, nil)
				sendAll(t, line, []byte("abc"))
				expectWrapped(t, "Flush", line.Flush(row.ctx(t)), row.want)
			})
		}
		t.Run("cancelled during the call, on a caller that does not read: context.Canceled, wrapped", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			fill(t, pair.server.TCPConn)
			sendAll(t, line, []byte("queued"))
			ctx, cancel := context.WithCancel(t.Context())
			returned := make(chan error, 1)
			go func() { returned <- line.Flush(ctx) }()
			cancel()
			expectWrapped(t, "Flush", waitedError(t, "Flush", returned), context.Canceled)
		})
	})

	t.Run("If the context has ended when RecvChar is called, or ends while it waits, then RecvChar shall return the context's error, wrapped, and no byte.", func(t *testing.T) {
		t.Parallel()
		for _, row := range endedContexts {
			t.Run(row.name+", a byte waiting: the context's error, wrapped", func(t *testing.T) {
				t.Parallel()
				_, line := answeredLine(t, []byte("a"))
				_, err := line.RecvChar(row.ctx(t), time.Now().Add(testrun.Patient(time.Minute)))
				expectWrapped(t, "RecvChar", err, row.want)
			})
		}
		t.Run("cancelled during the call, nothing sent: context.Canceled, wrapped", func(t *testing.T) {
			t.Parallel()
			_, line := answeredLine(t, nil)
			ctx, cancel := context.WithCancel(t.Context())
			returned := make(chan error, 1)
			go func() {
				_, err := line.RecvChar(ctx, time.Now().Add(testrun.Patient(time.Minute)))
				returned <- err
			}()
			cancel()
			expectWrapped(t, "RecvChar", waitedError(t, "RecvChar", returned), context.Canceled)
		})
	})

	t.Run("If the context has ended when Close is called, then Close shall return the context's error, wrapped, without touching the connection.", func(t *testing.T) {
		t.Parallel()
		for _, row := range endedContexts {
			t.Run(row.name+": the context's error, wrapped", func(t *testing.T) {
				t.Parallel()
				_, line := acceptedLine(t)
				expectWrapped(t, "Close", line.Close(row.ctx(t)), row.want)
			})
		}
	})

	t.Run("If the context ends while Close waits, then Close shall return the context's error, wrapped.", func(t *testing.T) {
		t.Parallel()
		t.Run("cancelled during the closing wait: context.Canceled, wrapped", func(t *testing.T) {
			t.Parallel()
			pair, line := acceptedLine(t)
			ctx, cancel := context.WithCancel(t.Context())
			done := closeOn(ctx, line)
			expectEndOfStream(t, pair.client)
			cancel()
			expectWrapped(t, "Close", waitClosed(t, done, testrun.Patient(10*time.Second)).err, context.Canceled)
		})
	})
}
