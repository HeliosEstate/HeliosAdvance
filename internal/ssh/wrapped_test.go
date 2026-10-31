// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests that the Channel's calls return a context's end wrapped in the SSH unit's own error, never
// the context's error bare: for a context cancelled, one whose deadline passed and was reported,
// one whose deadline the clock has passed before it reports it, and a cancel while a call waits.
package ssh_test

import (
	"bytes"
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
		ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
		t.Cleanup(cancel)
		return ctx
	}, context.DeadlineExceeded},
	{"its deadline passed by the clock, not yet reported", func(t *testing.T) context.Context {
		t.Helper()
		return newLateReport(time.Now().Add(-time.Second), time.Now().Add(time.Hour))
	}, context.DeadlineExceeded},
}

// expectWrapped fails unless err is want wrapped: errors.Is finds it, but err is neither want
// itself nor worded as want alone.
func expectWrapped(t *testing.T, call string, err, want error) {
	t.Helper()
	//nolint:errorlint // the row tells a wrapped error from the bare one by the value itself
	if !errors.Is(err, want) || err == want || err.Error() == want.Error() {
		t.Fatalf("%s gave %#v, want %v wrapped in the unit's own error", call, err, want)
	}
}

// waitedError is the error a call running on its own goroutine returns, within a hang's bound.
func waitedError(t *testing.T, call string, returned <-chan error) error {
	t.Helper()
	select {
	case err := <-returned:
		return err
	case <-time.After(testrun.Patient(testrun.HangBound)):
		t.Fatalf("%s had not returned %v after its context was cancelled", call, testrun.Patient(testrun.HangBound))
		return nil
	}
}

func TestChannelWrapsTheContextsError(t *testing.T) {
	t.Parallel()

	t.Run("If the context has ended when SendChar is called, then SendChar shall queue nothing and return the context's error, wrapped.", func(t *testing.T) {
		t.Parallel()
		for _, row := range endedContexts {
			t.Run(row.name+": the context's error, wrapped", func(t *testing.T) {
				t.Parallel()
				call := acceptCall(t, false, "", clientWindow)
				expectWrapped(t, "SendChar", call.channel.SendChar(row.ctx(t), 'a'), row.want)
			})
		}
	})

	t.Run("If the context has ended when Flush is called, or ends while it waits, then Flush shall write nothing more and return the context's error, wrapped.", func(t *testing.T) {
		t.Parallel()
		for _, row := range endedContexts {
			t.Run(row.name+", abc queued: the context's error, wrapped", func(t *testing.T) {
				t.Parallel()
				call := acceptCall(t, false, "", clientWindow)
				sendText(t, call.channel, []byte("abc"))
				expectWrapped(t, "Flush", call.channel.Flush(row.ctx(t)), row.want)
			})
		}
		t.Run("cancelled while the write waits on a caller that lets 16 bytes through: context.Canceled, wrapped", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", 16)
			sendText(t, call.channel, bytes.Repeat([]byte("abcdefgh"), 12))
			ctx, cancel := context.WithCancel(t.Context())
			returned := make(chan error, 1)
			go func() { returned <- call.channel.Flush(ctx) }()
			call.client.readData(16, time.Now().Add(testrun.Patient(testrun.HangBound)))
			cancel()
			expectWrapped(t, "Flush", waitedError(t, "Flush", returned), context.Canceled)
		})
	})

	t.Run("If the context has ended when RecvChar is called, or ends while it waits, then RecvChar shall return the context's error, wrapped, and no byte.", func(t *testing.T) {
		t.Parallel()
		for _, row := range endedContexts {
			t.Run(row.name+", a waiting: the context's error, wrapped", func(t *testing.T) {
				t.Parallel()
				call := acceptCall(t, false, "a", clientWindow)
				_, err := call.channel.RecvChar(row.ctx(t), time.Now().Add(time.Minute))
				expectWrapped(t, "RecvChar", err, row.want)
			})
		}
		t.Run("cancelled during the call, nothing sent: context.Canceled, wrapped", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			ctx, cancel := context.WithCancel(t.Context())
			returned := make(chan error, 1)
			go func() {
				_, err := call.channel.RecvChar(ctx, time.Now().Add(time.Minute))
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
				call := acceptCall(t, false, "", clientWindow)
				expectWrapped(t, "Close", call.channel.Close(row.ctx(t)), row.want)
			})
		}
	})

	t.Run("If the context ends while Close waits, then Close shall return the context's error, wrapped.", func(t *testing.T) {
		t.Parallel()
		t.Run("cancelled during the closing wait: context.Canceled, wrapped", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			ctx, cancel := context.WithCancel(t.Context())
			returned := make(chan error, 1)
			go func() { returned <- call.channel.Close(ctx) }()
			expectClosingMessages(t, call.client, "")
			cancel()
			expectWrapped(t, "Close", waitedError(t, "Close", returned), context.Canceled)
		})
	})
}
