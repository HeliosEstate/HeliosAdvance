// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests that Text I/O's SendString, over a real Telnet Line, returns a context's end wrapped in an
// error of its own, never the context's error bare: for a context cancelled, one whose deadline
// passed and was reported, and one whose deadline the clock has passed before it reports it.
package listener_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/textio"
)

// notYetReported is a context whose deadline the clock has passed but which has not reported its
// end: the moment before a context's own timer fires, held still.
type notYetReported struct {
	context.Context
	deadline time.Time
}

func (ctx notYetReported) Deadline() (time.Time, bool) { return ctx.deadline, true }

func TestSendStringWrapsTheContextsError(t *testing.T) {
	t.Parallel()

	t.Run("If the context has ended when SendString is called, then SendString shall write nothing and return the context's error, wrapped.", func(t *testing.T) {
		t.Parallel()
		for _, row := range []struct {
			name string
			ctx  func(t *testing.T) context.Context
			want error
		}{
			{"cancelled", ended, context.Canceled},
			{"its deadline passed and reported", func(t *testing.T) context.Context {
				t.Helper()
				ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
				t.Cleanup(cancel)
				return ctx
			}, context.DeadlineExceeded},
			{"its deadline passed by the clock, not yet reported", func(t *testing.T) context.Context {
				t.Helper()
				return notYetReported{Context: context.WithoutCancel(t.Context()), deadline: time.Now().Add(-time.Second)}
			}, context.DeadlineExceeded},
		} {
			t.Run(row.name+": the context's error, wrapped", func(t *testing.T) {
				t.Parallel()
				pair := openStack(t, answers, nil)
				err := textio.New(pair.line).SendString(row.ctx(t), "abc")
				//nolint:errorlint // a wrapped error told from the bare one by value
				if !errors.Is(err, row.want) || err == row.want || err.Error() == row.want.Error() {
					t.Fatalf("SendString returned %#v, want %v wrapped in an error of its own", err, row.want)
				}
			})
		}
	})
}
