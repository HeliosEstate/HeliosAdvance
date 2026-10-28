// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests of Ended: which error it gives for a context that has reported its end, for one whose
// deadline the clock has passed before the context reports it, and nil for one whose time has
// not run out.
package timeup_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/timeup"
)

// unreported is a context whose deadline is set but which never reports an end: the moment
// after a context's deadline has passed and before its own timer has fired, held still.
type unreported struct {
	deadline time.Time
}

func (ctx unreported) Deadline() (time.Time, bool) { return ctx.deadline, true }
func (unreported) Done() <-chan struct{}           { return nil }
func (unreported) Err() error                      { return nil }
func (unreported) Value(any) any                   { return nil }

func cancelled(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	return ctx
}

func withDeadline(t *testing.T, parent context.Context, deadline time.Time) context.Context {
	t.Helper()
	ctx, cancel := context.WithDeadline(parent, deadline)
	t.Cleanup(cancel)
	return ctx
}

func TestEnded(t *testing.T) {
	t.Parallel()
	causeOfTheRow := errors.New("the row's own cause")

	t.Run("If the context reports that it has ended, then Ended shall return the context's own error, context.Canceled or context.DeadlineExceeded, unwrapped.", func(t *testing.T) {
		t.Parallel()
		for _, row := range []struct {
			name string
			ctx  func(t *testing.T) context.Context
			want error
		}{
			{"cancelled: context.Canceled itself", cancelled, context.Canceled},
			{"cancelled with a cause: context.Canceled itself, not the cause", func(t *testing.T) context.Context {
				t.Helper()
				ctx, cancel := context.WithCancelCause(t.Context())
				cancel(causeOfTheRow)
				return ctx
			}, context.Canceled},
			{"its deadline passed and reported: context.DeadlineExceeded itself", func(t *testing.T) context.Context {
				t.Helper()
				return withDeadline(t, t.Context(), time.Now().Add(-time.Hour))
			}, context.DeadlineExceeded},
			{"its deadline passed with a cause: context.DeadlineExceeded itself, not the cause", func(t *testing.T) context.Context {
				t.Helper()
				ctx, cancel := context.WithDeadlineCause(t.Context(), time.Now().Add(-time.Hour), causeOfTheRow)
				t.Cleanup(cancel)
				return ctx
			}, context.DeadlineExceeded},
			{"cancelled with its deadline an hour ahead: context.Canceled", func(t *testing.T) context.Context {
				t.Helper()
				ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(time.Hour))
				cancel()
				return ctx
			}, context.Canceled},
			{"reporting context.Canceled with its deadline already passed: context.Canceled, not context.DeadlineExceeded", func(t *testing.T) context.Context {
				t.Helper()
				return withDeadline(t, cancelled(t), time.Now().Add(-time.Hour))
			}, context.Canceled},
		} {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				ctx := row.ctx(t)
				if !errors.Is(ctx.Err(), row.want) {
					t.Fatalf("the row's context reports %v, want %v: a fault in the row", ctx.Err(), row.want)
				}
				//nolint:errorlint // the line asks for the context's error itself, unwrapped
				if err := timeup.Ended(ctx); err != row.want {
					t.Fatalf("Ended returned %#v, want %v itself", err, row.want)
				}
			})
		}
	})

	t.Run("If the context has not reported its end and its deadline is not after the clock's time, then Ended shall return context.DeadlineExceeded.", func(t *testing.T) {
		t.Parallel()
		for _, row := range []struct {
			name     string
			deadline func() time.Time
		}{
			{"its deadline an hour past", func() time.Time { return time.Now().Add(-time.Hour) }},
			{"its deadline the clock's time just before the call, never after it at the call", time.Now},
		} {
			t.Run(row.name+": context.DeadlineExceeded itself", func(t *testing.T) {
				t.Parallel()
				//nolint:errorlint // the line asks for context.DeadlineExceeded itself
				if err := timeup.Ended(unreported{deadline: row.deadline()}); err != context.DeadlineExceeded {
					t.Fatalf("Ended returned %#v, want context.DeadlineExceeded itself", err)
				}
			})
		}
	})

	t.Run("While the context has not reported its end and has no deadline, or a deadline after the clock's time, Ended shall return nil.", func(t *testing.T) {
		t.Parallel()
		for _, row := range []struct {
			name string
			ctx  func(t *testing.T) context.Context
		}{
			{"no deadline and never ended", func(t *testing.T) context.Context {
				t.Helper()
				return context.WithoutCancel(t.Context())
			}},
			{"no deadline, cancellable and not cancelled", func(t *testing.T) context.Context {
				t.Helper()
				ctx, cancel := context.WithCancel(t.Context())
				t.Cleanup(cancel)
				return ctx
			}},
			{"its deadline an hour ahead", func(t *testing.T) context.Context {
				t.Helper()
				return withDeadline(t, t.Context(), time.Now().Add(time.Hour))
			}},
			{"not reporting, its deadline an hour ahead", func(*testing.T) context.Context {
				return unreported{deadline: time.Now().Add(time.Hour)}
			}},
		} {
			t.Run(row.name+": nil", func(t *testing.T) {
				t.Parallel()
				if err := timeup.Ended(row.ctx(t)); err != nil {
					t.Fatalf("Ended returned %v, want nil", err)
				}
			})
		}
	})
}
