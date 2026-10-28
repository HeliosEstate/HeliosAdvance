// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests of Limit: the earlier of a call's own deadline and its context's, which of the two at the
// same instant, and each side missing, for contexts live and ended alike.
package timeup_test

import (
	"context"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/timeup"
)

// Times far ahead, so no row's context ends while it runs unless the row ends it, written in two
// zones so that the same instant can be told apart by which value came back.
var (
	ahead       = time.Date(2100, time.March, 4, 5, 6, 7, 8, time.UTC)
	oneHourEast = time.FixedZone("one hour east", 3600)
)

// expectLimit fails unless Limit returned exactly want: the same instant, zone and monotonic
// reading, so a row tells which of two equal instants came back.
func expectLimit(t *testing.T, got, want time.Time) {
	t.Helper()
	if got != want {
		t.Fatalf("Limit returned %v (zone %v), want %v (zone %v), the same value", got, got.Location(), want, want.Location())
	}
}

func TestLimit(t *testing.T) {
	t.Parallel()

	t.Run("When deadline is not zero and the context has a deadline, Limit shall return the earlier of the two, and deadline itself when the two are the same instant.", func(t *testing.T) {
		t.Parallel()
		inTheZone := ahead.In(oneHourEast)
		withClock := time.Now().Add(time.Hour)
		passed := time.Now().Add(-time.Hour)
		for _, row := range []struct {
			name            string
			contextDeadline time.Time
			deadline        time.Time
			cancel          bool
			want            time.Time
		}{
			{"the context's a nanosecond earlier: the context's", ahead.Add(-time.Nanosecond), ahead, false, ahead.Add(-time.Nanosecond)},
			{"deadline a nanosecond earlier: deadline", ahead, ahead.Add(-time.Nanosecond), false, ahead.Add(-time.Nanosecond)},
			{"the same instant, the context's in another zone: deadline itself", inTheZone, ahead, false, ahead},
			{"the same instant, deadline in another zone: deadline itself", ahead, inTheZone, false, inTheZone},
			{"the same instant, only deadline with the clock's monotonic reading: deadline itself", withClock.Round(0), withClock, false, withClock},
			{"the same instant, only the context's with the clock's monotonic reading: deadline itself", withClock, withClock.Round(0), false, withClock.Round(0)},
			{"the context already ended by its deadline, which is earlier: the context's", passed, ahead, false, passed},
			{"the context cancelled, its deadline later: deadline", ahead, ahead.Add(-time.Hour), true, ahead.Add(-time.Hour)},
		} {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				ctx, cancel := context.WithDeadline(t.Context(), row.contextDeadline)
				t.Cleanup(cancel)
				if row.cancel {
					cancel()
				}
				expectLimit(t, timeup.Limit(ctx, row.deadline), row.want)
			})
		}
	})

	t.Run("When deadline is zero, Limit shall return the context's deadline, or the zero time when the context has none.", func(t *testing.T) {
		t.Parallel()
		passed := time.Now().Add(-time.Hour)
		for _, row := range []struct {
			name string
			ctx  func(t *testing.T) context.Context
			want time.Time
		}{
			{"the context's deadline ahead, in another zone: the context's", func(t *testing.T) context.Context {
				t.Helper()
				return withDeadline(t, t.Context(), ahead.In(oneHourEast))
			}, ahead.In(oneHourEast)},
			{"the context already ended by its deadline: the context's", func(t *testing.T) context.Context {
				t.Helper()
				return withDeadline(t, t.Context(), passed)
			}, passed},
			{"a context with no deadline: the zero time", func(t *testing.T) context.Context {
				t.Helper()
				return context.WithoutCancel(t.Context())
			}, time.Time{}},
			{"a cancelled context with no deadline: the zero time", cancelled, time.Time{}},
		} {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				expectLimit(t, timeup.Limit(row.ctx(t), time.Time{}), row.want)
			})
		}
	})

	t.Run("When the context has no deadline, Limit shall return deadline.", func(t *testing.T) {
		t.Parallel()
		passed := time.Now().Add(-time.Hour)
		for _, row := range []struct {
			name     string
			ctx      func(t *testing.T) context.Context
			deadline time.Time
		}{
			{"a context that never ends, deadline ahead in another zone: deadline", func(t *testing.T) context.Context {
				t.Helper()
				return context.WithoutCancel(t.Context())
			}, ahead.In(oneHourEast)},
			{"a cancelled context, deadline ahead: deadline", cancelled, ahead},
			{"a context that never ends, deadline already passed: deadline", func(t *testing.T) context.Context {
				t.Helper()
				return context.WithoutCancel(t.Context())
			}, passed},
		} {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				expectLimit(t, timeup.Limit(row.ctx(t), row.deadline), row.deadline)
			})
		}
	})
}
