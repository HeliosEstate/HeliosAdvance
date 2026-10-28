// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests of WakeOnEnd and its release over a real loopback connection: no goroutine while the
// context lasts, one wake on a goroutine of its own once it ends, a wake begun for a context
// already ended, a failing connection, and what the release leaves running when it returns,
// a release that lands while the wake is midway included.
package timeup_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/timeup"
)

// register calls WakeOnEnd under the row's label and returns its release, called once: by the
// row, or at the row's end if the row failed first.
func register(t *testing.T, label string, ctx context.Context, conn *watchedConn) func() {
	t.Helper()
	var release func()
	labelled(ctx, label, func() { release = timeup.WakeOnEnd(ctx, conn) })
	var once sync.Once
	releaseOnce := func() { once.Do(release) }
	t.Cleanup(releaseOnce)
	return releaseOnce
}

// expectWakesAtAll is the probe a row that expects no wake ends with: a WakeOnEnd of the probe's
// own, whose context it ends, must wake its connection, so a WakeOnEnd that does nothing fails.
func expectWakesAtAll(t *testing.T) {
	t.Helper()
	conn := newWatched(t)
	ctx, cancel := context.WithCancel(t.Context())
	release := register(t, "", ctx, conn)
	cancel()
	waitFor(t, conn.writeSet, "the probe's wake")
	release()
	expectWoken(t, conn.entries(), wokenTime(t))
}

func TestWakeOnEnd(t *testing.T) {
	t.Parallel()

	t.Run("Where ctx was made by the context package, WakeOnEnd shall start no goroutine before ctx ends.", func(t *testing.T) {
		t.Parallel()
		for _, row := range []struct {
			name string
			ctx  func(t *testing.T) (context.Context, context.CancelFunc)
		}{
			{"a live context", func(t *testing.T) (context.Context, context.CancelFunc) {
				t.Helper()
				return context.WithCancel(t.Context())
			}},
			{"a context whose deadline is an hour ahead", func(t *testing.T) (context.Context, context.CancelFunc) {
				t.Helper()
				return context.WithDeadline(t.Context(), time.Now().Add(time.Hour))
			}},
			{"a context that never ends", func(t *testing.T) (context.Context, context.CancelFunc) {
				t.Helper()
				return context.WithoutCancel(t.Context()), nil
			}},
		} {
			t.Run(row.name+": no goroutine of the row's and no deadline set, then the wake once a context ends", func(t *testing.T) {
				t.Parallel()
				woken := wokenTime(t)
				conn := newWatched(t)
				ctx, cancel := row.ctx(t)
				label := labelled(t.Context(), "", func() {})
				release := register(t, label, ctx, conn)
				if count := countLabelled(t, label); count != 0 {
					t.Fatalf("WakeOnEnd started %d goroutines before the context ended", count)
				}
				if journal := conn.entries(); len(journal) != 0 {
					t.Fatalf("WakeOnEnd set %s before the context ended", described(journal))
				}
				if cancel == nil {
					release()
					expectWakesAtAll(t)
					return
				}
				labelled(t.Context(), label, cancel)
				waitFor(t, conn.writeSet, "the wake")
				release()
				expectWoken(t, conn.entries(), woken)
			})
		}
	})

	t.Run("Once ctx has ended, WakeOnEnd shall begin the wake, which calls Wake on conn once, in a goroutine of its own, unless the release has stopped it before it began.", func(t *testing.T) {
		t.Parallel()
		t.Run("cancelled after it is registered: Wake's two deadlines once, on a goroutine of their own", func(t *testing.T) {
			t.Parallel()
			woken := wokenTime(t)
			conn := newWatched(t)
			ctx, cancel := context.WithCancel(t.Context())
			label := labelled(t.Context(), "", func() {})
			release := register(t, label, ctx, conn)
			labelled(t.Context(), label, cancel)
			waitFor(t, conn.writeSet, "the wake")
			release()
			waitNoneLabelled(t, label)
			expectWoken(t, conn.entries(), woken, goroutineID())
		})
		t.Run("cancelled from another goroutine: on a goroutine that is neither the row's nor the cancelling one", func(t *testing.T) {
			t.Parallel()
			woken := wokenTime(t)
			conn := newWatched(t)
			ctx, cancel := context.WithCancel(t.Context())
			label := labelled(t.Context(), "", func() {})
			release := register(t, label, ctx, conn)
			cancelledOn := make(chan int64, 1)
			labelled(t.Context(), label, func() {
				go func() {
					cancelledOn <- goroutineID()
					cancel()
				}()
			})
			canceller := <-cancelledOn
			waitFor(t, conn.writeSet, "the wake")
			release()
			waitNoneLabelled(t, label)
			expectWoken(t, conn.entries(), woken, goroutineID(), canceller)
		})
		t.Run("a parent context cancelled: Wake's two deadlines once, on a goroutine of their own", func(t *testing.T) {
			t.Parallel()
			woken := wokenTime(t)
			conn := newWatched(t)
			parent, cancel := context.WithCancel(t.Context())
			child, childCancel := context.WithCancel(parent)
			t.Cleanup(childCancel)
			label := labelled(t.Context(), "", func() {})
			release := register(t, label, child, conn)
			labelled(t.Context(), label, cancel)
			waitFor(t, conn.writeSet, "the wake")
			release()
			waitNoneLabelled(t, label)
			expectWoken(t, conn.entries(), woken, goroutineID())
		})
		t.Run("ended by its own deadline: Wake's two deadlines once, on a goroutine of their own", func(t *testing.T) {
			t.Parallel()
			woken := wokenTime(t)
			conn := newWatched(t)
			ctx := withDeadline(t, t.Context(), time.Now().Add(50*time.Millisecond))
			release := register(t, "", ctx, conn)
			waitFor(t, conn.writeSet, "the wake")
			release()
			expectWoken(t, conn.entries(), woken, goroutineID())
		})
		t.Run("two connections on one context: each woken once, on two goroutines, neither the row's", func(t *testing.T) {
			t.Parallel()
			woken := wokenTime(t)
			first, second := newWatched(t), newWatched(t)
			ctx, cancel := context.WithCancel(t.Context())
			label := labelled(t.Context(), "", func() {})
			releaseFirst := register(t, label, ctx, first)
			releaseSecond := register(t, label, ctx, second)
			labelled(t.Context(), label, cancel)
			waitFor(t, first.writeSet, "the first wake")
			waitFor(t, second.writeSet, "the second wake")
			releaseFirst()
			releaseSecond()
			waitNoneLabelled(t, label)
			row := goroutineID()
			expectWoken(t, first.entries(), woken, row)
			expectWoken(t, second.entries(), woken, row, first.entries()[0].goroutine)
		})
		t.Run("released before the context ends: no deadline set, once none of the row's goroutines is left", func(t *testing.T) {
			t.Parallel()
			conn := newWatched(t)
			ctx, cancel := context.WithCancel(t.Context())
			label := labelled(t.Context(), "", func() {})
			register(t, label, ctx, conn)()
			labelled(t.Context(), label, cancel)
			waitNoneLabelled(t, label)
			if journal := conn.entries(); len(journal) != 0 {
				t.Fatalf("a released WakeOnEnd set %s when its context ended", described(journal))
			}
			expectWakesAtAll(t)
		})
	})

	t.Run("If ctx has already ended when WakeOnEnd is called, then the wake shall have begun when WakeOnEnd returns.", func(t *testing.T) {
		t.Parallel()
		for _, row := range []struct {
			name string
			ctx  func(t *testing.T) context.Context
		}{
			{"cancelled", cancelled},
			{"its deadline passed", func(t *testing.T) context.Context {
				t.Helper()
				return withDeadline(t, t.Context(), time.Now().Add(-time.Hour))
			}},
			{"cancelled with a cause", func(t *testing.T) context.Context {
				t.Helper()
				ctx, cancel := context.WithCancelCause(t.Context())
				cancel(errReadRefused)
				return ctx
			}},
		} {
			t.Run(row.name+": a release called at once still returns after Wake's two deadlines, set on a goroutine of their own", func(t *testing.T) {
				t.Parallel()
				woken := wokenTime(t)
				conn := newWatched(t)
				label := labelled(t.Context(), "", func() {})
				register(t, label, row.ctx(t), conn)()
				journal := conn.entries()
				waitNoneLabelled(t, label)
				expectWoken(t, journal, woken, goroutineID())
				if after := conn.entries(); len(after) != len(journal) {
					t.Fatalf("the connection had %s when the release returned, then %s", described(journal), described(after))
				}
			})
		}
	})

	t.Run("If Wake returns an error, then the wake shall drop it: the call's time has already run out, and each unit reports that, whatever the connection does next.", func(t *testing.T) {
		t.Parallel()
		for _, row := range wakeCases[1:] {
			t.Run(row.name+": both deadlines tried once, and the release returns", func(t *testing.T) {
				t.Parallel()
				woken := wokenTime(t)
				conn := row.conn(t)
				ctx, cancel := context.WithCancel(t.Context())
				label := labelled(t.Context(), "", func() {})
				release := register(t, label, ctx, conn)
				labelled(t.Context(), label, cancel)
				waitFor(t, conn.writeSet, "the wake")
				release()
				waitNoneLabelled(t, label)
				expectWoken(t, conn.entries(), woken, goroutineID())
			})
		}
	})

	t.Run("When the release returns, no wake shall be running and none shall begin afterwards: the release stops a wake that has not begun, and waits for one that has begun to end.", func(t *testing.T) {
		t.Parallel()
		t.Run("released before the context ends, which then ends: no deadline set, once none of the row's goroutines is left", func(t *testing.T) {
			t.Parallel()
			conn := newWatched(t)
			ctx, cancel := context.WithCancel(t.Context())
			label := labelled(t.Context(), "", func() {})
			register(t, label, ctx, conn)()
			conn.mark(releasedMark)
			labelled(t.Context(), label, cancel)
			waitNoneLabelled(t, label)
			if journal := conn.entries(); len(journal) != 1 {
				t.Fatalf("the connection has %s, want only the release", described(journal))
			}
			expectWakesAtAll(t)
		})
		for _, held := range []string{readDeadline, writeDeadline} {
			t.Run("released while the wake is held setting the "+held+" deadline: the release waits, and returns after both are set", func(t *testing.T) {
				t.Parallel()
				woken := wokenTime(t)
				conn := newWatched(t)
				ctx, cancel := context.WithCancel(t.Context())
				label := labelled(t.Context(), "", func() {})
				release := register(t, label, ctx, conn)
				// Held after the registration, so a failed row lets the wake go before its
				// release is called at the row's end.
				letGo := conn.hold(t, held)
				entered := conn.readEntered
				if held == writeDeadline {
					entered = conn.writeEntered
				}
				labelled(t.Context(), label, cancel)
				waitFor(t, entered, "the wake reaching the "+held+" deadline")
				releasing := make(chan int64, 1)
				returned := make(chan struct{})
				go func() {
					releasing <- goroutineID()
					release()
					conn.mark(releasedMark)
					close(returned)
				}()
				if !waitParked(t, <-releasing, returned) {
					letGo()
					t.Fatalf("the release returned while the wake was still setting the %s deadline: %s", held, described(conn.entries()))
				}
				letGo()
				waitFor(t, returned, "the release's return")
				waitNoneLabelled(t, label)
				journal := conn.entries()
				if len(journal) != 3 || journal[2].what != releasedMark {
					t.Fatalf("the connection has %s, want both deadlines and then the release", described(journal))
				}
				expectWoken(t, journal[:2], woken, goroutineID())
			})
		}
		t.Run("released after the wake has set both: nothing set after the release", func(t *testing.T) {
			t.Parallel()
			woken := wokenTime(t)
			conn := newWatched(t)
			ctx, cancel := context.WithCancel(t.Context())
			label := labelled(t.Context(), "", func() {})
			release := register(t, label, ctx, conn)
			labelled(t.Context(), label, cancel)
			waitFor(t, conn.writeSet, "the wake")
			release()
			conn.mark(releasedMark)
			waitNoneLabelled(t, label)
			journal := conn.entries()
			if len(journal) != 3 || journal[2].what != releasedMark {
				t.Fatalf("the connection has %s, want both deadlines and then the release", described(journal))
			}
			expectWoken(t, journal[:2], woken, goroutineID())
		})
		t.Run("released at once after the context ends: what the connection has when the release returns is what it keeps, nothing or both", func(t *testing.T) {
			t.Parallel()
			woken := wokenTime(t)
			conn := newWatched(t)
			ctx, cancel := context.WithCancel(t.Context())
			label := labelled(t.Context(), "", func() {})
			release := register(t, label, ctx, conn)
			labelled(t.Context(), label, func() {
				cancel()
				release()
			})
			conn.mark(releasedMark)
			waitNoneLabelled(t, label)
			journal := conn.entries()
			switch len(journal) {
			case 1:
				if journal[0].what != releasedMark {
					t.Fatalf("the connection has %s, want nothing before the release", described(journal))
				}
				expectWakesAtAll(t)
			case 3:
				if journal[2].what != releasedMark {
					t.Fatalf("the connection has %s, want both deadlines before the release and nothing after", described(journal))
				}
				expectWoken(t, journal[:2], woken, goroutineID())
			default:
				t.Fatalf("the connection has %s, want nothing or both deadlines before the release, and nothing after", described(journal))
			}
		})
	})
}
