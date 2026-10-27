// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package timeup holds, once, the rule for whether a call's time has run out, the time a call must
// stop by, and the wake that makes a waiting read or write return when its time has run out, for
// every unit that reads or writes a caller's connection: Telnet, SSH and Text I/O.
//
// It owns judging a call's context by the clock as well as by the context's own report, the earlier
// of a call's own deadline and its context's, and setting a connection's read and write deadlines
// long past so that a read or write waiting on it returns. It does not own what a unit returns to
// its caller: each unit turns Ended's answer into its own result, as its own contract says, so no
// caller sees a change. It does not own a unit's timers: a unit that waits on a timer makes it from
// Limit's answer. It writes nothing to the local log, stores nothing and keeps nothing between
// calls.
//
// What the engine does as a whole, this package included, is in docs/behavior.md.
//
// # Lines for the package
//
//   - The timeup package shall write nothing to standard output or standard error. [read]
//   - The timeup package shall import nothing outside the Go standard library. [read]
package timeup

import (
	"context"
	"time"
)

// Conn is a connection whose waiting read or write returns once a deadline set on it has passed;
// an accepted net.Conn satisfies it, and so does each kind of connection's own Conn built on one.
type Conn interface {
	// SetReadDeadline wakes a read that is waiting when the deadline has passed; zero clears it.
	SetReadDeadline(deadline time.Time) error
	// SetWriteDeadline wakes a write that is waiting when the deadline has passed; zero clears
	// it.
	SetWriteDeadline(deadline time.Time) error
}

// Ended returns why the call's time has run out, or nil while it has not. A connection's deadline
// can wake a call before the context's own timer reports that the context has ended, so the clock
// judges the deadline too.
//
//   - If the context reports that it has ended, then Ended shall return the context's own error,
//     context.Canceled or context.DeadlineExceeded, unwrapped.
//   - If the context has not reported its end and its deadline is not after the clock's time,
//     then Ended shall return context.DeadlineExceeded.
//   - While the context has not reported its end and has no deadline, or a deadline after the
//     clock's time, Ended shall return nil.
func Ended(ctx context.Context) error {
	return ended(ctx)
}

// Limit returns the time a call must stop by: the earlier of deadline and the context's deadline.
// A zero deadline means the call has none of its own.
//
//   - When deadline is not zero and the context has a deadline, Limit shall return the earlier of
//     the two.
//   - When deadline is zero, Limit shall return the context's deadline, or the zero time when the
//     context has none.
//   - When the context has no deadline, Limit shall return deadline.
func Limit(ctx context.Context, deadline time.Time) time.Time {
	return limit(ctx, deadline)
}

// Wake sets both of conn's deadlines long past, so a read or write waiting on it returns now. It
// is for a call that must wake the connection itself, such as after a release that stopped a wake
// not yet begun.
//
//   - Wake shall set conn's read deadline and then its write deadline to the same fixed time long
//     past, setting the write deadline even when setting the read deadline fails.
//   - Wake shall never set the zero time, which clears a deadline instead of waking a call.
//   - Wake shall return nil when both are set, and otherwise each failure, joined with
//     errors.Join.
func Wake(conn Conn) error {
	return wake(conn)
}

// WakeOnEnd makes a read or write waiting on conn return once ctx ends, by calling Wake. A call
// registers it after it sets the deadline the wake must override, and calls the release it returns
// once, before the call returns; calling a release a second time is a wrong call. The wake has
// begun once the release can no longer stop it.
//
//   - WakeOnEnd shall start no goroutine before ctx ends.
//   - Once ctx has ended, WakeOnEnd shall begin the wake, which calls Wake on conn once, in a
//     goroutine of its own, unless the release has stopped it before it began.
//   - If ctx has already ended when WakeOnEnd is called, then the wake shall have begun when
//     WakeOnEnd returns.
//   - If Wake returns an error, then the wake shall drop it: the call's time has already run out,
//     and each unit reports that, whatever the connection does next.
//   - When the release returns, no wake shall be running and none shall begin afterwards: the
//     release stops a wake that has not begun, and waits for one that has begun to end.
func WakeOnEnd(ctx context.Context, conn Conn) (release func()) {
	return wakeOnEnd(ctx, conn)
}
