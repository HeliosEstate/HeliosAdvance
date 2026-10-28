// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package timeup

import (
	"context"
	"errors"
	"time"
)

// The contract's operations hand their work to the unexported functions below, so the contract
// builds before the package is built and the build never needs to change the contract.

// wokenDeadline is long past and never zero, which would clear a deadline instead of waking a
// call.
var wokenDeadline = time.Unix(1, 0)

// ended lets the clock judge the deadline, since a connection's deadline can wake a call before
// the context's own timer reports that the context has ended.
func ended(ctx context.Context) error {
	if cause := ctx.Err(); cause != nil {
		return cause
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// limit is the earlier of the two because either ending must wake the call; it returns the zero
// time when neither has one.
func limit(ctx context.Context, deadline time.Time) time.Time {
	contextDeadline, ok := ctx.Deadline()
	if ok && (deadline.IsZero() || contextDeadline.Before(deadline)) {
		return contextDeadline
	}
	return deadline
}

// wake sets the write deadline even when the read one fails, so that a wake reaches both.
func wake(conn Conn) error {
	readErr := conn.SetReadDeadline(wokenDeadline)
	writeErr := conn.SetWriteDeadline(wokenDeadline)
	return errors.Join(readErr, writeErr)
}

// wakeOnEnd starts nothing before ctx ends: context.AfterFunc registers with the context package's
// own contexts without a goroutine. The release waits for a wake that has begun, so nothing of the
// package's runs once the call that registered it returns.
func wakeOnEnd(ctx context.Context, conn Conn) (release func()) {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		//nolint:errcheck // the connection may already be closed, and there is no one to tell
		wake(conn)
	})
	return func() {
		if !stop() {
			<-done
		}
	}
}
