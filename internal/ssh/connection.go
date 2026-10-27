// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package ssh

import (
	"context"
	"fmt"
	"net"
	"time"
)

// wokenDeadline is long past, so that setting it wakes any read or write that is waiting.
var wokenDeadline = time.Unix(1, 0)

// connection is what the Accept call and its Channel share about one connection: when it ended.
// It holds nothing the caller sent.
type connection struct {
	// ended is closed once the library has torn the connection down, after it has marked the end
	// of every channel's data.
	ended chan struct{}
}

func newConnection() *connection {
	return &connection{ended: make(chan struct{})}
}

func (connection *connection) hasEnded() bool {
	select {
	case <-connection.ended:
		return true
	default:
		return false
	}
}

// endedCause lets the clock judge the deadline, since a connection's deadline can wake a call
// before the context's own timer reports that the context has ended.
func endedCause(ctx context.Context) error {
	if cause := ctx.Err(); cause != nil {
		return cause
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func contextEnded(ctx context.Context) error {
	cause := endedCause(ctx)
	if cause == nil {
		return nil
	}
	return fmt.Errorf("ssh: the call's context ended: %w", cause)
}

func deadlineEnded(cause error) error {
	return fmt.Errorf("%w: %w", ErrDeadlineEnded, cause)
}

// wakeOnEnd makes a read or write that is waiting return when ctx ends, by setting both deadlines
// long past. The release it returns waits for a wake-up that has started, so nothing of the
// package's runs once the call that registered it returns.
func wakeOnEnd(ctx context.Context, socket net.Conn) (release func()) {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		wake(socket)
	})
	return func() {
		if !stop() {
			<-done
		}
	}
}

// wake passes the deadlines because a read or write blocked in the library returns only when its
// socket's deadline passes.
func wake(socket net.Conn) {
	//nolint:errcheck // a socket that cannot be set is failing, and its end reaches every call
	socket.SetDeadline(wokenDeadline)
}

// waitLimit is the timer for a wait that ends at the earlier of the deadline and the context's.
func waitLimit(ctx context.Context, deadline time.Time) (<-chan time.Time, func()) {
	limit := deadline
	if contextDeadline, ok := ctx.Deadline(); ok && (limit.IsZero() || contextDeadline.Before(limit)) {
		limit = contextDeadline
	}
	if limit.IsZero() {
		return nil, func() {}
	}
	timer := time.NewTimer(time.Until(limit))
	return timer.C, func() { timer.Stop() }
}
