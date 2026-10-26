// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// wokenDeadline is long past, so that setting it wakes any read or write that is waiting.
var wokenDeadline = time.Unix(1, 0)

// disconnectPrefix starts the text the library gives for a disconnect message the caller sent. The
// type is unexported, so the text is the only way to know the caller ended the connection on
// purpose; the text itself is never passed on.
const disconnectPrefix = "ssh: disconnect, reason"

// connection is what the Accept call and its Channel share about one connection: why it ended, in
// the engine's own record, and when. It holds nothing the caller sent.
type connection struct {
	// ended is closed once the library has torn the connection down, after it has marked the end
	// of every channel's data.
	ended chan struct{}

	mutex sync.Mutex
	// socketError is the first error a read of the socket returned, recorded before the library
	// sees it: the library reports a caller's close and a reset alike as an end of file.
	socketError error
	// noted is a failure the engine itself met while answering the library.
	noted error
	// endError is what the library ended the connection with.
	endError error
}

func newConnection() *connection {
	return &connection{ended: make(chan struct{})}
}

func (connection *connection) recordSocketError(err error) {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	if connection.socketError == nil {
		connection.socketError = err
	}
}

func (connection *connection) note(err error) {
	if err == nil {
		return
	}
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	if connection.noted == nil {
		connection.noted = err
	}
}

func (connection *connection) finish(err error) {
	connection.mutex.Lock()
	connection.endError = err
	connection.mutex.Unlock()
	close(connection.ended)
}

func (connection *connection) hasEnded() bool {
	select {
	case <-connection.ended:
		return true
	default:
		return false
	}
}

// socketClosed is whether the socket ended in order.
func (connection *connection) socketClosed() bool {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	return errors.Is(connection.socketError, io.EOF)
}

// failed is whether the engine knows the connection failed, as the caller closing it is not.
func (connection *connection) failed() bool {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	if connection.socketError != nil && !errors.Is(connection.socketError, io.EOF) {
		return true
	}
	if connection.noted != nil {
		return true
	}
	if connection.endError == nil || errors.Is(connection.endError, io.EOF) {
		return false
	}
	return !disconnected(connection.endError)
}

// disconnected is whether err is the library's report of a disconnect message the caller sent.
func disconnected(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), disconnectPrefix)
}

// callerClosed is the error for a caller that ended its side in order.
func callerClosed() error {
	return fmt.Errorf("%w: %w", ErrCallerClosed, io.EOF)
}

// sessionEnd reads how a connection or its session ended, once the session has no more to give.
func (connection *connection) sessionEnd() error {
	if connection.failed() {
		return ErrConnectionFailed
	}
	return callerClosed()
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

// recordingConn records the first error the socket's reads return, before the library sees it.
type recordingConn struct {
	net.Conn
	owner *connection
}

func (socket recordingConn) Read(buffer []byte) (int, error) {
	count, err := socket.Conn.Read(buffer)
	if err != nil {
		socket.owner.recordSocketError(err)
	}
	return count, err
}

// wakeOnEnd makes a read or write that is waiting return when ctx ends, by setting both deadlines
// long past. The release it returns waits for a wake-up that has started, so nothing of the
// package's runs once the call that registered it returns.
func (connection *connection) wakeOnEnd(ctx context.Context, socket net.Conn) (release func()) {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		connection.note(errors.Join(
			socket.SetReadDeadline(wokenDeadline), socket.SetWriteDeadline(wokenDeadline)))
	})
	return func() {
		if !stop() {
			<-done
		}
	}
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
