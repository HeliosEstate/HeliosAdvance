// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package ssh

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

// readResult is what one read of the library's channel returned.
type readResult struct {
	count int
	err   error
}

// channelState is owned by the one goroutine that calls the Channel, except what the two helper
// goroutines below touch, which the hand-offs keep apart: the reader fills only the receive
// buffer's free tail while it is asked to, and the writer reads the send buffer only while a call
// waits on it.
type channelState struct {
	library    cryptossh.Channel
	connection *connection
	echo       bool

	receive     [ReadBufferSize]byte
	receiveNext int
	receiveEnd  int
	readError   error
	reading     bool
	asks        chan int
	results     chan readResult
	readerDone  chan struct{}

	send       [SendBufferSize]byte
	sendLength int
	failed     bool
	jobs       chan func() error
	written    chan error
}

func newChannelState(library cryptossh.Channel, connection *connection) channelState {
	return channelState{
		library:    library,
		connection: connection,
		asks:       make(chan int, 1),
		results:    make(chan readResult, 1),
		readerDone: make(chan struct{}),
		jobs:       make(chan func() error),
		written:    make(chan error, 1),
	}
}

// readLoop reads one time per ask, since a library read waits for the caller with no deadline and
// the receive buffer must never hold more than its size. It ends with the connection, after it
// has finished a read it was asked for.
func (state *channelState) readLoop() {
	defer close(state.readerDone)
	for {
		select {
		case from := <-state.asks:
			state.readOnce(from)
		case <-state.connection.ended:
			select {
			case from := <-state.asks:
				state.readOnce(from)
			default:
			}
			return
		}
	}
}

func (state *channelState) readOnce(from int) {
	count, err := state.library.Read(state.receive[from:])
	state.results <- readResult{count, err}
}

// writeLoop makes every library write, since a library write waits on the caller's window with no
// deadline and the call that wants it must be free to give up.
func (state *channelState) writeLoop() {
	for {
		select {
		case job := <-state.jobs:
			state.written <- job()
		case <-state.connection.ended:
			return
		}
	}
}

// drainExtended reads and discards the caller's stderr-coded data through a fixed buffer: the
// library keeps that code against the window, and discards every other code itself.
func (state *channelState) drainExtended() {
	var discard [ReadBufferSize]byte
	for {
		if _, err := state.library.Stderr().Read(discard[:]); err != nil {
			return
		}
	}
}

func (channel *Channel) usable() bool {
	return channel != nil && channel.state.library != nil
}

func (channel *Channel) check(ctx context.Context) error {
	if !channel.usable() {
		return ErrConnectionFailed
	}
	if err := contextEnded(ctx); err != nil {
		return err
	}
	if channel.state.failed {
		return ErrConnectionFailed
	}
	return nil
}

// write hands job to the writer and waits for it. A wait that ends before the job does counts as a
// failed write, since what it handed the library may still go out.
func (channel *Channel) write(ctx context.Context, deadline time.Time, job func() error) error {
	state := &channel.state
	limit, stop := waitLimit(ctx, deadline)
	defer stop()
	giveUp := func(err error) error {
		state.failed = true
		if ended := contextEnded(ctx); ended != nil {
			return ended
		}
		return err
	}
	select {
	case state.jobs <- job:
	case <-state.connection.ended:
		return giveUp(ErrConnectionFailed)
	case <-ctx.Done():
		return giveUp(ErrConnectionFailed)
	case <-limit:
		return giveUp(os.ErrDeadlineExceeded)
	}
	select {
	case err := <-state.written:
		if err != nil {
			return giveUp(ErrConnectionFailed)
		}
		return nil
	case <-state.connection.ended:
		select {
		case err := <-state.written:
			if err == nil {
				return nil
			}
		default:
		}
		return giveUp(ErrConnectionFailed)
	case <-ctx.Done():
		return giveUp(ErrConnectionFailed)
	case <-limit:
		return giveUp(os.ErrDeadlineExceeded)
	}
}

func (channel *Channel) writeOut(ctx context.Context, deadline time.Time) error {
	state := &channel.state
	if state.sendLength == 0 {
		return nil
	}
	length := state.sendLength
	err := channel.write(ctx, deadline, func() error {
		_, err := state.library.Write(state.send[:length])
		return err
	})
	if err != nil {
		return err
	}
	state.sendLength = 0
	return nil
}

func (channel *Channel) sendChar(ctx context.Context, character byte) error {
	if err := channel.check(ctx); err != nil {
		return err
	}
	state := &channel.state
	if state.sendLength == SendBufferSize {
		if err := channel.writeOut(ctx, time.Time{}); err != nil {
			return err
		}
	}
	state.send[state.sendLength] = character
	state.sendLength++
	return nil
}

func (channel *Channel) flush(ctx context.Context) error {
	if err := channel.check(ctx); err != nil {
		return err
	}
	return channel.writeOut(ctx, time.Time{})
}

// askRead lets the reader fill the free tail of the receive buffer, once, if there is room.
func (state *channelState) askRead() {
	if state.reading || state.readError != nil {
		return
	}
	if state.receiveNext == state.receiveEnd {
		state.receiveNext, state.receiveEnd = 0, 0
	}
	if state.receiveEnd == len(state.receive) {
		return
	}
	state.reading = true
	state.asks <- state.receiveEnd
}

func (state *channelState) absorb(result readResult) {
	state.reading = false
	state.receiveEnd += result.count
	if result.err != nil {
		state.readError = result.err
	}
}

// readAfterEnd takes what the library still holds once the connection has ended: it no longer
// waits then, because the library marks the end of every channel's data before the connection's
// end is seen. The reader is done first, so that nothing else reads.
func (state *channelState) readAfterEnd() {
	<-state.readerDone
	select {
	case result := <-state.results:
		state.absorb(result)
	default:
		state.reading = false
	}
	if state.readError != nil {
		return
	}
	if state.receiveNext == state.receiveEnd {
		state.receiveNext, state.receiveEnd = 0, 0
	}
	if state.receiveEnd == len(state.receive) {
		return
	}
	count, err := state.library.Read(state.receive[state.receiveEnd:])
	state.absorb(readResult{count, err})
}

// readFailure reads a stored end by the socket's own error: a reset is a failure, whatever the
// library says.
func (state *channelState) readFailure() error {
	if state.connection.failed() {
		return ErrConnectionFailed
	}
	if errors.Is(state.readError, io.EOF) {
		return io.EOF
	}
	return ErrConnectionFailed
}

func (channel *Channel) recvChar(ctx context.Context, deadline time.Time) (byte, error) {
	if !channel.usable() {
		return 0, ErrConnectionFailed
	}
	state := &channel.state
	for {
		if err := channel.check(ctx); err != nil {
			return 0, err
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return 0, os.ErrDeadlineExceeded
		}
		if state.receiveNext < state.receiveEnd {
			character := state.receive[state.receiveNext]
			state.receiveNext++
			return character, nil
		}
		if state.readError != nil {
			return 0, state.readFailure()
		}
		if err := channel.writeOut(ctx, deadline); err != nil {
			return 0, err
		}
		channel.awaitRead(ctx, deadline)
	}
}

// awaitRead waits for the reader's result, the connection's end, the context's end or the
// deadline, and leaves judging the last two to the caller's next step.
func (channel *Channel) awaitRead(ctx context.Context, deadline time.Time) {
	state := &channel.state
	if state.connection.hasEnded() {
		state.readAfterEnd()
		return
	}
	state.askRead()
	limit, stop := waitLimit(ctx, deadline)
	defer stop()
	select {
	case result := <-state.results:
		state.absorb(result)
	case <-state.connection.ended:
		state.readAfterEnd()
	case <-ctx.Done():
	case <-limit:
	}
}

func (channel *Channel) echoes() bool {
	return channel.usable() && channel.state.echo
}

// exitStatusPayload is exit-status 0 as RFC 4254 section 6.10 lays it out.
type exitStatusPayload struct {
	Status uint32
}

func (channel *Channel) close(ctx context.Context) error {
	if !channel.usable() {
		return ErrConnectionFailed
	}
	if err := contextEnded(ctx); err != nil {
		return err
	}
	state := &channel.state
	if state.failed {
		return ErrConnectionFailed
	}
	length := state.sendLength
	err := channel.write(ctx, time.Time{}, func() error {
		if length > 0 {
			if _, err := state.library.Write(state.send[:length]); err != nil {
				return err
			}
		}
		_, err := state.library.SendRequest("exit-status", false,
			cryptossh.Marshal(exitStatusPayload{Status: 0}))
		if err != nil {
			return err
		}
		if err := state.library.CloseWrite(); err != nil {
			return err
		}
		return state.library.Close()
	})
	if err != nil {
		return err
	}
	state.sendLength = 0

	limit, stop := waitLimit(ctx, time.Now().Add(ClosingWaitSeconds*time.Second))
	defer stop()
	select {
	case <-state.connection.ended:
		return nil
	case <-ctx.Done():
	case <-limit:
	}
	return contextEnded(ctx)
}
