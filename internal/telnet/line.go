// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package telnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// lineState keeps a read's error until the bytes that came with it are read, since the caller's
// last words arrive together with its closing and must not be lost to it.
type lineState struct {
	connection Conn
	// accepted is the connection Accept made this Line over: only Close needs it, to shut down the
	// sending side, and its being set is what makes a Line Accept's.
	accepted      *net.TCPConn
	negotiation   *Negotiation
	receiveBuffer [ReadBufferSize]byte
	receiveNext   int
	receiveEnd    int
	sendBuffer    [SendBufferSize]byte
	sendLength    int
	// urgentFrom and urgentTo bound the bytes of the send buffer that go out with WriteUrgent, the
	// Synchs owed; equal when there are none.
	urgentFrom  int
	urgentTo    int
	writeFailed bool
	readError   error
}

func open(ctx context.Context, connection Conn) (*Line, Outcome, error) {
	line := &Line{}
	state := &line.state
	negotiation, opening := newNegotiation()
	// The replies of a read cut short by its deadline are built straight into the send buffer and
	// the bytes after negotiation's end stay in the receive buffer, so nothing is copied.
	replyBuffer := (*[ReplyBufferSize]byte)(state.sendBuffer[:ReplyBufferSize])
	outcome, left, err := negotiateWith(
		ctx, connection, negotiation, opening, &state.receiveBuffer, replyBuffer)
	if err != nil {
		if errors.Is(err, ErrCallerClosed) {
			err = fmt.Errorf("%w: %w", err, io.EOF)
		}
		return nil, 0, err
	}
	state.connection = connection
	state.negotiation = negotiation
	state.sendLength = left.unwritten + left.urgent
	state.urgentFrom = left.unwritten
	state.urgentTo = left.unwritten + left.urgent
	state.receiveNext = left.from
	state.receiveEnd = left.readCount
	return line, outcome, nil
}

// usable is false for a Line that cannot be written through, so a misuse fails with an error and
// never with a nil dereference.
func (line *Line) usable() bool {
	return line != nil && line.state.connection != nil
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
	return fmt.Errorf("telnet: the call's context ended: %w", cause)
}

// judge reads a failure by what ended the call: a deadline that passed is the context's when the
// context has ended, since the connection cannot tell the two apart, and the call's own otherwise.
func judge(ctx context.Context, cause error) error {
	if ended := contextEnded(ctx); ended != nil {
		return ended
	}
	switch {
	case errors.Is(cause, io.EOF):
		return io.EOF
	case errors.Is(cause, os.ErrDeadlineExceeded):
		return os.ErrDeadlineExceeded
	}
	return fmt.Errorf("%w: %w", ErrConnectionFailed, cause)
}

// connectionDeadline is the earlier of the two because either ending must wake the call; none when
// neither has one, which clears any deadline an earlier call left.
func connectionDeadline(ctx context.Context, deadline time.Time) time.Time {
	contextDeadline, ok := ctx.Deadline()
	if ok && (deadline.IsZero() || contextDeadline.Before(deadline)) {
		return contextDeadline
	}
	return deadline
}

// check puts the context ending before a failed write so that a stop is reported as a stop, not as
// the failed write it caused by waking the call.
func (line *Line) check(ctx context.Context) error {
	if !line.usable() {
		return ErrConnectionFailed
	}
	if err := contextEnded(ctx); err != nil {
		return err
	}
	if line.state.writeFailed {
		return ErrConnectionFailed
	}
	return nil
}

// A failed write marks the Line failed whatever it got out, since what a write cut short sent
// cannot be known.
func (line *Line) writeOut(ctx context.Context, deadline time.Time) error {
	state := &line.state
	if state.sendLength == 0 {
		return nil
	}
	if err := state.connection.SetWriteDeadline(connectionDeadline(ctx, deadline)); err != nil {
		return fmt.Errorf("%w: %w", ErrConnectionFailed, err)
	}
	release := wakeOnEnd(ctx, state.connection)
	err := line.writeParts()
	release()
	if err != nil {
		state.writeFailed = true
		return judge(ctx, err)
	}
	state.sendLength = 0
	state.urgentFrom, state.urgentTo = 0, 0
	return nil
}

// writeParts writes the bytes before the urgent range, the range with WriteUrgent, then the bytes
// after it, so that a Synch follows every reply queued before it.
func (line *Line) writeParts() error {
	state := &line.state
	buffer := state.sendBuffer[:state.sendLength]
	from, to := state.urgentFrom, state.urgentTo
	if from == to {
		from, to = len(buffer), len(buffer)
	}
	parts := [...]struct {
		bytes  []byte
		urgent bool
	}{{buffer[:from], false}, {buffer[from:to], true}, {buffer[to:], false}}
	for _, part := range parts {
		if len(part.bytes) == 0 {
			continue
		}
		write := state.connection.Write
		if part.urgent {
			write = state.connection.WriteUrgent
		}
		count, err := write(part.bytes)
		if err == nil && count < len(part.bytes) {
			err = io.ErrShortWrite
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (line *Line) sendChar(ctx context.Context, character byte) error {
	if err := line.check(ctx); err != nil {
		return err
	}
	state := &line.state
	need := 1
	if character == TelnetIAC {
		need = 2
	}
	if SendBufferSize-state.sendLength < need {
		if err := line.writeOut(ctx, time.Time{}); err != nil {
			return err
		}
	}
	state.sendBuffer[state.sendLength] = character
	state.sendLength++
	if character == TelnetIAC {
		state.sendBuffer[state.sendLength] = character
		state.sendLength++
	}
	return nil
}

func (line *Line) flush(ctx context.Context) error {
	if err := line.check(ctx); err != nil {
		return err
	}
	return line.writeOut(ctx, time.Time{})
}

func (line *Line) recvChar(ctx context.Context, deadline time.Time) (byte, error) {
	for {
		if err := line.check(ctx); err != nil {
			return 0, err
		}
		state := &line.state
		// A stored end or failure happened before the deadline passed, so it is what ended the
		// read. While bytes are waiting the deadline comes first, so a caller who keeps sending
		// cannot hold a read past its deadline.
		if state.receiveNext >= state.receiveEnd && state.readError != nil {
			return 0, state.readError
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return 0, os.ErrDeadlineExceeded
		}
		if state.receiveNext < state.receiveEnd {
			if SendBufferSize-state.sendLength < MostReply {
				if err := line.writeOut(ctx, deadline); err != nil {
					return 0, err
				}
				continue
			}
			character := state.receiveBuffer[state.receiveNext]
			state.receiveNext++
			queued := state.sendBuffer[:state.sendLength:SendBufferSize]
			queued, handOn, isData := state.negotiation.Strip(character, queued)
			state.sendLength = len(queued)
			if err := line.sendSynch(ctx, deadline); err != nil {
				return 0, err
			}
			if isData {
				return handOn, nil
			}
			continue
		}
		if err := line.writeOut(ctx, deadline); err != nil {
			return 0, err
		}
		if err := line.readMore(ctx, deadline); err != nil {
			return 0, err
		}
	}
}

// readMore reads into the empty receive buffer. A read's error is kept for when its bytes have
// been read, only if it ends the stream: a passed deadline or an ended context is judged afresh
// at the next step.
func (line *Line) readMore(ctx context.Context, deadline time.Time) error {
	state := &line.state
	if err := state.connection.SetReadDeadline(connectionDeadline(ctx, deadline)); err != nil {
		return fmt.Errorf("%w: %w", ErrConnectionFailed, err)
	}
	release := wakeOnEnd(ctx, state.connection)
	count, err := state.connection.Read(state.receiveBuffer[:])
	release()
	state.receiveNext, state.receiveEnd = 0, count
	if err != nil {
		judged := judge(ctx, err)
		if errors.Is(judged, io.EOF) || errors.Is(judged, ErrConnectionFailed) {
			state.readError = judged
		}
	}
	return nil
}

// sendSynch writes a Synch the byte just stripped owed, after every reply queued before it and
// before the next byte is stripped, since one range of the send buffer goes out with WriteUrgent.
func (line *Line) sendSynch(ctx context.Context, deadline time.Time) error {
	state := &line.state
	owed := state.negotiation.TakeSynch()
	if owed == 0 {
		return nil
	}
	if state.urgentTo > state.urgentFrom {
		if err := line.writeOut(ctx, deadline); err != nil {
			return err
		}
	}
	state.urgentFrom = state.sendLength
	state.sendLength = len(synchBytes(state.sendBuffer[:state.sendLength:SendBufferSize], owed))
	state.urgentTo = state.sendLength
	return line.writeOut(ctx, deadline)
}

func (line *Line) echoes() bool {
	return line.usable() && line.state.negotiation.state.current(slotEcho) == stateYes
}

func (line *Line) close(ctx context.Context) error {
	if !line.usable() || line.state.accepted == nil {
		return ErrConnectionFailed
	}
	if err := contextEnded(ctx); err != nil {
		return err
	}
	connection := line.state.accepted
	if err := connection.CloseWrite(); err != nil {
		return fmt.Errorf("%w: %w", ErrConnectionFailed, err)
	}
	waitEnd := time.Now().Add(ClosingWaitSeconds * time.Second)
	if err := connection.SetReadDeadline(connectionDeadline(ctx, waitEnd)); err != nil {
		return fmt.Errorf("%w: %w", ErrConnectionFailed, err)
	}
	release := wakeOnEnd(ctx, line.state.connection)
	defer release()
	var discard [DiscardBufferSize]byte
	for {
		if _, err := connection.Read(discard[:]); err != nil {
			return contextEnded(ctx)
		}
	}
}
