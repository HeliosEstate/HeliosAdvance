// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package telnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// The contract's operations hand their work to the unexported functions below, so the contract
// builds before the package is built and the build never needs to change the contract.

// optionState is the RFC 1143 state of one option on the engine's side. Its zero is WANTYES: the
// opening request is outstanding, which is what a Negotiation not made by New must start as.
type optionState uint8

const (
	stateWantYes optionState = iota
	stateYes
	stateNo
)

// readPhase is kept between calls because a sequence can be split across them, and Receive must
// then answer as if it had come whole. Its zero is plain data, the state a fresh stream is in.
type readPhase uint8

const (
	phaseData readPhase = iota
	phaseAfterIAC
	phaseAfterVerb
	phaseSubnegotiation
	phaseSubnegotiationIAC
)

// negotiationState has a field for ECHO and SGA only: the contract forbids a state for any other
// option, so a caller cannot make the engine remember more by asking for more. The last two fields
// are false in a zero Negotiation: once Strip has taken over, Receive keeps what it returned
// before, because Strip can change the option states it would otherwise be read from.
type negotiationState struct {
	echo             optionState
	goAhead          optionState
	phase            readPhase
	heldVerb         byte
	handedOver       bool
	handedOverReturn bool
}

func newNegotiation() (*Negotiation, [6]byte) {
	opening := [6]byte{
		TelnetIAC, TelnetWILL, OptionEcho,
		TelnetIAC, TelnetWILL, OptionSuppressGoAhead,
	}
	return &Negotiation{}, opening
}

// answered is derived from the two states so that a zero Negotiation needs no stored flag.
func (state *negotiationState) answered() bool {
	return state.echo != stateWantYes && state.goAhead != stateWantYes
}

func (negotiation *Negotiation) receive(input, replies []byte) ([]byte, bool) {
	replies, answered, _ := negotiation.receiveCounting(input, replies)
	return replies, answered
}

// receiveCounting also returns how many bytes of input it read before negotiation ended, so that
// Open can tell negotiation's bytes from the Line's.
func (negotiation *Negotiation) receiveCounting(input, replies []byte) ([]byte, bool, int) {
	state := &negotiation.state
	if state.handedOver {
		return replies, state.handedOverReturn, 0
	}
	read := 0
	for _, value := range input {
		if state.answered() {
			break
		}
		replies, _ = state.readByte(value, replies)
		read++
	}
	return replies, state.answered(), read
}

func (negotiation *Negotiation) strip(character byte, replies []byte) ([]byte, bool) {
	state := &negotiation.state
	if !state.handedOver {
		state.handedOver = true
		state.handedOverReturn = state.answered()
	}
	return state.readByte(character, replies)
}

// readByte is the one table Receive and Strip both run, so a later option is added in one place.
// Its second result is whether the byte is data: a byte outside every command, or the second IAC
// of IAC IAC.
func (state *negotiationState) readByte(value byte, replies []byte) ([]byte, bool) {
	isData := false
	switch state.phase {
	case phaseData:
		if value == TelnetIAC {
			state.phase = phaseAfterIAC
		} else {
			isData = true
		}
	case phaseAfterIAC:
		state.phase = phaseData
		switch value {
		case TelnetWILL, TelnetWONT, TelnetDO, TelnetDONT:
			state.heldVerb = value
			state.phase = phaseAfterVerb
		case TelnetSB:
			state.phase = phaseSubnegotiation
		case TelnetIAC:
			isData = true
		}
	case phaseAfterVerb:
		state.phase = phaseData
		replies = state.answer(state.heldVerb, value, replies)
	case phaseSubnegotiation:
		if value == TelnetIAC {
			state.phase = phaseSubnegotiationIAC
		}
	case phaseSubnegotiationIAC:
		if value == TelnetSE {
			state.phase = phaseData
		} else {
			state.phase = phaseSubnegotiation
		}
	}
	return replies, isData
}

// answer follows RFC 1143 section 7 so that a caller who repeats or contradicts a request cannot
// start a reply loop; an option the engine does not offer is refused from the verb alone, so it
// costs no state.
func (state *negotiationState) answer(verb, option byte, replies []byte) []byte {
	var current *optionState
	switch option {
	case OptionEcho:
		current = &state.echo
	case OptionSuppressGoAhead:
		current = &state.goAhead
	}
	switch verb {
	case TelnetWILL:
		return append(replies, TelnetIAC, TelnetDONT, option)
	case TelnetDO:
		if current == nil {
			return append(replies, TelnetIAC, TelnetWONT, option)
		}
		switch *current {
		case stateWantYes:
			*current = stateYes
		case stateNo:
			*current = stateYes
			return append(replies, TelnetIAC, TelnetWILL, option)
		}
	case TelnetDONT:
		if current == nil {
			return replies
		}
		switch *current {
		case stateWantYes:
			*current = stateNo
		case stateYes:
			*current = stateNo
			return append(replies, TelnetIAC, TelnetWONT, option)
		}
	}
	return replies
}

// wokenDeadline is long past, so that setting it wakes any read or write that is waiting.
var wokenDeadline = time.Unix(1, 0)

// wakeOnEnd makes a read or write that is waiting return when ctx ends, by setting both deadlines
// long past. The release it returns waits for a wake-up that has started, so nothing of the
// package's runs once the call that registered it returns. It is registered after the deadline it
// must override is set.
func wakeOnEnd(ctx context.Context, connection Conn) (release func()) {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		//nolint:errcheck // the connection may already be closed, and there is no one to tell
		setDeadlines(connection, wokenDeadline, wokenDeadline)
	})
	return func() {
		if !stop() {
			<-done
		}
	}
}

// handOver is what Open takes from negotiation so that nothing is copied or lost: the last read's
// bytes from index from to readCount, and the replies of a read cut short by its deadline, which
// were never written and go out first.
type handOver struct {
	readCount int
	from      int
	unwritten int
}

func negotiate(ctx context.Context, connection Conn) (Outcome, error) {
	var readBuffer [ReadBufferSize]byte
	var replyBuffer [ReplyBufferSize]byte
	negotiation, opening := newNegotiation()
	outcome, _, err := negotiateWith(ctx, connection, negotiation, opening, &readBuffer, &replyBuffer)
	return outcome, err
}

// negotiateWith is the one negotiation of Negotiate and Open. The buffers are the caller's so that
// Open can read into the Line's own and leave what is not negotiation's where the Line finds it.
func negotiateWith(
	ctx context.Context, connection Conn, negotiation *Negotiation, opening [6]byte,
	readBuffer *[ReadBufferSize]byte, replyBuffer *[ReplyBufferSize]byte,
) (Outcome, handOver, error) {
	var release func()
	finish := func(outcome Outcome, left handOver, err error) (Outcome, handOver, error) {
		if release != nil {
			release()
		}
		deadline, _ := ctx.Deadline()
		if setErr := setDeadlines(connection, deadline, deadline); setErr != nil && err == nil {
			outcome, err = failure(ctx, setErr)
		}
		return outcome, left, err
	}
	fail := func(err error) (Outcome, handOver, error) {
		outcome, failed := failure(ctx, err)
		return finish(outcome, handOver{}, failed)
	}

	if err := ctx.Err(); err != nil {
		return finish(0, handOver{}, endedBy(err))
	}

	timeout := time.Now().Add(NegotiationSeconds * time.Second)
	readDeadline := connectionDeadline(ctx, timeout)
	writeDeadline := connectionDeadline(ctx, time.Time{})
	if err := setDeadlines(connection, readDeadline, writeDeadline); err != nil {
		return fail(err)
	}

	// Registered after the first deadlines are set, so they can never overwrite the wake-up.
	release = wakeOnEnd(ctx, connection)

	// The three seconds end only a read that waits, never a write, so a write that ends with them
	// passed is where negotiation stops, without a read after it.
	endAtTimeout := func(left handOver) (Outcome, handOver, error) {
		if contextDeadline, ok := ctx.Deadline(); ok && !time.Now().Before(contextDeadline) {
			return finish(0, handOver{}, endedBy(context.DeadlineExceeded))
		}
		return finish(TimedOut, left, nil)
	}

	if _, err := connection.Write(opening[:]); err != nil {
		return fail(err)
	}
	if !time.Now().Before(timeout) {
		return endAtTimeout(handOver{})
	}

	for {
		count, readErr := connection.Read(readBuffer[:])
		replies, answered, used := negotiation.receiveCounting(readBuffer[:count], replyBuffer[:0])
		left := handOver{readCount: count, from: count}
		if answered {
			left.from = used
		}
		if readErr != nil {
			outcome, failed := failure(ctx, readErr)
			if failed == nil && outcome == TimedOut {
				left.unwritten = len(replies)
			}
			return finish(outcome, left, failed)
		}
		if len(replies) > 0 {
			if _, err := connection.Write(replies); err != nil {
				return fail(err)
			}
		}
		if answered {
			return finish(Answered, left, nil)
		}
		if !time.Now().Before(timeout) {
			return endAtTimeout(left)
		}
	}
}

// setDeadlines sets both deadlines even when the first fails, so that a wake-up reaches both.
func setDeadlines(connection Conn, read, write time.Time) error {
	readErr := connection.SetReadDeadline(read)
	writeErr := connection.SetWriteDeadline(write)
	return errors.Join(readErr, writeErr)
}

func endedBy(cause error) error {
	return fmt.Errorf("%w: %w", ErrDeadlineEnded, cause)
}

// failure turns a failed read, write or deadline setting into Negotiate's result. A passed
// deadline is told apart by the clock, because the context may not have reported its end yet.
func failure(ctx context.Context, cause error) (Outcome, error) {
	if ended := ctx.Err(); ended != nil {
		return 0, endedBy(ended)
	}
	switch {
	case errors.Is(cause, io.EOF):
		return 0, ErrCallerClosed
	case errors.Is(cause, os.ErrDeadlineExceeded):
		if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
			return 0, endedBy(context.DeadlineExceeded)
		}
		return TimedOut, nil
	}
	return 0, fmt.Errorf("%w: %w", ErrConnectionFailed, cause)
}
