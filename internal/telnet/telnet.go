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
// option, so a caller cannot make the engine remember more by asking for more.
type negotiationState struct {
	echo     optionState
	goAhead  optionState
	phase    readPhase
	heldVerb byte
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
	state := &negotiation.state
	for _, value := range input {
		if state.answered() {
			break
		}
		replies = state.readByte(value, replies)
	}
	return replies, state.answered()
}

func (state *negotiationState) readByte(value byte, replies []byte) []byte {
	switch state.phase {
	case phaseData:
		if value == TelnetIAC {
			state.phase = phaseAfterIAC
		}
	case phaseAfterIAC:
		switch value {
		case TelnetWILL, TelnetWONT, TelnetDO, TelnetDONT:
			state.heldVerb = value
			state.phase = phaseAfterVerb
		case TelnetSB:
			state.phase = phaseSubnegotiation
		default:
			state.phase = phaseData
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
	return replies
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

func negotiate(ctx context.Context, connection Conn) (Outcome, error) {
	var stopWake func() bool
	wakeDone := make(chan struct{})

	finish := func(outcome Outcome, err error) (Outcome, error) {
		if stopWake != nil && !stopWake() {
			<-wakeDone
		}
		deadline, _ := ctx.Deadline()
		if setErr := setDeadlines(connection, deadline); setErr != nil && err == nil {
			return failure(ctx, setErr)
		}
		return outcome, err
	}

	if err := ctx.Err(); err != nil {
		return finish(0, endedBy(err))
	}

	negotiation, opening := newNegotiation()
	start := time.Now()
	deadline := start.Add(NegotiationSeconds * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := setDeadlines(connection, deadline); err != nil {
		return finish(failure(ctx, err))
	}

	// Registered after the first deadlines are set, so they can never overwrite the wake-up.
	stopWake = context.AfterFunc(ctx, func() {
		defer close(wakeDone)
		//nolint:errcheck // the connection may already be closed, and there is no one to tell
		setDeadlines(connection, wokenDeadline)
	})

	if _, err := connection.Write(opening[:]); err != nil {
		return finish(failure(ctx, err))
	}

	var readBuffer [ReadBufferSize]byte
	var replyBuffer [ReplyBufferSize]byte
	for {
		count, readErr := connection.Read(readBuffer[:])
		replies, answered := negotiation.Receive(readBuffer[:count], replyBuffer[:0])
		if readErr != nil {
			return finish(failure(ctx, readErr))
		}
		if len(replies) > 0 {
			if _, err := connection.Write(replies); err != nil {
				return finish(failure(ctx, err))
			}
		}
		if answered {
			// A stop that lands as the last answer is read must win, or the caller of
			// Negotiate would go on to write to a connection that is being closed.
			if ended := ctx.Err(); ended != nil {
				return finish(0, endedBy(ended))
			}
			return finish(Answered, nil)
		}
	}
}

// setDeadlines sets both deadlines even when the first fails, so that a wake-up reaches both.
func setDeadlines(connection Conn, deadline time.Time) error {
	readErr := connection.SetReadDeadline(deadline)
	writeErr := connection.SetWriteDeadline(deadline)
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
