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

	"github.com/heliosestate/heliosadvance/internal/timeup"
)

// The contract's operations hand their work to the unexported functions below, so the contract
// builds before the package is built and the build never needs to change the contract.

// optionState is the RFC 1143 state of one option on one side. Its zero is not a state: it stands
// for the state the opening left that option in, so a Negotiation not made by New starts as New's
// does.
type optionState uint8

const (
	stateOpening optionState = iota
	stateWantYes
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

// optionSlot is one row of the option table: the contract forbids a state for any other option,
// so a caller cannot make the engine remember more by asking for more.
type optionSlot struct {
	option byte
	// engineSide is whether the option is the engine's own (answered to DO and DONT) or the
	// caller's (answered to WILL and WONT).
	engineSide bool
	// asked is whether the opening requests it; the opening is built from the rows that do.
	asked bool
	// send is the subnegotiation that asks the caller for its answer, once, when the option is
	// agreed.
	send string
}

const (
	sendTerminalType  = "\xff\xfa\x18\x01\xff\xf0"
	sendTerminalSpeed = "\xff\xfa\x20\x01\xff\xf0"
	sendUser          = "\xff\xfa\x27\x01\x00USER\xff\xf0"
)

// optionSlots is in the opening's order, with the caller's SGA, which the opening does not ask
// for, last.
var optionSlots = [...]optionSlot{
	{option: OptionEcho, engineSide: true, asked: true},
	{option: OptionSuppressGoAhead, engineSide: true, asked: true},
	{option: OptionBinary, engineSide: true, asked: true},
	{option: OptionBinary, asked: true},
	{option: OptionTerminalType, asked: true, send: sendTerminalType},
	{option: OptionWindowSize, asked: true},
	{option: OptionNewEnviron, asked: true, send: sendUser},
	{option: OptionTerminalSpeed, asked: true, send: sendTerminalSpeed},
	{option: OptionSuppressGoAhead},
}

const (
	slotCount = len(optionSlots)
	// slotEcho is the engine's ECHO, which the Line reads to know whether to echo.
	slotEcho = 0
)

type optionEntry struct {
	state optionState
	sent  bool
}

// negotiationState holds the nine option states and the Synchs owed. The last two fields are false
// in a zero Negotiation: once Strip has taken over, Receive keeps what it returned before, because
// Strip can change the option states it would otherwise be read from.
type negotiationState struct {
	options          [slotCount]optionEntry
	synchs           int
	phase            readPhase
	heldVerb         byte
	handedOver       bool
	handedOverReturn bool
}

func newNegotiation() (*Negotiation, [OpeningLength]byte) {
	var opening [OpeningLength]byte
	length := 0
	for _, slot := range optionSlots {
		if !slot.asked {
			continue
		}
		verb := byte(TelnetDO)
		if slot.engineSide {
			verb = TelnetWILL
		}
		length += copy(opening[length:], []byte{TelnetIAC, verb, slot.option})
	}
	return &Negotiation{}, opening
}

// current is the state of a slot, with the zero read as the state the opening left it in.
func (state *negotiationState) current(index int) optionState {
	if current := state.options[index].state; current != stateOpening {
		return current
	}
	if optionSlots[index].asked {
		return stateWantYes
	}
	return stateNo
}

// answered is derived from the states so that a zero Negotiation needs no stored flag: it holds
// when none of the options the opening asked for is still waiting for its answer.
func (state *negotiationState) answered() bool {
	for index, slot := range optionSlots {
		if slot.asked && state.current(index) == stateWantYes {
			return false
		}
	}
	return true
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
		replies, _, _ = state.readByte(value, replies)
		read++
	}
	return replies, state.answered(), read
}

func (negotiation *Negotiation) strip(character byte, replies []byte) ([]byte, byte, bool) {
	state := &negotiation.state
	if !state.handedOver {
		state.handedOver = true
		state.handedOverReturn = state.answered()
	}
	return state.readByte(character, replies)
}

func (negotiation *Negotiation) takeSynch() int {
	owed := negotiation.state.synchs
	negotiation.state.synchs = 0
	return owed
}

// readByte is the one table Receive and Strip both run, so a later option is added in one place.
// Its results are the replies, the byte to hand on and whether there is one: a byte outside every
// command, the second IAC of IAC IAC, or the stand-in for EC and EL.
func (state *negotiationState) readByte(value byte, replies []byte) ([]byte, byte, bool) {
	handOn, isData := value, false
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
		case TelnetEC:
			handOn, isData = backspace, true
		case TelnetEL:
			handOn, isData = eraseLine, true
		case TelnetAYT:
			replies = append(replies, AYTAnswer...)
		case TelnetAO, TelnetIP:
			state.synchs++
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
	return replies, handOn, isData
}

const (
	backspace = 0x08
	eraseLine = 0x15
)

// slotFor finds the option's row on the side the verb is about: DO and DONT speak of the engine's
// own options, WILL and WONT of the caller's.
func slotFor(verb, option byte) (int, bool) {
	engineSide := verb == TelnetDO || verb == TelnetDONT
	for index, slot := range optionSlots {
		if slot.option == option && slot.engineSide == engineSide {
			return index, true
		}
	}
	return 0, false
}

// answer follows RFC 1143 section 7 so that a caller who repeats or contradicts a request cannot
// start a reply loop; an option the engine does not offer is refused from the verb alone, so it
// costs no state.
func (state *negotiationState) answer(verb, option byte, replies []byte) []byte {
	index, known := slotFor(verb, option)
	if !known {
		switch verb {
		case TelnetWILL:
			return append(replies, TelnetIAC, TelnetDONT, option)
		case TelnetDO:
			return append(replies, TelnetIAC, TelnetWONT, option)
		}
		return replies
	}
	entry := &state.options[index]
	slot := optionSlots[index]
	switch verb {
	case TelnetWILL, TelnetDO:
		switch state.current(index) {
		case stateWantYes:
			entry.state = stateYes
		case stateNo:
			entry.state = stateYes
			agree := byte(TelnetDO)
			if slot.engineSide {
				agree = TelnetWILL
			}
			replies = append(replies, TelnetIAC, agree, option)
		default:
			return replies
		}
		if slot.send != "" && !entry.sent {
			entry.sent = true
			replies = append(replies, slot.send...)
		}
	case TelnetWONT, TelnetDONT:
		switch state.current(index) {
		case stateWantYes:
			entry.state = stateNo
		case stateYes:
			entry.state = stateNo
			refuse := byte(TelnetDONT)
			if slot.engineSide {
				refuse = TelnetWONT
			}
			replies = append(replies, TelnetIAC, refuse, option)
		}
	}
	return replies
}

// wakeOnEnd stays as one line because the urgent send's rows register their wake by this name; it
// holds no rule, and the wake is timeup's.
func wakeOnEnd(ctx context.Context, connection Conn) (release func()) {
	return timeup.WakeOnEnd(ctx, connection)
}

// handOver is what Open takes from negotiation so that nothing is copied or lost: the last read's
// bytes from index from to readCount, and what a read cut short by its deadline left unwritten,
// which goes out first: unwritten bytes of replies, then urgent bytes of Synchs.
type handOver struct {
	readCount int
	from      int
	unwritten int
	urgent    int
}

func negotiate(ctx context.Context, connection Conn) (Outcome, error) {
	var readBuffer [ReadBufferSize]byte
	var replyBuffer [ReplyBufferSize]byte
	negotiation, opening := newNegotiation()
	outcome, _, err := negotiateWith(ctx, connection, negotiation, opening, &readBuffer, &replyBuffer)
	return outcome, err
}

// synchBytes appends IAC DM once for each Synch owed, after the replies already in buffer, so the
// replies and the Synchs share the buffer that holds the replies.
func synchBytes(buffer []byte, owed int) []byte {
	for range owed {
		buffer = append(buffer, TelnetIAC, TelnetDM)
	}
	return buffer
}

// negotiateWith is the one negotiation of Negotiate and Open. The buffers are the caller's so that
// Open can read into the Line's own and leave what is not negotiation's where the Line finds it.
func negotiateWith(
	ctx context.Context, connection Conn, negotiation *Negotiation, opening [OpeningLength]byte,
	readBuffer *[ReadBufferSize]byte, replyBuffer *[ReplyBufferSize]byte,
) (Outcome, handOver, error) {
	var release func()
	finish := func(outcome Outcome, left handOver, err error) (Outcome, handOver, error) {
		if release != nil {
			release()
		}
		deadline := timeup.Limit(ctx, time.Time{})
		if setErr := setDeadlines(connection, deadline, deadline); setErr != nil && err == nil {
			outcome, err = failure(ctx, setErr)
		}
		// The clock may have ended the context while the deadlines were being put back.
		if err == nil {
			if ended := timeup.Ended(ctx); ended != nil {
				outcome, left, err = 0, handOver{}, endedBy(ended)
			}
		}
		return outcome, left, err
	}
	fail := func(err error) (Outcome, handOver, error) {
		outcome, failed := failure(ctx, err)
		return finish(outcome, handOver{}, failed)
	}

	if err := timeup.Ended(ctx); err != nil {
		return finish(0, handOver{}, endedBy(err))
	}

	timeout := time.Now().Add(NegotiationSeconds * time.Second)
	readDeadline := timeup.Limit(ctx, timeout)
	writeDeadline := timeup.Limit(ctx, time.Time{})
	if err := setDeadlines(connection, readDeadline, writeDeadline); err != nil {
		return fail(err)
	}

	// Registered after the first deadlines are set, so they can never overwrite the wake-up.
	release = wakeOnEnd(ctx, connection)

	// The three seconds end only a read that waits, never a write, so a write that ends with them
	// passed is where negotiation stops, without a read after it.
	endAtTimeout := func(left handOver) (Outcome, handOver, error) {
		return finish(TimedOut, left, nil)
	}

	if _, err := connection.Write(opening[:]); err != nil {
		return fail(err)
	}
	if ended := timeup.Ended(ctx); ended != nil {
		return finish(0, handOver{}, endedBy(ended))
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
				// Taken here, so the Line's first TakeSynch cannot owe them a second time.
				replies = synchBytes(replies, negotiation.takeSynch())
				left.urgent = len(replies) - left.unwritten
			}
			return finish(outcome, left, failed)
		}
		if ended := timeup.Ended(ctx); ended != nil {
			return finish(0, handOver{}, endedBy(ended))
		}
		if len(replies) > 0 {
			if _, err := connection.Write(replies); err != nil {
				return fail(err)
			}
			if ended := timeup.Ended(ctx); ended != nil {
				return finish(0, handOver{}, endedBy(ended))
			}
		}
		if owed := negotiation.takeSynch(); owed > 0 {
			urgent := synchBytes(replies, owed)[len(replies):]
			if _, err := connection.WriteUrgent(urgent); err != nil {
				return fail(err)
			}
			if ended := timeup.Ended(ctx); ended != nil {
				return finish(0, handOver{}, endedBy(ended))
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

// setDeadlines sets the write deadline even when the read one fails, so that neither keeps a
// deadline the other has been given.
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
	if ended := timeup.Ended(ctx); ended != nil {
		return 0, endedBy(ended)
	}
	switch {
	case errors.Is(cause, io.EOF):
		return 0, ErrCallerClosed
	case errors.Is(cause, os.ErrDeadlineExceeded):
		return TimedOut, nil
	}
	return 0, fmt.Errorf("%w: %w", ErrConnectionFailed, cause)
}
