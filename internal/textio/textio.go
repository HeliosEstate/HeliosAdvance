// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package textio

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// The contract's operations hand their work to the unexported functions below, so the contract
// builds before the package is built and the build never needs to change the contract.

const (
	backspace      = 0x08
	deleteKey      = 0x7F
	carriageReturn = 0x0D
	lineFeed       = 0x0A
	eraseLine      = 0x15
	space          = 0x20
	tilde          = 0x7E
)

// errNoChars is what every call of a Conn that has no Chars returns, so that a Conn not made by
// New cannot panic the code calling it.
var errNoChars = errors.New("textio: the connection has no characters to send and receive")

type connState struct {
	chars Chars
}

// lineState is an array, not a slice, so that a Line copies by value and two copies never share
// bytes, which a caller that keeps a Line before an Edit and tries another byte depends on.
type lineState struct {
	characters [MostLine]byte
	count      int
	limit      int
	ended      bool
}

func newConn(chars Chars) *Conn {
	return &Conn{state: connState{chars: chars}}
}

func (conn *Conn) sendChar(ctx context.Context, character byte) error {
	if conn == nil || conn.state.chars == nil {
		return errNoChars
	}
	return conn.state.chars.SendChar(ctx, character)
}

func (conn *Conn) recvChar(ctx context.Context, deadline time.Time) (byte, error) {
	if conn == nil || conn.state.chars == nil {
		return 0, errNoChars
	}
	return conn.state.chars.RecvChar(ctx, deadline)
}

func (conn *Conn) sendString(ctx context.Context, text string) error {
	if conn == nil || conn.state.chars == nil {
		return errNoChars
	}
	if err := contextEnded(ctx); err != nil {
		return err
	}
	chars := conn.state.chars
	for index := range len(text) {
		if err := chars.SendChar(ctx, text[index]); err != nil {
			return err
		}
	}
	return chars.Flush(ctx)
}

// contextEnded lets the clock judge the deadline, since a connection's deadline can wake a call
// before the context's own timer reports that the context has ended.
func contextEnded(ctx context.Context) error {
	cause := ctx.Err()
	if cause == nil {
		deadline, ok := ctx.Deadline()
		if !ok || time.Now().Before(deadline) {
			return nil
		}
		cause = context.DeadlineExceeded
	}
	return fmt.Errorf("textio: the call's context ended: %w", cause)
}

func (conn *Conn) recvString(ctx context.Context, deadline time.Time, most int) (string, error) {
	if most < 1 || most > MostLine {
		return "", ErrMostOutOfRange
	}
	if conn == nil || conn.state.chars == nil {
		return "", errNoChars
	}
	chars := conn.state.chars
	line := NewLine(most)
	for {
		character, err := chars.RecvChar(ctx, deadline)
		if err != nil {
			return "", err
		}
		var echo []byte
		var ended bool
		line, echo, ended = Edit(line, character)
		if chars.Echoes() {
			for _, value := range echo {
				if err := chars.SendChar(ctx, value); err != nil {
					return "", err
				}
			}
		}
		if ended {
			return line.Text(), nil
		}
	}
}

func newLine(most int) Line {
	return Line{state: lineState{limit: min(max(most, 0), MostLine)}}
}

func (line Line) text() string {
	return string(line.state.characters[:line.state.count])
}

func edit(line Line, character byte) (Line, []byte, bool) {
	state := &line.state
	if state.ended {
		return line, nil, true
	}
	switch {
	case character >= space && character <= tilde:
		if state.count < state.limit {
			state.characters[state.count] = character
			state.count++
			return line, []byte{character}, false
		}
	case character == backspace || character == deleteKey:
		if state.count > 0 {
			state.count--
			return line, []byte{backspace, space, backspace}, false
		}
	case character == eraseLine:
		if state.count > 0 {
			echo := make([]byte, 0, 3*state.count)
			for range state.count {
				echo = append(echo, backspace, space, backspace)
			}
			state.count = 0
			return line, echo, false
		}
	case character == carriageReturn || character == lineFeed:
		if state.count > 0 {
			state.ended = true
			return line, []byte{carriageReturn, lineFeed}, true
		}
	}
	return line, nil, false
}
