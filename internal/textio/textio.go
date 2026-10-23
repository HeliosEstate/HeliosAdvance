// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package textio

import (
	"context"
	"errors"
	"time"
)

// The contract's operations hand their work to the unexported functions below, so the contract
// builds before the package is built and the build never needs to change the contract. Each
// placeholder here is replaced by the issue that builds it.

// errNotBuilt is what a placeholder returns until its issue builds it.
var errNotBuilt = errors.New("textio: not built yet")

// connState is the state a Conn keeps; the build gives it its fields.
type connState struct{}

// lineState is the state a Line keeps; the build gives it its fields.
type lineState struct{}

func newConn(_ Chars) *Conn {
	return &Conn{state: connState{}}
}

func (conn *Conn) sendChar(_ context.Context, _ byte) error {
	return errNotBuilt
}

func (conn *Conn) recvChar(_ context.Context, _ time.Time) (byte, error) {
	return 0, errNotBuilt
}

func (conn *Conn) sendString(_ context.Context, _ string) error {
	return errNotBuilt
}

func (conn *Conn) recvString(_ context.Context, _ time.Time, _ int) (string, error) {
	return "", errNotBuilt
}

func newLine(_ int) Line {
	return Line{state: lineState{}}
}

func (line Line) text() string {
	return ""
}

func edit(line Line, _ byte) (Line, []byte, bool) {
	return line, nil, false
}
