// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package telnet

import (
	"context"
	"errors"
	"time"
)

// The Line's operations and Data hand their work to the unexported functions below, so the
// contract builds before they are built and the build never needs to change the contract. Each
// placeholder here is replaced by the issue that builds it.

// errLineNotBuilt is what a placeholder returns until its issue builds it.
var errLineNotBuilt = errors.New("telnet: the line is not built yet")

// lineState is the state a Line keeps; the build gives it its fields.
type lineState struct{}

func (negotiation *Negotiation) data(_, data []byte) []byte {
	return data
}

func open(_ context.Context, _ Conn) (*Line, Outcome, error) {
	return &Line{state: lineState{}}, 0, errLineNotBuilt
}

func (line *Line) sendChar(_ context.Context, _ byte) error {
	return errLineNotBuilt
}

func (line *Line) flush(_ context.Context) error {
	return errLineNotBuilt
}

func (line *Line) recvChar(_ context.Context, _ time.Time) (byte, error) {
	return 0, errLineNotBuilt
}

func (line *Line) echoes() bool {
	return false
}
