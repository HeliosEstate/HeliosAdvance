// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package telnet

import (
	"context"
	"errors"
)

// The contract's operations hand their work to the unexported functions below, so the contract
// builds before the package is built and the build never needs to change the contract. Each
// placeholder here is replaced by the issue that builds it.

// errNotBuilt is what a placeholder returns until its issue builds it.
var errNotBuilt = errors.New("telnet: not built yet")

// negotiationState is the state a Negotiation keeps; the build gives it its fields.
type negotiationState struct{}

func newNegotiation() (*Negotiation, []byte) {
	return &Negotiation{state: negotiationState{}}, nil
}

func (negotiation *Negotiation) receive(_, replies []byte) ([]byte, bool) {
	return replies, false
}

func (negotiation *Negotiation) answered() bool {
	return false
}

func negotiate(_ context.Context, _ Conn) (Outcome, error) {
	return 0, errNotBuilt
}
