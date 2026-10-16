// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package listener

import (
	"errors"
	"net"
)

// The contract's operations hand their work to the unexported functions below, so the contract
// builds before the package is built and the build never needs to change the contract. Each
// placeholder here is replaced by the issue that builds it.

// errNotBuilt is what a placeholder returns until its issue builds it.
var errNotBuilt = errors.New("listener: not built yet")

// listenerState is the state a Listener keeps; the build gives it its fields.
type listenerState struct{}

// The placeholders answer with what no line allows, so that no approved test passes before the
// build: start fails with errNotBuilt.
func start(_ []*net.TCPListener) (*Listener, error) {
	return nil, errNotBuilt
}

func (listener *Listener) stop() {
	if listener != nil {
		_ = listener.state
	}
}
