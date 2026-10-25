// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package telnet

import (
	"context"
	"net"
)

// Accept and Close hand their work to the unexported functions below, so the contract builds
// before they are built and the build never needs to change the contract. Each placeholder here
// is replaced by the issue that builds it, and fails until then, so nothing calls it yet.

func accept(_ context.Context, _ *net.TCPConn) (*Line, error) {
	return nil, ErrConnectionFailed
}

func (line *Line) close(_ context.Context) error {
	return ErrConnectionFailed
}
