// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package telnets

import (
	"context"
	"errors"
	"net"

	"github.com/heliosestate/heliosadvance/internal/telnet"
)

// The contract's operations hand their work to the unexported functions below, so the contract
// builds before the package is built and the build never needs to change the contract. Each
// placeholder here is replaced by the issue that builds it, and fails until then, so nothing calls
// it yet.

type certificateState struct{}

// errNotBuilt is what a placeholder returns until its issue builds it.
var errNotBuilt = errors.New("telnets: not built yet")

func readCertificate(_, _ string) (*Certificate, error) {
	return nil, errNotBuilt
}

func accept(_ context.Context, _ *net.TCPConn, certificate *Certificate) (*telnet.Line, error) {
	if certificate == nil {
		return nil, telnet.ErrConnectionFailed
	}
	_ = certificate.state
	return nil, errNotBuilt
}
