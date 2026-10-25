// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package ssh

import (
	"context"
	"errors"
	"net"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

// The contract's operations hand their work to the unexported functions below, so the contract
// builds before the package is built and the build never needs to change the contract. Each
// placeholder here is replaced by the issue that builds it, and fails until then, so nothing calls
// it yet.

type hostKeyState struct {
	signer cryptossh.Signer
}

type channelState struct {
	channel cryptossh.Channel
}

// errNotBuilt is what a placeholder returns until its issue builds it.
var errNotBuilt = errors.New("ssh: not built yet")

func readHostKey(_ string) (*HostKey, error) {
	return nil, errNotBuilt
}

func accept(_ context.Context, _ *net.TCPConn, key *HostKey) (*Channel, error) {
	if key == nil || key.state.signer == nil {
		return nil, ErrConnectionFailed
	}
	return nil, errNotBuilt
}

func (channel *Channel) sendChar(_ context.Context, _ byte) error {
	return ErrConnectionFailed
}

func (channel *Channel) flush(_ context.Context) error {
	return ErrConnectionFailed
}

func (channel *Channel) recvChar(_ context.Context, _ time.Time) (byte, error) {
	return 0, ErrConnectionFailed
}

func (channel *Channel) echoes() bool {
	return channel != nil && channel.state.channel != nil
}

func (channel *Channel) close(_ context.Context) error {
	return ErrConnectionFailed
}
