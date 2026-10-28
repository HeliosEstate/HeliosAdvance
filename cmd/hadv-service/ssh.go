// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"net"

	"github.com/heliosestate/heliosadvance/internal/listener"
	"github.com/heliosestate/heliosadvance/internal/ssh"
)

const defaultSSHPort = "22"

// sshTargets are the only addresses SSH listens on, IPv4 first.
var sshTargets = []target{{"tcp4", ipv4Address}, {"tcp6", ipv6Address}}

// sshOpener is SSH's way in with the host key read at start.
func sshOpener(key *ssh.HostKey) listener.Open {
	return func(ctx context.Context, connection *net.TCPConn) (listener.KindConnection, error) {
		channel, err := ssh.Accept(ctx, connection, key)
		if err != nil {
			return nil, err
		}
		return channel, nil
	}
}

// newSSHListener returns SSH's Listener, not started, with the addresses it listens at. The
// sockets are closed here only when New refuses, since they are the Listener's once it has them.
func newSSHListener(ctx context.Context, port string, key *ssh.HostKey,
	count *listener.ConnectionCount,
) (*listener.Listener, []string, error) {
	sockets, addresses, err := listen(ctx, sshTargets, port)
	if err != nil {
		return nil, nil, err
	}
	sshListener, err := listener.New(sockets, sshOpener(key), count)
	if err != nil {
		return nil, nil, errors.Join(err, closeAll(sockets))
	}
	return sshListener, addresses, nil
}
