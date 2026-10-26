// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"net"

	"github.com/heliosestate/heliosadvance/internal/listener"
	"github.com/heliosestate/heliosadvance/internal/ssh"
	"github.com/heliosestate/heliosadvance/internal/telnet"
)

// openTelnet adapts Telnet's way in to the Listener's, which wants a nil KindConnection on an
// error, never one holding a nil Line.
func openTelnet(ctx context.Context, connection *net.TCPConn) (listener.KindConnection, error) {
	line, err := telnet.Accept(ctx, connection)
	if err != nil {
		return nil, err
	}
	return line, nil
}

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
