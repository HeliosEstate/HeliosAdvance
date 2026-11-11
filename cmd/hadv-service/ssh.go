// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"net"

	"github.com/heliosestate/heliosadvance/internal/language"
	"github.com/heliosestate/heliosadvance/internal/listener"
	"github.com/heliosestate/heliosadvance/internal/ssh"
)

const defaultSSHPort = "22"

// sshTargets are SSH's own list, so that its addresses can change without Telnet's.
var sshTargets = []target{{ipv4Network, ipv4Address}, {ipv6Network, ipv6Address}}

// newSSHListener serves with the host key read at start.
func newSSHListener(ctx context.Context, port string, key *ssh.HostKey,
	count *listener.ConnectionCount, texts *language.Texts,
) (*listener.Listener, []string, error) {
	return newKindListener(ctx, sshTargets, port,
		func(ctx context.Context, connection *net.TCPConn) (*ssh.Channel, error) {
			return ssh.Accept(ctx, connection, key)
		}, count, texts)
}
