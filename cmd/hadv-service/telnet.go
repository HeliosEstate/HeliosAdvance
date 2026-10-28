// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"net"

	"github.com/heliosestate/heliosadvance/internal/listener"
	"github.com/heliosestate/heliosadvance/internal/telnet"
)

const defaultPort = "23"

// telnetTargets are the only addresses Telnet listens on, IPv4 first.
var telnetTargets = []target{{"tcp4", ipv4Address}, {"tcp6", ipv6Address}}

// openTelnet adapts Telnet's way in to the Listener's, which wants a nil KindConnection on an
// error, never one holding a nil Line.
func openTelnet(ctx context.Context, connection *net.TCPConn) (listener.KindConnection, error) {
	line, err := telnet.Accept(ctx, connection)
	if err != nil {
		return nil, err
	}
	return line, nil
}

// newTelnetListener returns Telnet's Listener, not started, with the addresses it listens at. The
// sockets are closed here only when New refuses, since they are the Listener's once it has them.
func newTelnetListener(ctx context.Context, port string, count *listener.ConnectionCount,
) (*listener.Listener, []string, error) {
	sockets, addresses, err := listen(ctx, telnetTargets, port)
	if err != nil {
		return nil, nil, err
	}
	telnetListener, err := listener.New(sockets, openTelnet, count)
	if err != nil {
		return nil, nil, errors.Join(err, closeAll(sockets))
	}
	return telnetListener, addresses, nil
}
