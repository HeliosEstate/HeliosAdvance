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

// telnetTargets are Telnet's own list, so that its addresses can change without SSH's.
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

// newTelnetListener closes the sockets only when New refuses: once it has them they are the
// Listener's.
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
