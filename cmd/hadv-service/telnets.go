// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"net"

	"github.com/heliosestate/heliosadvance/internal/listener"
	"github.com/heliosestate/heliosadvance/internal/telnets"
)

const defaultTLSPort = "992"

// telnetsTargets are Telnet over TLS's own list, so that its addresses can change without the
// others'.
var telnetsTargets = []target{{"tcp4", ipv4Address}, {"tcp6", ipv6Address}}

// telnetsOpener is Telnet over TLS's way in with the certificate read at start.
func telnetsOpener(certificate *telnets.Certificate) listener.Open {
	return func(ctx context.Context, connection *net.TCPConn) (listener.KindConnection, error) {
		line, err := telnets.Accept(ctx, connection, certificate)
		if err != nil {
			return nil, err
		}
		return line, nil
	}
}

func newTelnetsListener(ctx context.Context, port string, certificate *telnets.Certificate,
	count *listener.ConnectionCount,
) (*listener.Listener, []string, error) {
	return newKindListener(ctx, telnetsTargets, port, telnetsOpener(certificate), count)
}
