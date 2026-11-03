// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"

	"github.com/heliosestate/heliosadvance/internal/listener"
	"github.com/heliosestate/heliosadvance/internal/telnet"
)

const defaultPort = "23"

// telnetTargets are Telnet's own list, so that its addresses can change without SSH's.
var telnetTargets = []target{{ipv4Network, ipv4Address}, {ipv6Network, ipv6Address}}

func newTelnetListener(ctx context.Context, port string, count *listener.ConnectionCount,
) (*listener.Listener, []string, error) {
	return newKindListener(ctx, telnetTargets, port, telnet.Accept, count)
}
