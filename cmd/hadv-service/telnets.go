// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"

	"github.com/heliosestate/heliosadvance/internal/language"
	"github.com/heliosestate/heliosadvance/internal/listener"
	"github.com/heliosestate/heliosadvance/internal/telnets"
)

// telnetsTargets are Telnet over TLS's own list, so that its addresses can change without the
// others'.
var telnetsTargets = []target{{ipv4Network, ipv4Address}, {ipv6Network, ipv6Address}}

// newTelnetsListener serves with the certificate read at start.
func newTelnetsListener(ctx context.Context, port string, certificate *telnets.Certificate,
	count *listener.ConnectionCount, texts *language.Texts,
) (*listener.Listener, []string, error) {
	return newCredentialListener(ctx, telnetsTargets, port, certificate, telnets.Accept, count, texts)
}
