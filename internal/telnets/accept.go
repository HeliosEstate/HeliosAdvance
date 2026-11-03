// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package telnets

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/heliosestate/heliosadvance/internal/telnet"
	"github.com/heliosestate/heliosadvance/internal/timeup"
)

// encryptedConn is the encrypted connection as Telnet's Conn, with the TCP connection beneath it
// for the shutdown that follows close_notify.
type encryptedConn struct {
	*tls.Conn
	tcp *net.TCPConn
}

// WriteUrgent writes every byte as an ordinary one, since TLS carries no urgent data.
func (connection *encryptedConn) WriteUrgent(buffer []byte) (int, error) {
	return connection.Write(buffer)
}

// CloseWrite shuts down the TCP connection's sending side whether or not close_notify was sent,
// and never closes the connection, which the shared execution path does: closing the encrypted
// connection would send close_notify after a write that failed.
func (connection *encryptedConn) CloseWrite() error {
	return errors.Join(connection.Conn.CloseWrite(), connection.tcp.CloseWrite())
}

func deadlineEnded(cause error) error {
	return fmt.Errorf("%w: %w", telnet.ErrDeadlineEnded, cause)
}

func accept(ctx context.Context, connection *net.TCPConn, certificate *Certificate) (*telnet.Line, error) {
	if connection == nil || certificate == nil || certificate.state.config == nil {
		return nil, telnet.ErrConnectionFailed
	}
	if cause := timeup.Ended(ctx); cause != nil {
		return nil, deadlineEnded(cause)
	}
	encrypted := tls.Server(connection, certificate.state.config)
	release := timeup.WakeOnEnd(ctx, connection)
	//nolint:noctx // HandshakeContext closes the connection, which the shared execution path does
	// instead; timeup's wake ends the handshake
	err := encrypted.Handshake()
	release()
	if err != nil {
		// Judged after the release, by the clock, since the wake can end the handshake before the
		// context reports that it has ended.
		if cause := timeup.Ended(ctx); cause != nil {
			return nil, deadlineEnded(cause)
		}
		return nil, ErrHandshakeFailed
	}
	line, _, err := telnet.Open(ctx, &encryptedConn{Conn: encrypted, tcp: connection})
	if err != nil {
		return nil, err
	}
	return line, nil
}
