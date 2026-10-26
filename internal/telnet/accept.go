// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package telnet

import (
	"context"
	"fmt"
	"net"
)

func accept(ctx context.Context, connection *net.TCPConn) (*Line, error) {
	if connection == nil {
		return nil, ErrConnectionFailed
	}
	if err := keepUrgentInLine(connection); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConnectionFailed, err)
	}
	line, _, err := open(ctx, connection)
	if err != nil {
		return nil, err
	}
	line.state.accepted = connection
	return line, nil
}

// keepUrgentInLine is set before anything is read, since a Synch whose DM byte leaves the stream
// would leave its IAC to swallow the caller's next character.
func keepUrgentInLine(connection *net.TCPConn) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	if err := raw.Control(func(descriptor uintptr) { setErr = setUrgentInLine(descriptor) }); err != nil {
		return err
	}
	return setErr
}
