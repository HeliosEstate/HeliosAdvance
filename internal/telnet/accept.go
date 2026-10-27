// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package telnet

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// acceptedConn is a placeholder until Part 4's build, which writes the Synch as TCP urgent data:
// the accepted connection as a Conn, its urgent write not built.
type acceptedConn struct {
	*net.TCPConn
}

var errUrgentNotBuilt = errors.New("telnet: the urgent write is not built")

func (connection acceptedConn) WriteUrgent([]byte) (int, error) {
	return 0, errUrgentNotBuilt
}

func accept(ctx context.Context, connection *net.TCPConn) (*Line, error) {
	if connection == nil {
		return nil, ErrConnectionFailed
	}
	if err := keepUrgentInLine(connection); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConnectionFailed, err)
	}
	line, _, err := open(ctx, acceptedConn{connection})
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
