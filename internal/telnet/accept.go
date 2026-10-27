// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package telnet

import (
	"context"
	"fmt"
	"net"
)

// acceptedConn is the one instance Accept makes of an accepted connection as a Conn: the
// connection, with the platform's state for its urgent write beside it.
type acceptedConn struct {
	*net.TCPConn
	urgentState
}

// WriteUrgent sends every byte but the last in the ordinary write, then the last alone as urgent
// data: an urgent send cut short would mark the wrong byte urgent, and the ordinary write already
// waits for room as Go's own writes do.
func (connection *acceptedConn) WriteUrgent(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	last := len(buffer) - 1
	if last > 0 {
		if count, err := connection.Write(buffer[:last]); err != nil {
			return count, err
		}
	}
	if err := connection.write(connection.TCPConn, buffer[last]); err != nil {
		return last, err
	}
	return len(buffer), nil
}

func accept(ctx context.Context, connection *net.TCPConn) (*Line, error) {
	if connection == nil {
		return nil, ErrConnectionFailed
	}
	if err := keepUrgentInLine(connection); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConnectionFailed, err)
	}
	line, _, err := open(ctx, &acceptedConn{TCPConn: connection})
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
