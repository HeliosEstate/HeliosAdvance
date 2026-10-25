// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The caller's socket calls the standard library has none for: an urgent send, and a receive
// buffer set before the connection opens.
package listener_test

import (
	"net"
	"syscall"
)

// smallWindow sets a socket's receive buffer to 4096 bytes before it connects, so the window it
// offers stays small: set after, Linux keeps honouring the larger window it already offered, and
// a caller that never reads lets the engine's writes creep on.
func smallWindow(_, _ string, raw syscall.RawConn) error {
	var setErr error
	err := raw.Control(func(descriptor uintptr) {
		setErr = syscall.SetsockoptInt(int(descriptor), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096)
	})
	if err != nil {
		return err
	}
	return setErr
}

func sendUrgent(connection *net.TCPConn, value byte) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	var sendErr error
	err = raw.Write(func(descriptor uintptr) bool {
		sendErr = syscall.Sendto(int(descriptor), []byte{value}, syscall.MSG_OOB, nil)
		return true
	})
	if err != nil {
		return err
	}
	return sendErr
}
