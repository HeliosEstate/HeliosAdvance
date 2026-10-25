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
// offers stays small.
func smallWindow(_, _ string, raw syscall.RawConn) error {
	var setErr error
	err := raw.Control(func(descriptor uintptr) {
		setErr = syscall.SetsockoptInt(syscall.Handle(descriptor), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096)
	})
	if err != nil {
		return err
	}
	return setErr
}

// Winsock's MSG_OOB, which the syscall package does not name.
const winsockMessageOutOfBand = 0x1

func sendUrgent(connection *net.TCPConn, value byte) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	var sendErr error
	err = raw.Write(func(descriptor uintptr) bool {
		data := [1]byte{value}
		buffer := syscall.WSABuf{Len: 1, Buf: &data[0]}
		var sent uint32
		sendErr = syscall.WSASend(syscall.Handle(descriptor), &buffer, 1, &sent, winsockMessageOutOfBand, nil, nil)
		return true
	})
	if err != nil {
		return err
	}
	return sendErr
}
