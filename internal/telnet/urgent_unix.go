// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package telnet

import (
	"errors"
	"net"
	"syscall"
)

// setUrgentInLine is the one call that differs by platform: the syscall package names SO_OOBINLINE
// on every Unix it knows, each with its own value.
func setUrgentInLine(descriptor uintptr) error {
	return syscall.SetsockoptInt(int(descriptor), syscall.SOL_SOCKET, syscall.SO_OOBINLINE, 1)
}

// urgentState is empty here: Go's poller waits for room and the connection's write deadline wakes
// it, so the platform keeps nothing between sends.
type urgentState struct{}

// write sends the byte as urgent data and returns false from the callback when the socket has no
// room, so Go's poller waits for it, with the write deadline. No flag beyond MSG_OOB is needed:
// the socket Go accepted is already non-blocking, so a full send buffer gives EAGAIN, and
// MSG_DONTWAIT is not defined on every Unix this file builds for.
func (state *urgentState) write(connection *net.TCPConn, value byte) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	var sendErr error
	err = raw.Write(func(descriptor uintptr) bool {
		for {
			sendErr = syscall.Sendto(int(descriptor), []byte{value}, syscall.MSG_OOB, nil)
			if !errors.Is(sendErr, syscall.EINTR) {
				break
			}
		}
		return !errors.Is(sendErr, syscall.EAGAIN)
	})
	if err != nil {
		return err
	}
	return sendErr
}
