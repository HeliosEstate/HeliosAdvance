// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package listener

import "syscall"

// socketOOBInline is Winsock's SO_OOBINLINE, which the syscall package does not name.
const socketOOBInline = 0x0100

func setUrgentInLine(descriptor uintptr) error {
	return syscall.SetsockoptInt(syscall.Handle(descriptor), syscall.SOL_SOCKET, socketOOBInline, 1)
}
