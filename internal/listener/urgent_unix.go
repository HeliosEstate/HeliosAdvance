// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package listener

import "syscall"

// setUrgentInLine is the one call that differs by platform: the syscall package names SO_OOBINLINE
// on every Unix it knows, each with its own value.
func setUrgentInLine(descriptor uintptr) error {
	return syscall.SetsockoptInt(int(descriptor), syscall.SOL_SOCKET, syscall.SO_OOBINLINE, 1)
}
