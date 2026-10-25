// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The caller's socket call the standard library has none for: a receive buffer set before the
// connection opens.
package telnet_test

import "syscall"

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
