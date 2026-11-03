// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !windows

package main_test

import "testing"

// listeningSockets cannot read a process's sockets on a system the engine does not ship to, so a
// row that needs them fails rather than pass on nothing.
func listeningSockets(t *testing.T, _ int) []string {
	t.Helper()
	t.Fatalf("this system's table of a process's listening sockets is not read here")
	return nil
}
