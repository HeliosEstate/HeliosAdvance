// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The mark of a read-bound row's child: on Linux a row runs again in this test binary under
// strace, and TestMain, on every system, runs such a child's tests alone.
package bootstrap_test

import (
	"os"
	"slices"
)

// readBoundChild marks the run of this test binary that is a row's child under strace, on Linux:
// an argument after the test flags, which the testing package leaves alone, followed by the
// bootstrap folder the child opens.
const readBoundChild = "read-bound-child"

// childFolder is the bootstrap folder this run opens when it is a row's child, and whether it is
// one.
func childFolder() (string, bool) {
	place := slices.Index(os.Args, readBoundChild)
	if place < 0 {
		return "", false
	}
	if place+1 >= len(os.Args) {
		return "", true
	}
	return os.Args[place+1], true
}
