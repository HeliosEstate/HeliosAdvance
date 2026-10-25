// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package ssh_test

import (
	"os"
	"testing"
)

// keepFromReading leaves the owner only the right to write, so that an ordinary user, the
// engine's, cannot read it; root reads every file, so the row needs an ordinary user.
func keepFromReading(t *testing.T, path string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Fatalf("this row needs an ordinary user: root reads a file of any mode")
	}
	if err := os.Chmod(path, 0o200); err != nil {
		t.Fatalf("setting %s to 0200: %v", path, err)
	}
}
