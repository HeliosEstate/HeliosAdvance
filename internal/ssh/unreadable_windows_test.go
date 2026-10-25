// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package ssh_test

import (
	"os"
	"testing"
)

// keepFromReading puts a folder where the file was, which the engine can open but never read,
// whatever its rights. A file held open with no sharing is not enough: an administrator whose
// backup privilege is enabled, as on CI's Windows runner, reads past the hold, since Go's open
// asks for backup semantics.
func keepFromReading(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatalf("removing %s: %v", path, err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("making a folder at %s: %v", path, err)
	}
}
