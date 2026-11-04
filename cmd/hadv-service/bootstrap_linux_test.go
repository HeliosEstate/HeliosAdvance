// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main_test

import (
	"os"
	"path/filepath"
	"testing"
)

// protectKeyFile gives a key file the mode of a good one on Linux: its owner, the runner's own
// user, may read and write it, and its group and others nothing.
func protectKeyFile(t *testing.T, path string) {
	t.Helper()
	setKeyMode(t, path, 0o600)
}

// setKeyMode sets a file's or folder's mode exactly, past the umask.
func setKeyMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("setting %s's mode to %o: %v", path, mode, err)
	}
}

// makeUnopenable takes every permission from a file or folder, mode 0000, which its owner cannot
// open either, and gives it back once the row ends, so the row's folder can be removed.
func makeUnopenable(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	setKeyMode(t, path, 0)
	t.Cleanup(func() {
		if err := os.Chmod(path, info.Mode().Perm()); err != nil {
			t.Errorf("giving %s its mode back: %v", path, err)
		}
	})
}

// openToOthers lets the key file's group and others read it, mode 0644.
func openToOthers(t *testing.T, path string) {
	t.Helper()
	setKeyMode(t, path, 0o644)
}

// linkOutside puts at link a symbolic link to a file outside the bootstrap folder that holds
// contents, mode 0600, so following the link would read a file the engine would otherwise take.
func linkOutside(t *testing.T, link string, contents []byte) {
	t.Helper()
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, contents, 0o600); err != nil {
		t.Fatalf("writing the file outside the folder: %v", err)
	}
	setKeyMode(t, target, 0o600)
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("linking %s to a file outside the folder: %v", link, err)
	}
}

// linkKinds names the way linkOutside links, for the rows' names.
const linkKinds = "a symbolic link"
