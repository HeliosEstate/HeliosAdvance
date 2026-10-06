// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

// windowsBuildFolder is a folder on NTFS holding a good key file, so that a row judges only
// what it names.
func windowsBuildFolder(t *testing.T) string {
	t.Helper()
	folder := filepath.Join(t.TempDir(), "folder")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, nameKeyFile), []byte(keyText(rowKey(1))), 0o600); err != nil {
		t.Fatal(err)
	}
	return folder
}

// TestWindowsNotElevatedBuild runs where the process is not elevated: the loop's machine and
// the developer's. The source is FromOSStore, the one Windows allows, so that the missing
// rights are the only thing wrong. GitHub's runner is elevated, so it skips there.
func TestWindowsNotElevatedBuild(t *testing.T) {
	t.Parallel()
	if elevated(t) {
		t.Skip("needs a process that is not elevated: runs on the loop's machine and the developer's")
	}
	t.Run(lineBuildNotElevated, func(t *testing.T) {
		t.Parallel()
		_, err := build(t, windowsBuildFolder(t), rowFields(), FirstSetup, FromOSStore)
		wantRefusal(t, err, NotElevated)
	})
}

// TestWindowsElevatedBuild is the Windows rows that need an elevated process: the two key
// sources Windows does not allow. It runs on GitHub's Windows runner, whose job fails before
// the tests when the runner is not elevated, so its skip elsewhere cannot pass there unseen.
func TestWindowsElevatedBuild(t *testing.T) {
	t.Parallel()
	if !elevated(t) {
		t.Skip("needs an elevated process: runs on GitHub's Windows runner, whose job fails when it is not elevated")
	}
	t.Run(lineBuildKeyFileRefused, func(t *testing.T) {
		t.Parallel()
		_, err := build(t, windowsBuildFolder(t), rowFields(), FirstSetup, FromKeyFile)
		wantRefusal(t, err, SourceRefused)
	})
	t.Run(lineBuildContainerRefused, func(t *testing.T) {
		t.Parallel()
		_, err := build(t, windowsBuildFolder(t), rowFields(), FirstSetup, FromContainer)
		wantRefusal(t, err, SourceRefused)
	})
}
