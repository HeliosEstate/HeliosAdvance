// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The language files' refusals that need a file or folder the program's own account cannot read,
// which a mode of 000 gives on Linux to an account that is not root.
package main_test

import (
	"os"
	"path/filepath"
	"testing"
)

// unreadable sets path's mode to 000 until the row ends, when its mode is given back so the row's
// folder can be removed.
func unreadable(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, 0); err != nil {
		t.Fatalf("making %s unreadable: %v", path, err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, mode) })
}

func TestLinuxLanguageFiles(t *testing.T) {
	t.Parallel()

	t.Run("If the engine fails to read the `lang` folder or its en-us file, or en-us lacks a text the engine shows or holds one that counts as missing, then the engine shall write one `start_failed` line naming the file and why, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("lang of mode 000: start_failed naming lang", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile()})
			unreadable(t, filepath.Join(folder, langFolder), 0o700)
			expectRefusalNamingLang(t, startPlaced(t, programFile))
		})
		t.Run("en-us.toml of mode 000: start_failed naming en-us.toml", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile()})
			unreadable(t, filepath.Join(folder, langFolder, filepath.FromSlash(languagePath(fallbackCode))), 0o600)
			expectRefusalNaming(t, startPlaced(t, programFile), fallbackCode+".toml")
		})
	})
}
