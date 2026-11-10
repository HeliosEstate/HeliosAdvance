// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Load's lines on Linux that need the system's own links and modes: a language's folder or file
// a symbolic link out of the lang folder, and a file link that stays inside it.
package language_test

import (
	"os"
	"path/filepath"
	"testing"
)

// makeUnopenable takes every permission from a file or folder, mode 0000, which its owner cannot
// open either, and gives it back once the row ends, so the row's folder can be removed.
func makeUnopenable(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatalf("taking every permission from %s: %v", path, err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(path, info.Mode().Perm()); err != nil {
			t.Errorf("giving %s its mode back: %v", path, err)
		}
	})
}

// outside makes a folder beside the lang folder, outside it, holding fr-fr/fr-fr.toml, the full
// French file, and returns the path of that fr-fr folder.
func outside(t *testing.T, lang string) string {
	t.Helper()
	return filepath.Dir(writeLanguage(t, filepath.Join(filepath.Dir(lang), "outside"), frFR, []byte(frFile(nil))))
}

func TestLinuxLoad(t *testing.T) {
	t.Parallel()

	t.Run("If a language's folder or file is a link leading out of folder, or its file cannot be read, then Load shall return ErrFileRefused naming the file.", func(t *testing.T) {
		t.Parallel()
		t.Run("the language's folder a symbolic link to a folder outside: ErrFileRefused naming its file", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			if err := os.Symlink(outside(t, folder), filepath.Join(folder, frFR)); err != nil {
				t.Fatalf("linking fr-fr to a folder outside: %v", err)
			}
			expectRefused(t, folder, fallbackCode, fileName(frFR))
		})
		t.Run("the language's file a symbolic link to a file outside: ErrFileRefused naming it", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			if err := os.Mkdir(filepath.Join(folder, frFR), 0o700); err != nil {
				t.Fatalf("making fr-fr/: %v", err)
			}
			target := filepath.Join(outside(t, folder), fileName(frFR))
			if err := os.Symlink(target, filepath.Join(folder, frFR, fileName(frFR))); err != nil {
				t.Fatalf("linking fr-fr.toml to a file outside: %v", err)
			}
			expectRefused(t, folder, fallbackCode, fileName(frFR))
		})
		t.Run("the language's file a relative symbolic link climbing out, ../../outside/fr-fr/fr-fr.toml: ErrFileRefused naming it", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			outside(t, folder)
			if err := os.Mkdir(filepath.Join(folder, frFR), 0o700); err != nil {
				t.Fatalf("making fr-fr/: %v", err)
			}
			if err := os.Symlink("../../outside/fr-fr/fr-fr.toml", filepath.Join(folder, frFR, fileName(frFR))); err != nil {
				t.Fatalf("linking fr-fr.toml to a file outside: %v", err)
			}
			expectRefused(t, folder, fallbackCode, fileName(frFR))
		})
		t.Run("the language's file a symbolic link to a file inside lang, the edge inside: loads, its texts shown", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			if err := os.Mkdir(filepath.Join(folder, frFR), 0o700); err != nil {
				t.Fatalf("making fr-fr/: %v", err)
			}
			if err := os.WriteFile(filepath.Join(folder, frFR, "real.toml"), []byte(frFile(nil)), 0o600); err != nil {
				t.Fatalf("writing fr-fr/real.toml: %v", err)
			}
			if err := os.Symlink("real.toml", filepath.Join(folder, frFR, fileName(frFR))); err != nil {
				t.Fatalf("linking fr-fr.toml to real.toml: %v", err)
			}
			expectShown(t, expectLoaded(t, folder, frFR), frShown)
		})
	})
}
