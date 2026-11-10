// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Load's lines on Linux that need the system's own links and modes: a language's folder or file
// a symbolic link out of the lang folder, a file link that stays inside it, and the count of bytes
// this process has read, from /proc/self/io.
package language_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// bytesRead is the bytes this process has read, rchar in /proc/self/io, and how many bytes this
// reading of it read.
func bytesRead(t *testing.T) (count int64, length int64) {
	t.Helper()
	text, err := os.ReadFile("/proc/self/io")
	if err != nil {
		t.Fatalf("reading this process's count of bytes read: %v", err)
	}
	for line := range strings.SplitSeq(string(text), "\n") {
		if value, found := strings.CutPrefix(line, "rchar: "); found {
			count, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				t.Fatalf("reading rchar %q: %v", value, err)
			}
			return count, int64(len(text))
		}
	}
	t.Fatalf("no rchar in /proc/self/io: %q", text)
	return 0, 0
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
