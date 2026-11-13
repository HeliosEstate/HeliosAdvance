// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Load's lines on Linux that need the system's own links, modes and sockets: a language's folder
// or file a symbolic link out of the lang folder, a file link that stays inside it, and an entry
// that cannot be opened, refused when named as a language tag and left alone when not.
package language_test

import (
	"os"
	"path/filepath"
	"syscall"
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
		t.Run("fr-fr's folder of mode 0000, fr-fr.toml in it, the board en-us: ErrFileRefused naming fr-fr.toml", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), frFR: frFile(nil)})
			makeUnopenable(t, filepath.Join(folder, frFR))
			expectRefused(t, folder, fallbackCode, fileName(frFR))
		})
		t.Run("fr-fr a relative symbolic link to nothing, the board en-us: ErrFileRefused naming fr-fr.toml", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			if err := os.Symlink("gone", filepath.Join(folder, frFR)); err != nil {
				t.Fatalf("linking fr-fr to nothing: %v", err)
			}
			expectRefused(t, folder, fallbackCode, fileName(frFR))
		})
		t.Run("fr-fr a socket, the board en-us: ErrFileRefused naming fr-fr.toml", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			makeSocket(t, filepath.Join(folder, frFR))
			expectRefused(t, folder, fallbackCode, fileName(frFR))
		})
		t.Run("fr-fr a plain file of mode 0000, named as a tag, the edge inside: no language, left alone, loads", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			if err := os.WriteFile(filepath.Join(folder, frFR), []byte("notes"), 0o600); err != nil {
				t.Fatalf("writing the plain file fr-fr: %v", err)
			}
			makeUnopenable(t, filepath.Join(folder, frFR))
			expectShown(t, expectLoaded(t, folder, fallbackCode), enUSShown)
		})
	})

	t.Run("If a language's folder name is not a well-formed language tag in lower case, then Load shall return ErrFileRefused naming its file.", func(t *testing.T) {
		t.Parallel()
		t.Run("Fr-FR a relative symbolic link to nothing, a tag in mixed case: ErrFileRefused naming Fr-FR.toml", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			if err := os.Symlink("gone", filepath.Join(folder, "Fr-FR")); err != nil {
				t.Fatalf("linking Fr-FR to nothing: %v", err)
			}
			expectRefused(t, folder, fallbackCode, fileName("Fr-FR"))
		})
		t.Run("e, a name of one letter that is no tag, a relative symbolic link to nothing, the edge inside: no language, left alone, loads", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			if err := os.Symlink("gone", filepath.Join(folder, "e")); err != nil {
				t.Fatalf("linking e to nothing: %v", err)
			}
			expectShown(t, expectLoaded(t, folder, fallbackCode), enUSShown)
		})
		t.Run(".#README.txt, an editor's lock file, a symbolic link to nothing, the edge inside: no language, left alone, loads", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			if err := os.Symlink("ann@host.1234:1700000000", filepath.Join(folder, ".#README.txt")); err != nil {
				t.Fatalf("linking .#README.txt to nothing: %v", err)
			}
			expectShown(t, expectLoaded(t, folder, fallbackCode), enUSShown)
		})
		t.Run("outside_lang, a symbolic link to a folder outside holding fr-fr.toml, the edge inside: no language, left alone, loads", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			if err := os.Symlink(outside(t, folder), filepath.Join(folder, "outside_lang")); err != nil {
				t.Fatalf("linking outside_lang to a folder outside: %v", err)
			}
			expectShown(t, expectLoaded(t, folder, fallbackCode), enUSShown)
		})
		t.Run("my_private, a folder of mode 0000, the edge inside: no language, left alone, loads", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			if err := os.Mkdir(filepath.Join(folder, "my_private"), 0o700); err != nil {
				t.Fatalf("making my_private/: %v", err)
			}
			makeUnopenable(t, filepath.Join(folder, "my_private"))
			expectShown(t, expectLoaded(t, folder, fallbackCode), enUSShown)
		})
		t.Run("app.sock, a socket, the edge inside: no language, left alone, loads", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			makeSocket(t, filepath.Join(folder, "app.sock"))
			expectShown(t, expectLoaded(t, folder, fallbackCode), enUSShown)
		})
	})
}

// makeSocket makes a socket at path with mknod, bound by nothing, which an open fails on as it
// does on a bound one; a socket's address is too short for some of the rows' folders.
func makeSocket(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mknod(path, syscall.S_IFSOCK|0o600, 0); err != nil {
		t.Fatalf("making a socket at %s: %v", path, err)
	}
}
