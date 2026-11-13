// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The language files' refusals that need a file or folder the program's own account cannot read,
// which a mode of 000 gives on Linux to an account that is not root, and the entries in lang it
// fails to open, links and sockets among them.
package main_test

import (
	"os"
	"path/filepath"
	"syscall"
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

	t.Run("If the engine fails to open an entry in the `lang` folder, other than a plain file, whose name is a well-formed language tag in any case, to tell whether it is a language, such as a link to nothing, a link leading out of the folder, a folder the engine has no right to read, or a socket, then the engine shall write one `start_failed` line naming the file that entry would hold and why, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("de-de a relative symbolic link to nothing: start_failed naming de-de/de-de.toml", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile()})
			if err := os.Symlink("gone", filepath.Join(folder, langFolder, deDE)); err != nil {
				t.Fatalf("linking de-de to nothing: %v", err)
			}
			expectRefusalNaming(t, startPlaced(t, programFile), entryFile(deDE))
		})
		t.Run("de-de a symbolic link to a folder outside lang holding a valid de-de.toml: start_failed naming de-de/de-de.toml", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile()})
			if err := os.Symlink(outsideLanguage(t, deDE), filepath.Join(folder, langFolder, deDE)); err != nil {
				t.Fatalf("linking de-de to a folder outside: %v", err)
			}
			expectRefusalNaming(t, startPlaced(t, programFile), entryFile(deDE))
		})
		t.Run("de-de a folder of mode 000 holding a valid de-de.toml: start_failed naming de-de/de-de.toml", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile(), deDE: deFile()})
			unreadable(t, filepath.Join(folder, langFolder, deDE), 0o700)
			expectRefusalNaming(t, startPlaced(t, programFile), entryFile(deDE))
		})
		t.Run("de-de a socket: start_failed naming de-de/de-de.toml", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile()})
			makeSocket(t, filepath.Join(folder, langFolder, deDE))
			expectRefusalNaming(t, startPlaced(t, programFile), entryFile(deDE))
		})
		t.Run("Fr-FR a relative symbolic link to nothing, a tag in mixed case: start_failed naming Fr-FR/Fr-FR.toml", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile()})
			if err := os.Symlink("gone", filepath.Join(folder, langFolder, "Fr-FR")); err != nil {
				t.Fatalf("linking Fr-FR to nothing: %v", err)
			}
			expectRefusalNaming(t, startPlaced(t, programFile), entryFile("Fr-FR"))
		})
		t.Run(".#README.txt, an editor's lock file, a symbolic link to nothing, the edge inside: left alone, it starts in en-us", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile()})
			if err := os.Symlink("ann@host.1234:1700000000", filepath.Join(folder, langFolder, ".#README.txt")); err != nil {
				t.Fatalf("linking .#README.txt to nothing: %v", err)
			}
			expectLeftAlone(t, programFile)
		})
		t.Run("outside_lang, a symbolic link to a folder outside lang holding a valid de-de.toml, the edge inside: left alone, it starts in en-us", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile()})
			if err := os.Symlink(outsideLanguage(t, deDE), filepath.Join(folder, langFolder, "outside_lang")); err != nil {
				t.Fatalf("linking outside_lang to a folder outside: %v", err)
			}
			expectLeftAlone(t, programFile)
		})
		t.Run("my_private, a folder of mode 000, the edge inside: left alone, it starts in en-us", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile()})
			private := filepath.Join(folder, langFolder, "my_private")
			if err := os.Mkdir(private, 0o700); err != nil {
				t.Fatalf("making my_private: %v", err)
			}
			unreadable(t, private, 0o700)
			expectLeftAlone(t, programFile)
		})
		t.Run("app.sock, a socket, the edge inside: left alone, it starts in en-us", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile()})
			makeSocket(t, filepath.Join(folder, langFolder, "app.sock"))
			expectLeftAlone(t, programFile)
		})
		t.Run("de-de a plain file of mode 000, named as a tag, the edge inside: left alone, it starts in en-us", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile()})
			plain := filepath.Join(folder, langFolder, deDE)
			if err := os.WriteFile(plain, []byte("notes"), 0o600); err != nil {
				t.Fatalf("writing the plain file de-de: %v", err)
			}
			unreadable(t, plain, 0o600)
			expectLeftAlone(t, programFile)
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

// outsideLanguage writes a valid language file for code in a lang folder of the row's own, apart
// from the program's, and returns the path of its folder code.
func outsideLanguage(t *testing.T, code string) string {
	t.Helper()
	outside := t.TempDir()
	writeLanguages(t, outside, map[string]string{code: deFile()})
	return filepath.Join(outside, langFolder, code)
}
