// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The entries in lang the program fails to open on Windows: a junction, the link an account makes
// without any privilege, and a file or folder held open with no sharing. CI's Windows runner is
// elevated and opens past any access list, so a folder the program has no right to read is stood
// for by one held open with no sharing, which fails to open there too.
package main_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// junctionIn puts in the lang folder beside the program an entry called name, a junction to
// target, a path relative to folder. cmd reads a comma as a space, and a row's folder carries its
// name's commas, so mklink is given relative names, run in folder.
func junctionIn(t *testing.T, folder, name, target string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testrun.Patient(testrun.HangBound))
	defer cancel()
	command := exec.CommandContext(ctx, "cmd", "/c", "mklink", "/J", filepath.Join(langFolder, name), target)
	command.Dir = folder
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("making a junction at %s: %v: %s", name, err, strings.TrimSpace(string(output)))
	}
}

// junctionToNothingIn puts in lang an entry called name, a junction to a folder it then removes.
func junctionToNothingIn(t *testing.T, folder, name string) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(folder, "gone"), 0o700); err != nil {
		t.Fatalf("making the folder the junction leads to: %v", err)
	}
	junctionIn(t, folder, name, "gone")
	if err := os.Remove(filepath.Join(folder, "gone")); err != nil {
		t.Fatalf("removing the folder the junction leads to: %v", err)
	}
}

// outsideLanguageIn writes a valid language file for code in a lang folder inside folder, apart
// from the program's, and returns its folder code as a path relative to folder.
func outsideLanguageIn(t *testing.T, folder, code string) string {
	t.Helper()
	writeLanguages(t, filepath.Join(folder, "outside"), map[string]string{code: deFile()})
	return filepath.Join("outside", langFolder, code)
}

// holdUnshared holds a file or folder open with no sharing until the row ends: a file for
// reading and writing, a folder for reading, which no other open gets past, the elevated runner's
// backup intent included. It still shows as there.
func holdUnshared(t *testing.T, path string) {
	t.Helper()
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatalf("naming %s: %v", path, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("reading what %s is: %v", path, err)
	}
	var access uint32 = syscall.GENERIC_READ
	if !info.IsDir() {
		access |= syscall.GENERIC_WRITE
	}
	handle, err := syscall.CreateFile(name, access, 0, nil, syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatalf("holding %s open with no sharing: %v", path, err)
	}
	t.Cleanup(func() {
		if err := syscall.CloseHandle(handle); err != nil {
			t.Errorf("closing %s: %v", path, err)
		}
	})
}

func TestWindowsLanguageFiles(t *testing.T) {
	t.Parallel()

	t.Run("If the engine fails to open an entry in the `lang` folder, other than a plain file, whose name is a well-formed language tag in any case, to tell whether it is a language, such as a link to nothing, a link leading out of the folder, a folder the engine has no right to read, or a socket, then the engine shall write one `start_failed` line naming the file that entry would hold and why, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("de-de a junction to a folder since removed: start_failed naming de-de/de-de.toml", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile()})
			junctionToNothingIn(t, folder, deDE)
			expectRefusalNaming(t, startPlaced(t, programFile), entryFile(deDE))
		})
		t.Run("de-de a junction to a folder outside lang holding a valid de-de.toml: start_failed naming de-de/de-de.toml", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile()})
			junctionIn(t, folder, deDE, outsideLanguageIn(t, folder, deDE))
			expectRefusalNaming(t, startPlaced(t, programFile), entryFile(deDE))
		})
		t.Run("de-de a folder held open with no sharing, holding a valid de-de.toml: start_failed naming de-de/de-de.toml", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile(), deDE: deFile()})
			holdUnshared(t, filepath.Join(folder, langFolder, deDE))
			expectRefusalNaming(t, startPlaced(t, programFile), entryFile(deDE))
		})
		t.Run("Fr-FR a junction to a folder since removed, a tag in mixed case: start_failed naming Fr-FR/Fr-FR.toml", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile()})
			junctionToNothingIn(t, folder, "Fr-FR")
			expectRefusalNaming(t, startPlaced(t, programFile), entryFile("Fr-FR"))
		})
		t.Run(".#README.txt a junction to a folder since removed, the edge inside: left alone, it starts in en-us", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile()})
			junctionToNothingIn(t, folder, ".#README.txt")
			expectLeftAlone(t, programFile)
		})
		t.Run("outside_lang, a junction to a folder outside lang holding a valid de-de.toml, the edge inside: left alone, it starts in en-us", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile()})
			junctionIn(t, folder, "outside_lang", outsideLanguageIn(t, folder, deDE))
			expectLeftAlone(t, programFile)
		})
		t.Run("my_private, a folder held open with no sharing, the edge inside: left alone, it starts in en-us", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile()})
			private := filepath.Join(folder, langFolder, "my_private")
			if err := os.Mkdir(private, 0o700); err != nil {
				t.Fatalf("making my_private: %v", err)
			}
			holdUnshared(t, private)
			expectLeftAlone(t, programFile)
		})
		t.Run("de-de a plain file held open with no sharing, named as a tag, the edge inside: left alone, it starts in en-us", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile()})
			plain := filepath.Join(folder, langFolder, deDE)
			if err := os.WriteFile(plain, []byte("notes"), 0o600); err != nil {
				t.Fatalf("writing the plain file de-de: %v", err)
			}
			holdUnshared(t, plain)
			expectLeftAlone(t, programFile)
		})
	})
}
