// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Load's lines on Windows that need the system's own links and handles: a language's folder a
// junction out of the lang folder, a file or folder held open with no sharing, and an entry that
// cannot be opened, refused when named as a language tag and left alone when not. A symbolic link
// to a file needs a privilege only an elevated process holds, so those rows are
// TestWindowsElevated's. The count of bytes this process has read is Linux's alone here: Windows
// gives it only through a raw pointer, which the engine's imports refuse, or by asking another
// program, which timed out on CI's runner.
package language_test

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

// makeUnopenable holds a file or folder open with no sharing until the row ends: a file for
// reading and writing, a folder for reading, which no other open gets past, the elevated runner's
// backup intent included. It still shows as there.
func makeUnopenable(t *testing.T, path string) {
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

// junctionOutside puts at lang's fr-fr a junction to a folder outside lang holding fr-fr.toml,
// the full French file: the link a Windows account makes without any privilege.
func junctionOutside(t *testing.T, lang string) {
	t.Helper()
	// cmd reads a comma as a space, and a row's folder carries its name's commas: mklink is given
	// names relative to the folder holding lang, never a full path.
	base := filepath.Dir(lang)
	writeLanguage(t, filepath.Join(base, "outside"), frFR, []byte(frFile(nil)))
	ctx, cancel := context.WithTimeout(context.Background(), testrun.Patient(testrun.HangBound))
	defer cancel()
	command := exec.CommandContext(ctx, "cmd", "/c", "mklink", "/J", filepath.Join(langFolder, frFR), filepath.Join("outside", frFR))
	command.Dir = base
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("making a junction at fr-fr: %v: %s", err, strings.TrimSpace(string(output)))
	}
}

// symlinkTo puts at link a symbolic link to target. Making one needs a privilege only an elevated
// process holds here.
func symlinkTo(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("linking %s to %s: %v", link, target, err)
	}
}

func TestWindowsLoad(t *testing.T) {
	t.Parallel()

	t.Run("If a language's folder or file is a link leading out of folder, or its file cannot be read, then Load shall return ErrFileRefused naming the file.", func(t *testing.T) {
		t.Parallel()
		t.Run("the language's folder a junction to a folder outside: ErrFileRefused naming its file", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			junctionOutside(t, folder)
			expectRefused(t, folder, fallbackCode, fileName(frFR))
		})
		t.Run("fr-fr's folder held open with no sharing, fr-fr.toml in it, the board en-us: ErrFileRefused naming fr-fr.toml", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), frFR: frFile(nil)})
			makeUnopenable(t, filepath.Join(folder, frFR))
			expectRefused(t, folder, fallbackCode, fileName(frFR))
		})
		t.Run("fr-fr a junction to a folder since removed, the board en-us: ErrFileRefused naming fr-fr.toml", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			junctionToNothing(t, folder, frFR)
			expectRefused(t, folder, fallbackCode, fileName(frFR))
		})
		t.Run("fr-fr a plain file held open with no sharing, named as a tag, the edge inside: no language, left alone, loads", func(t *testing.T) {
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
		t.Run("Fr-FR a junction to a folder since removed, a tag in mixed case: ErrFileRefused naming Fr-FR.toml", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			junctionToNothing(t, folder, "Fr-FR")
			expectRefused(t, folder, fallbackCode, fileName("Fr-FR"))
		})
		t.Run("e, a name of one letter that is no tag, a junction to a folder since removed, the edge inside: no language, left alone, loads", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			junctionToNothing(t, folder, "e")
			expectShown(t, expectLoaded(t, folder, fallbackCode), enUSShown)
		})
		t.Run(".#README.txt a junction to a folder since removed, the edge inside: no language, left alone, loads", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			junctionToNothing(t, folder, ".#README.txt")
			expectShown(t, expectLoaded(t, folder, fallbackCode), enUSShown)
		})
		t.Run("outside_lang, a junction to a folder outside holding fr-fr.toml, the edge inside: no language, left alone, loads", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			base := filepath.Dir(folder)
			writeLanguage(t, filepath.Join(base, "outside"), frFR, []byte(frFile(nil)))
			junction(t, base, "outside_lang", filepath.Join("outside", frFR))
			expectShown(t, expectLoaded(t, folder, fallbackCode), enUSShown)
		})
		t.Run("my_private, a folder held open with no sharing, the edge inside: no language, left alone, loads", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			if err := os.Mkdir(filepath.Join(folder, "my_private"), 0o700); err != nil {
				t.Fatalf("making my_private/: %v", err)
			}
			makeUnopenable(t, filepath.Join(folder, "my_private"))
			expectShown(t, expectLoaded(t, folder, fallbackCode), enUSShown)
		})
	})
}

// junction puts in the lang folder beside base an entry called name, a junction to target, a path
// relative to base. cmd reads a comma as a space, and a row's folder carries its name's commas, so
// mklink is given relative names, run in base.
func junction(t *testing.T, base, name, target string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testrun.Patient(testrun.HangBound))
	defer cancel()
	command := exec.CommandContext(ctx, "cmd", "/c", "mklink", "/J", filepath.Join(langFolder, name), target)
	command.Dir = base
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("making a junction at %s: %v: %s", name, err, strings.TrimSpace(string(output)))
	}
}

// junctionToNothing puts in lang an entry called name, a junction to a folder it then removes.
func junctionToNothing(t *testing.T, lang, name string) {
	t.Helper()
	base := filepath.Dir(lang)
	if err := os.Mkdir(filepath.Join(base, "gone"), 0o700); err != nil {
		t.Fatalf("making the folder the junction leads to: %v", err)
	}
	junction(t, base, name, "gone")
	if err := os.Remove(filepath.Join(base, "gone")); err != nil {
		t.Fatalf("removing the folder the junction leads to: %v", err)
	}
}

// TestWindowsElevatedLoad holds the rows only an elevated process can set up: a symbolic link to
// a file. CI's Windows runner is elevated.
func TestWindowsElevatedLoad(t *testing.T) {
	t.Parallel()

	t.Run("If a language's folder or file is a link leading out of folder, or its file cannot be read, then Load shall return ErrFileRefused naming the file.", func(t *testing.T) {
		t.Parallel()
		t.Run("the language's file a symbolic link to a file outside: ErrFileRefused naming it", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			target := writeLanguage(t, filepath.Join(filepath.Dir(folder), "outside"), frFR, []byte(frFile(nil)))
			if err := os.Mkdir(filepath.Join(folder, frFR), 0o700); err != nil {
				t.Fatalf("making fr-fr/: %v", err)
			}
			symlinkTo(t, target, filepath.Join(folder, frFR, fileName(frFR)))
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
			symlinkTo(t, "real.toml", filepath.Join(folder, frFR, fileName(frFR)))
			expectShown(t, expectLoaded(t, folder, frFR), frShown)
		})
	})
}
