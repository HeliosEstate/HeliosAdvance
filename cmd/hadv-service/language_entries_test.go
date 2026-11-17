// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The limit on how many entries the lang folder, or a folder in it, holds, driven from outside:
// the lang folder and a language's folder, each one entry over the limit and at it, the entries
// files and folders alike.
package main_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// mostEntries is the page's limit, written here so a changed constant in the engine cannot move
// a test with it.
const mostEntries = 256

// fillLangFolder adds entries to the folder inside folder's lang folder, written with slashes, ""
// for lang itself, until it holds count: every other one an empty folder and the rest empty files.
// None is a language: a folder holds no file of its own name.
func fillLangFolder(t *testing.T, folder, inside string, count int) {
	t.Helper()
	filled := filepath.Join(folder, langFolder, filepath.FromSlash(inside))
	if err := os.MkdirAll(filled, 0o700); err != nil {
		t.Fatalf("making %s: %v", filled, err)
	}
	entries, err := os.ReadDir(filled)
	if err != nil {
		t.Fatalf("listing %s: %v", filled, err)
	}
	for index := len(entries); index < count; index++ {
		path := filepath.Join(filled, fmt.Sprintf("entry-%04d", index))
		if index%2 == 0 {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatalf("making %s: %v", path, err)
			}
			continue
		}
		if err := os.WriteFile(path+".txt", nil, 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
	}
	if entries, err = os.ReadDir(filled); err != nil || len(entries) != count {
		t.Fatalf("the row made %s hold %d entries (%v), not %d", filled, len(entries), err, count)
	}
}

// expectRefusalNamingFolder waits for a program that must refuse to start and checks its one
// start_failed line names the folder called name, as folderWord matches it.
func expectRefusalNamingFolder(t *testing.T, program *run, name string) {
	t.Helper()
	reason := unquoted(program.expectRefusal(t))
	if !folderWord(name).MatchString(reason) {
		t.Fatalf("the start_failed line %q does not name the folder %s", reason, name)
	}
}

func TestLanguageEntries(t *testing.T) {
	t.Parallel()
	t.Run("If the `lang` folder, or a folder in it, holds more than 256 entries, then the engine shall write one `start_failed` line naming the folder and why, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		for _, each := range []struct {
			name, inside, named string
			options             []string
			shown               func(string) string
		}{
			{"the lang folder", "", langFolder, nil, enUSShown},
			{"fr-fr's folder, with -lang fr-fr", frFR, frFR, []string{langOption, frFR}, frShown},
		} {
			t.Run(each.name+" of 257 entries, files and folders: one start_failed line naming it, and a non-zero exit", func(t *testing.T) {
				t.Parallel()
				folder, programFile := placeProgram(t)
				writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile(), frFR: frFile()})
				fillLangFolder(t, folder, each.inside, mostEntries+1)
				expectRefusalNamingFolder(t, startPlaced(t, programFile, each.options...), each.named)
			})
			t.Run(each.name+" of 256 entries, files and folders, the edge inside: it starts and shows its texts", func(t *testing.T) {
				t.Parallel()
				folder, programFile := placeProgram(t)
				writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile(), frFR: frFile()})
				fillLangFolder(t, folder, each.inside, mostEntries)
				expectShown(t, startPlaced(t, programFile, each.options...).telnetAmidMissing(t)[0], languageCaller, each.shown(languageCaller))
			})
		}
	})
}
