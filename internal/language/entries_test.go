// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The limit on how many entries the language folder, or a folder in it, holds: the language folder
// itself, a language's folder, the fallback's and a folder that is no language, each one entry over
// the limit and at it. The entries are files and folders alike, so a count of one kind falls short.
package language_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/language"
)

// mostEntries is the contract's limit, written here so a changed constant in the engine cannot
// move a test with it.
const mostEntries = 256

// notesFolder is a folder in lang that is no language: it holds no file of its own name.
const notesFolder = "notes"

// fillFolder adds count entries to folder, every other one an empty folder and the rest empty
// files, each named after prefix and its number. None is a language: a folder holds no file of
// its own name.
func fillFolder(t *testing.T, folder, prefix string, count int) {
	t.Helper()
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatalf("making %s: %v", folder, err)
	}
	for index := range count {
		path := filepath.Join(folder, fmt.Sprintf("%s-%04d", prefix, index))
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
}

// entryCount is how many entries folder holds, so a row can show it made the count it says.
func entryCount(t *testing.T, folder string) int {
	t.Helper()
	entries, err := os.ReadDir(folder)
	if err != nil {
		t.Fatalf("listing %s: %v", folder, err)
	}
	return len(entries)
}

// namesFolder says whether reason names the folder called name: the name as a word of its own,
// not followed by a path separator, as a path to something inside it is, nor by .toml, as the
// language's own file is. A word joined to others by an underscore or a hyphen, as in the row's
// temporary folder, does not count.
func namesFolder(reason, name string) bool {
	word := regexp.MustCompile(`(^|[^A-Za-z0-9_-])` + regexp.QuoteMeta(name) + `($|[^A-Za-z0-9_./\\-]|\.$|\.[^A-Za-z0-9])`)
	return word.MatchString(reason)
}

// expectFolderRefused fails the row unless Load returns no Texts and ErrFileRefused naming the
// folder called name, and holding no part of the marker every file the rows write holds.
func expectFolderRefused(t *testing.T, folder, code, name string) {
	t.Helper()
	texts, err := load(t, folder, code)
	if texts != nil || !errors.Is(err, language.ErrFileRefused) || errors.Is(err, language.ErrNotInstalled) {
		t.Fatalf("Load(%q) returned (%v, %v), want no Texts and ErrFileRefused", code, texts, err)
	}
	if !namesFolder(err.Error(), name) {
		t.Fatalf("the refusal %q does not name the folder %s", err.Error(), name)
	}
	if strings.Contains(err.Error(), marker[:6]) || strings.Contains(err.Error(), marker[4:]) {
		t.Fatalf("the refusal %q holds what the file holds", err.Error())
	}
}

// overLimit is a lang folder of en-us and fr-fr, with the folder inside it given, "" for lang
// itself, filled with entries named after prefix until it holds count, and returns lang.
func overLimit(t *testing.T, inside, prefix string, count int) string {
	t.Helper()
	folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), frFR: frFile(nil)})
	filled := filepath.Join(folder, inside)
	if err := os.MkdirAll(filled, 0o700); err != nil {
		t.Fatalf("making %s: %v", filled, err)
	}
	fillFolder(t, filled, prefix, count-entryCount(t, filled))
	if held := entryCount(t, filled); held != count {
		t.Fatalf("the row made %s hold %d entries, not %d", filled, held, count)
	}
	return folder
}

func TestEntries(t *testing.T) {
	t.Parallel()
	t.Run("If folder, or a folder in it, holds more than MostEntries entries, then Load shall return ErrFileRefused naming that folder, having listed no more than MostEntries and one of its entries.", func(t *testing.T) {
		t.Parallel()
		for _, each := range []struct {
			name, inside, named, code string
			shown                     shown
		}{
			{"the lang folder", "", langFolder, fallbackCode, enUSShown},
			{"fr-fr's folder, the board's language", frFR, frFR, frFR, frShown},
			{"en-us's folder, the fallback's", fallbackCode, fallbackCode, fallbackCode, enUSShown},
			{"notes, a folder that is no language", notesFolder, notesFolder, fallbackCode, enUSShown},
		} {
			t.Run(each.name+" of 257 entries, files and folders: ErrFileRefused naming it", func(t *testing.T) {
				t.Parallel()
				expectFolderRefused(t, overLimit(t, each.inside, "entry", mostEntries+1), each.code, each.named)
			})
			t.Run(each.name+" of 256 entries, files and folders, the edge inside: loads, its texts shown", func(t *testing.T) {
				t.Parallel()
				expectShown(t, expectLoaded(t, overLimit(t, each.inside, "entry", mostEntries), each.code), each.shown)
			})
		}
	})
}
