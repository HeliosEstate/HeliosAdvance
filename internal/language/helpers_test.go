// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// What the language package's rows share: the test's own copy of the page's en-us file and of a
// French one, the test's own writer of TOML strings, a lang folder made for each row, Load called
// with a bound on its wait, and the checks of a refusal and of the texts a Texts shows. None of
// the package's constants or code is used, so a fault there cannot hide in the oracle too.
package language_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/language"
	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// The page's names and limits, written here so a changed constant in the package cannot move a
// test with it.
const (
	langFolder      = "lang"
	fallbackCode    = "en-us"
	keyGreeting     = "session.greeting"
	keyNamePrompt   = "session.name_prompt"
	keyNameReply    = "session.name_reply"
	placeholderName = "NAME"
	mostFileBytes   = 1 << 20
)

// The page's en-us file, word for word.
const (
	enUSName       = "English (United States)"
	enUSGreeting   = "Hello Helios Advance BBS!"
	enUSNamePrompt = "What is your name? "
	enUSNameReply  = "Hello {$NAME}"
)

// A full French translation the rows use as the board's language.
const (
	frName       = "Français"
	frGreeting   = "Bonjour, BBS Helios Advance !"
	frNamePrompt = "Quel est votre nom ? "
	frNameReply  = "Bonjour {$NAME}"
)

// marker is written into every file the rows make, so a refusal's message can be checked for
// holding nothing the file holds.
const marker = "QX7-MARKER-9V"

// callerName is the name every row gives the name reply, and otherName another.
const (
	callerName = "ann"
	otherName  = "bob"
)

// The codes of the languages the rows write, beside en-us.
const (
	frFR = "fr-fr"
	frCA = "fr-ca"
	deDE = "de-de"
	esES = "es-es"
	esMX = "es-mx"
)

// The texts' own names inside the table session.
const (
	shortGreeting   = "greeting"
	shortNamePrompt = "name_prompt"
	shortNameReply  = "name_reply"
)

// Texts several rows write.
const (
	namePlaceholder  = "{$NAME}"
	twicePlaceholder = "{$NAME} et {$NAME}"
	localDeclaration = ".local $x = {1} {{a}}"
	enUSReplyStart   = "Hello "
)

// tomlString writes text as a TOML basic string: the quotation mark, the backslash and every
// control character, U+0000 to U+001F and U+007F to U+009F, escaped as TOML 1.0 and 1.1 both
// read them, so the file holds exactly the characters text names.
func tomlString(text string) string {
	var written strings.Builder
	written.WriteByte('"')
	for _, character := range text {
		switch {
		case character == '"':
			written.WriteString(`\"`)
		case character == '\\':
			written.WriteString(`\\`)
		case character < 0x20 || (character >= 0x7F && character <= 0x9F):
			fmt.Fprintf(&written, `\u%04X`, character)
		default:
			written.WriteRune(character)
		}
	}
	written.WriteByte('"')
	return written.String()
}

// entry is one TOML key and its string value.
func entry(key, text string) string {
	return key + " = " + tomlString(text)
}

// fileOf is a language file's text: a comment holding the marker, the lines given for its top,
// the table session holding the lines given for it, and the lines given after it.
func fileOf(top, session []string, after ...string) string {
	lines := append([]string{"# " + marker}, top...)
	lines = append(lines, "", "[session]")
	lines = append(lines, session...)
	lines = append(lines, after...)
	return strings.Join(lines, "\n") + "\n"
}

// enUSFile is the page's en-us file.
func enUSFile() string {
	return fileOf([]string{entry("name", enUSName)}, []string{
		entry(shortGreeting, enUSGreeting), entry(shortNamePrompt, enUSNamePrompt), entry(shortNameReply, enUSNameReply),
	})
}

// frSession is the French texts, with the line of each short key named in replace put in place
// of that key's own; a replacement of "" leaves the key out.
func frSession(replace map[string]string) []string {
	var lines []string
	for _, each := range []struct{ key, text string }{
		{shortGreeting, frGreeting}, {shortNamePrompt, frNamePrompt}, {shortNameReply, frNameReply},
	} {
		line, replaced := replace[each.key]
		if !replaced {
			line = entry(each.key, each.text)
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// frFile is the French file with no parent, its texts as frSession gives them.
func frFile(replace map[string]string) string {
	return fileOf([]string{entry("name", frName)}, frSession(replace))
}

// shortKey is a key's name inside the table session.
func shortKey(key string) string {
	return strings.TrimPrefix(key, "session.")
}

// makeLang makes a lang folder in the row's own temporary folder, holding each language given as
// its code and its file's text, and returns the folder's path.
func makeLang(t *testing.T, languages map[string]string) string {
	t.Helper()
	folder := filepath.Join(t.TempDir(), langFolder)
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatalf("making the lang folder: %v", err)
	}
	for code, text := range languages {
		writeLanguage(t, folder, code, []byte(text))
	}
	return folder
}

// writeLanguage makes the folder code in folder and writes contents as its file code.toml.
func writeLanguage(t *testing.T, folder, code string, contents []byte) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(folder, code), 0o700); err != nil {
		t.Fatalf("making the folder %s: %v", code, err)
	}
	path := filepath.Join(folder, code, code+".toml")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

// fileName is the name of a language's file, which a refusal's message names.
func fileName(code string) string {
	return code + ".toml"
}

// loaded is what one Load returned, or the panic it raised.
type loaded struct {
	texts    *language.Texts
	err      error
	panicked any
}

// load calls Load on a goroutine of its own and waits for it no longer than the hang bound, so a
// Load that hangs or panics fails its row by name.
func load(t *testing.T, folder, code string) (*language.Texts, error) {
	t.Helper()
	done := make(chan loaded, 1)
	go func() {
		defer func() {
			if value := recover(); value != nil {
				done <- loaded{panicked: value}
			}
		}()
		texts, err := language.Load(folder, code)
		done <- loaded{texts: texts, err: err}
	}()
	bound := testrun.Patient(testrun.HangBound)
	timer := time.NewTimer(bound)
	defer timer.Stop()
	select {
	case got := <-done:
		if got.panicked != nil {
			t.Fatalf("Load panicked: %v", got.panicked)
		}
		return got.texts, got.err
	case <-timer.C:
		t.Fatalf("Load did not return within %v", bound)
		return nil, nil
	}
}

// expectLoaded fails the row unless Load returns a Texts and no error.
func expectLoaded(t *testing.T, folder, code string) *language.Texts {
	t.Helper()
	texts, err := load(t, folder, code)
	if err != nil || texts == nil {
		t.Fatalf("Load(%q) returned (%v, %v), want a Texts and no error", code, texts, err)
	}
	return texts
}

// expectRefused fails the row unless Load returns no Texts and ErrFileRefused, never
// ErrNotInstalled, with a message naming named and holding no part of the marker every file the
// rows write holds.
func expectRefused(t *testing.T, folder, code, named string) {
	t.Helper()
	texts, err := load(t, folder, code)
	if texts != nil || !errors.Is(err, language.ErrFileRefused) || errors.Is(err, language.ErrNotInstalled) {
		t.Fatalf("Load(%q) returned (%v, %v), want no Texts and ErrFileRefused", code, texts, err)
	}
	if !strings.Contains(err.Error(), named) {
		t.Fatalf("the refusal %q does not name %s", err.Error(), named)
	}
	if strings.Contains(err.Error(), marker[:6]) || strings.Contains(err.Error(), marker[4:]) {
		t.Fatalf("the refusal %q holds what the file holds", err.Error())
	}
}

// expectRefusedNaming is expectRefused for a refusal that may name any one of the files given,
// such as a chain of parents that leads back, which every language in it does.
func expectRefusedNaming(t *testing.T, folder, code string, named ...string) {
	t.Helper()
	texts, err := load(t, folder, code)
	if texts != nil || !errors.Is(err, language.ErrFileRefused) || errors.Is(err, language.ErrNotInstalled) {
		t.Fatalf("Load(%q) returned (%v, %v), want no Texts and ErrFileRefused", code, texts, err)
	}
	if !slices.ContainsFunc(named, func(name string) bool { return strings.Contains(err.Error(), name) }) {
		t.Fatalf("the refusal %q names none of %v", err.Error(), named)
	}
	if strings.Contains(err.Error(), marker[:6]) || strings.Contains(err.Error(), marker[4:]) {
		t.Fatalf("the refusal %q holds what the file holds", err.Error())
	}
}

// expectNotInstalled fails the row unless Load returns no Texts and ErrNotInstalled, never
// ErrFileRefused.
func expectNotInstalled(t *testing.T, folder, code string) {
	t.Helper()
	texts, err := load(t, folder, code)
	if texts != nil || !errors.Is(err, language.ErrNotInstalled) || errors.Is(err, language.ErrFileRefused) {
		t.Fatalf("Load(%q) returned (%v, %v), want no Texts and ErrNotInstalled", code, texts, err)
	}
}

// shown is what a Texts shows: its three texts, the name reply given callerName, and its Missing.
type shown struct {
	greeting, namePrompt, nameReply string
	missing                         []string
}

var (
	enUSShown = shown{enUSGreeting, enUSNamePrompt, "Hello " + callerName, nil}
	frShown   = shown{frGreeting, frNamePrompt, "Bonjour " + callerName, nil}
)

// with is view with key's text replaced by text.
func (view shown) with(key, text string) shown {
	switch key {
	case keyGreeting:
		view.greeting = text
	case keyNamePrompt:
		view.namePrompt = text
	case keyNameReply:
		view.nameReply = text
	}
	return view
}

// from is view with key's text taken from other.
func (view shown) from(key string, other shown) shown {
	return view.with(key, other.text(key))
}

// text is view's text for key.
func (view shown) text(key string) string {
	switch key {
	case keyGreeting:
		return view.greeting
	case keyNamePrompt:
		return view.namePrompt
	default:
		return view.nameReply
	}
}

// missingFrom is view with Missing naming keys, in the order given.
func (view shown) missingFrom(keys ...string) shown {
	view.missing = keys
	return view
}

// textOf is texts' text for key, the name reply given callerName.
func textOf(texts *language.Texts, key string) string {
	if key == keyNameReply {
		return texts.Text(key, language.Value{Name: placeholderName, Text: callerName})
	}
	return texts.Text(key)
}

// expectShown fails the row unless texts shows exactly want.
func expectShown(t *testing.T, texts *language.Texts, want shown) {
	t.Helper()
	for _, key := range []string{keyGreeting, keyNamePrompt, keyNameReply} {
		if got := textOf(texts, key); got != want.text(key) {
			t.Errorf("Text(%q) is %q, want %q", key, got, want.text(key))
		}
	}
	if got := texts.Missing(); !slices.Equal(got, want.missing) {
		t.Errorf("Missing() is %q, want %q", got, want.missing)
	}
}

// isControlOrBidi is the contract's own list: a control character, U+0000 to U+001F or U+007F to
// U+009F, or a bidi control, U+061C, U+200E, U+200F, U+202A to U+202E or U+2066 to U+2069.
func isControlOrBidi(character rune) bool {
	switch {
	case character <= 0x1F, character >= 0x7F && character <= 0x9F:
		return true
	case character == 0x061C, character == 0x200E, character == 0x200F:
		return true
	case character >= 0x202A && character <= 0x202E, character >= 0x2066 && character <= 0x2069:
		return true
	}
	return false
}
