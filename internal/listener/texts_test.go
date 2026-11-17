// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The board's texts every Listener and Session row is given: loaded by the language package from
// a lang folder the row writes, holding the test's own copy of the page's en-us file, never the
// shipped one, so a change to the shipped file cannot move these rows; and a test language,
// xx-test, whose texts are not ASCII.
package listener_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/language"
)

// enUSFile is the page's en-us file, word for word.
const enUSFile = `name = "English (United States)"

[session]
greeting = "Hello Helios Advance BBS!"
name_prompt = "What is your name? "
name_reply = "Hello {$NAME}"
`

// annEnded is the name ann ended by CR, as a caller types it.
const annEnded = "ann\r"

// The test language's code, its texts as it shows them, and its file.
const (
	testCode       = "xx-test"
	testGreeting   = "Grüß Gott, Helios Advance BBS!"
	testNamePrompt = "Wie heißen Sie？ "
	testReply      = "Grüß dich, "
	testFile       = `name = "Test (Grüß)"

[session]
greeting = "Grüß Gott, Helios Advance BBS!"
name_prompt = "Wie heißen Sie？ "
name_reply = "Grüß dich, {$NAME}!"
`
)

// writeLang writes a lang folder in the row's own temporary folder holding each language given as
// its code and its file's text, and returns its path.
func writeLang(t *testing.T, languages map[string]string) string {
	t.Helper()
	folder := filepath.Join(t.TempDir(), "lang")
	for code, text := range languages {
		if err := os.MkdirAll(filepath.Join(folder, code), 0o700); err != nil {
			t.Fatalf("making the language folder %s: %v", code, err)
		}
		if err := os.WriteFile(filepath.Join(folder, code, code+".toml"), []byte(text), 0o600); err != nil {
			t.Fatalf("writing the language file %s: %v", code, err)
		}
	}
	return folder
}

// loadTexts loads the board's texts in code from the languages given, en-us always among them,
// and fails the row when Load refuses.
func loadTexts(t *testing.T, code string, languages map[string]string) *language.Texts {
	t.Helper()
	all := map[string]string{"en-us": enUSFile}
	for each, text := range languages {
		all[each] = text
	}
	return loadFrom(t, writeLang(t, all), code)
}

// loadFrom loads the board's texts in code from folder, and fails the row when Load refuses or
// does not return within the hang bound.
func loadFrom(t *testing.T, folder, code string) *language.Texts {
	t.Helper()
	type loaded struct {
		texts *language.Texts
		err   error
	}
	done := make(chan loaded, 1)
	go func() {
		texts, err := language.Load(folder, code)
		done <- loaded{texts: texts, err: err}
	}()
	timer := time.NewTimer(progressLimit)
	defer timer.Stop()
	select {
	case got := <-done:
		if got.err != nil || got.texts == nil {
			t.Fatalf("setting up: loading the texts in %s returned (%v, %v)", code, got.texts, got.err)
		}
		return got.texts
	case <-timer.C:
		t.Fatalf("setting up: loading the texts in %s did not return within %v", code, progressLimit)
		return nil
	}
}

// enUSTexts is the board's texts in en-us, the page's own.
func enUSTexts(t *testing.T) *language.Texts {
	t.Helper()
	return loadTexts(t, "en-us", nil)
}
