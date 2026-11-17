// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The board's language over SSH: the built program linked into a folder of the row's own, beside a
// lang folder the row writes, started with -lang, and called by QA's own SSH client.
package ssh_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// The page's en-us file and a full French one whose greeting is not ASCII, written here so a
// changed file in the engine cannot move a test with it.
const (
	enUSFileText = "name = \"English (United States)\"\n\n[session]\n" +
		"greeting = \"Hello Helios Advance BBS!\"\nname_prompt = \"What is your name? \"\nname_reply = \"Hello {$NAME}\"\n"
	frFileText = "name = \"Français\"\n\n[session]\n" +
		"greeting = \"Bonjour, BBS Hélios Advance !\"\nname_prompt = \"Quel est votre nom ? \"\nname_reply = \"Bonjour {$NAME} !\"\n"
	frAsked = "Bonjour, BBS H\xc3\xa9lios Advance !\r\nQuel est votre nom ? "
)

// placeLanguages links the built program into a folder of the row's own beside a lang folder
// holding en-us and fr-fr, and returns the program's path. A link is the program itself under a
// second name, in that folder.
func placeLanguages(t *testing.T) string {
	t.Helper()
	if buildFailure != nil {
		t.Fatalf("the program did not build: %v", buildFailure)
	}
	folder := t.TempDir()
	program := filepath.Join(folder, filepath.Base(programPath))
	if err := os.Link(programPath, program); err != nil {
		t.Fatalf("linking the program into the row's folder: %v", err)
	}
	for code, text := range map[string]string{"en-us": enUSFileText, "fr-fr": frFileText} {
		if err := os.MkdirAll(filepath.Join(folder, "lang", code), 0o700); err != nil {
			t.Fatalf("making lang/%s: %v", code, err)
		}
		if err := os.WriteFile(filepath.Join(folder, "lang", code, code+".toml"), []byte(text), 0o600); err != nil {
			t.Fatalf("writing lang/%s/%s.toml: %v", code, code, err)
		}
	}
	return program
}

func TestLanguage(t *testing.T) {
	t.Parallel()

	t.Run("When started with `-lang` and a code, the engine shall show its texts in that language, and without it, in en-us.", func(t *testing.T) {
		t.Parallel()
		t.Run("-lang fr-fr over SSH, QA's client: fr-fr's greeting, beyond ASCII, prompt and reply, byte for byte", func(t *testing.T) {
			t.Parallel()
			program := startEngineAt(t, placeLanguages(t), "-lang", "fr-fr")
			client := readyClient(t, program.ssh, "anyone")
			client.toShell(false)
			client.readUntil(frAsked, time.Now().Add(testrun.Patient(testrun.HangBound)))
			client.sendData(typedBob)
			client.readUntil("Bonjour bob !\r\n", time.Now().Add(testrun.Patient(testrun.HangBound)))
			expectClosingMessages(t, client, "")
			client.expectStream(frAsked + "Bonjour bob !\r\n")
		})
	})
}
