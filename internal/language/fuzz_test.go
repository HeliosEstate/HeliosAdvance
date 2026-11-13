// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The contract's fuzz target, the parser of a text, reached through Load and Text: any characters
// as fr-fr's greeting, then as its name reply. Load returns within the hang bound and never
// panics; a text the test's own reading reads gives what it says and is not in Missing; any other
// gives en-us's and is; and no text shown holds a control or bidi character.
package language_test

import (
	"slices"
	"strings"
	"testing"
)

func FuzzText(fuzzing *testing.F) {
	for _, seed := range []string{
		"", "Bonjour", "Bonjour {$NAME}", "{ $NAME }", `\{\}\|\\`, "{", "}", "{{a}}", localDeclaration,
		"{$NAME :string}", "{#b}a{/b}", "a\u0007b", "a\u202Eb", "{\u3000$NAME\u3000}", "{\t$NAME}",
		strings.Repeat("{", 64) + strings.Repeat("}", 64), "\xff", "Grüß {$NAME}",
	} {
		fuzzing.Add(seed)
	}
	fuzzing.Fuzz(func(t *testing.T, text string) {
		// A file that is not UTF-8 is refused whole, which the file rows prove; the target reads
		// texts, so it writes valid UTF-8 alone.
		text = strings.ToValidUTF8(text, "�")
		for _, key := range []string{keyGreeting, keyNameReply} {
			given := []string{}
			if key == keyNameReply {
				given = append(given, placeholderName)
			}
			folder := makeLang(t, map[string]string{
				fallbackCode: enUSFile(),
				frFR:         frFile(map[string]string{shortKey(key): entry(shortKey(key), text)}),
			})
			texts := expectLoaded(t, folder, frFR)
			got := textOf(texts, key)
			missing := slices.Contains(texts.Missing(), key)
			if reading := read(text, nil, given...); reading.kind == kindRead {
				if want := reading.gives(placeholderName, callerName); got != want || missing {
					t.Fatalf("%s %q: Text gives %q, in Missing %v; the test's reading gives %q, not missing", key, text, got, missing, want)
				}
			} else if got != enUSShown.text(key) || !missing {
				t.Fatalf("%s %q, %s: Text gives %q, in Missing %v; want en-us's %q, in Missing", key, text, reading.kind, got, missing, enUSShown.text(key))
			}
			if strings.ContainsFunc(got, isControlOrBidi) {
				t.Fatalf("%s %q: Text gives %q, holding a control or bidi character", key, text, got)
			}
		}
	})
}
