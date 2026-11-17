// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Text's lines, through a Texts Load made from a lang folder the row writes: each escape as the
// one character, a Value's Text put in as its characters, a placeholder with no Value, a Value the
// text does not hold, and a key that is none of the engine's.
package language_test

import (
	"testing"

	"github.com/heliosestate/heliosadvance/internal/language"
)

// frWith loads fr-fr, the board's language, holding the French texts with the short keys given
// written as the texts given.
func frWith(t *testing.T, texts map[string]string) *language.Texts {
	t.Helper()
	replace := map[string]string{}
	for key, text := range texts {
		replace[key] = entry(key, text)
	}
	folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), frFR: frFile(replace)})
	return expectLoaded(t, folder, frFR)
}

func TestText(t *testing.T) {
	t.Parallel()

	t.Run(`Text shall give each escape, \{, \}, \| or \\, as the one character it escapes.`, func(t *testing.T) {
		t.Parallel()
		for name, row := range map[string]struct{ text, want string }{
			`\{ alone`:                    {`\{`, `{`},
			`\} alone`:                    {`\}`, `}`},
			`\| alone`:                    {`\|`, `|`},
			`\\ alone`:                    {`\\`, `\`},
			"all four together":           {`a\{b\}c\|d\\e`, `a{b}c|d\e`},
			`\\ then \{, two escapes`:     {`\\\{`, `\{`},
			`\\\\, two backslashes`:       {`\\\\`, `\\`},
			"an escaped placeholder":      {`\{$NAME\}`, `{$NAME}`},
			"escapes in the whole text":   {`Bonjour \{BBS\} \| Helios \\ Advance`, `Bonjour {BBS} | Helios \ Advance`},
			"escapes at the very start":   {`\{\}`, `{}`},
			"an escape beside a letter":   {`x\|y`, `x|y`},
			"an escaped backslash at end": {`Bonjour\\`, `Bonjour\`},
		} {
			t.Run(name+" in the greeting: "+row.want, func(t *testing.T) {
				t.Parallel()
				texts := frWith(t, map[string]string{shortGreeting: row.text})
				if got := texts.Text(keyGreeting); got != row.want {
					t.Fatalf("Text(%q) is %q, want %q", keyGreeting, got, row.want)
				}
			})
		}
		t.Run(`\{{$NAME}\} in the name reply, given ann: {ann}`, func(t *testing.T) {
			t.Parallel()
			texts := frWith(t, map[string]string{shortNameReply: `\{{$NAME}\}`})
			if got := texts.Text(keyNameReply, language.Value{Name: placeholderName, Text: callerName}); got != "{"+callerName+"}" {
				t.Fatalf("Text(%q) is %q, want %q", keyNameReply, got, "{"+callerName+"}")
			}
		})
		t.Run(`\\{$NAME}\| in the name reply, given ann: \ann|`, func(t *testing.T) {
			t.Parallel()
			texts := frWith(t, map[string]string{shortNameReply: `\\{$NAME}\|`})
			if got := texts.Text(keyNameReply, language.Value{Name: placeholderName, Text: callerName}); got != `\`+callerName+`|` {
				t.Fatalf("Text(%q) is %q, want %q", keyNameReply, got, `\`+callerName+`|`)
			}
		})
	})

	t.Run("Text shall put each Value's Text in its placeholder's place as its characters, never read as a text's syntax.", func(t *testing.T) {
		t.Parallel()
		for _, name := range []string{namePlaceholder, "{#x}", `\{`, "}}", "a|b", "{{x}}", `\\`, "{$NAME :string}", ".local $x = {1}", "{", "Grüß", ""} {
			t.Run("the name "+name+" in the name reply: Bonjour and the name exactly", func(t *testing.T) {
				t.Parallel()
				texts := frWith(t, nil)
				if got := texts.Text(keyNameReply, language.Value{Name: placeholderName, Text: name}); got != "Bonjour "+name {
					t.Fatalf("Text(%q) given %q is %q, want %q", keyNameReply, name, got, "Bonjour "+name)
				}
			})
		}
		t.Run("the name {$NAME} in a reply holding {$NAME} twice: both put in once each, not read again", func(t *testing.T) {
			t.Parallel()
			texts := frWith(t, map[string]string{shortNameReply: twicePlaceholder})
			if got := texts.Text(keyNameReply, language.Value{Name: placeholderName, Text: namePlaceholder}); got != twicePlaceholder {
				t.Fatalf("Text(%q) is %q, want %q", keyNameReply, got, twicePlaceholder)
			}
		})
	})

	t.Run("Text shall replace a placeholder given no Value with nothing, and ignore a Value whose Name the text does not hold.", func(t *testing.T) {
		t.Parallel()
		t.Run("the en-us name reply with no Value: Hello and nothing", func(t *testing.T) {
			t.Parallel()
			texts := expectLoaded(t, makeLang(t, map[string]string{fallbackCode: enUSFile()}), fallbackCode)
			if got := texts.Text(keyNameReply); got != enUSReplyStart {
				t.Fatalf("Text(%q) is %q, want %q", keyNameReply, got, enUSReplyStart)
			}
		})
		t.Run("the en-us name reply given OTHER only: Hello and nothing", func(t *testing.T) {
			t.Parallel()
			texts := expectLoaded(t, makeLang(t, map[string]string{fallbackCode: enUSFile()}), fallbackCode)
			if got := texts.Text(keyNameReply, language.Value{Name: "OTHER", Text: otherName}); got != enUSReplyStart {
				t.Fatalf("Text(%q) is %q, want %q", keyNameReply, got, enUSReplyStart)
			}
		})
		t.Run("the en-us name reply given name in lower case only: Hello and nothing", func(t *testing.T) {
			t.Parallel()
			texts := expectLoaded(t, makeLang(t, map[string]string{fallbackCode: enUSFile()}), fallbackCode)
			if got := texts.Text(keyNameReply, language.Value{Name: "name", Text: otherName}); got != enUSReplyStart {
				t.Fatalf("Text(%q) is %q, want %q", keyNameReply, got, enUSReplyStart)
			}
		})
		t.Run("the en-us name reply given OTHER, then NAME: Hello ann", func(t *testing.T) {
			t.Parallel()
			texts := expectLoaded(t, makeLang(t, map[string]string{fallbackCode: enUSFile()}), fallbackCode)
			got := texts.Text(keyNameReply, language.Value{Name: "OTHER", Text: otherName}, language.Value{Name: placeholderName, Text: callerName})
			if got != enUSReplyStart+callerName {
				t.Fatalf("Text(%q) is %q, want %q", keyNameReply, got, enUSReplyStart+callerName)
			}
		})
		t.Run("the greeting given NAME: the greeting unchanged", func(t *testing.T) {
			t.Parallel()
			texts := expectLoaded(t, makeLang(t, map[string]string{fallbackCode: enUSFile()}), fallbackCode)
			if got := texts.Text(keyGreeting, language.Value{Name: placeholderName, Text: callerName}); got != enUSGreeting {
				t.Fatalf("Text(%q) is %q, want %q", keyGreeting, got, enUSGreeting)
			}
		})
		t.Run("a name reply of {$NAME} and {$NAME} given ann: both replaced", func(t *testing.T) {
			t.Parallel()
			texts := frWith(t, map[string]string{shortNameReply: twicePlaceholder})
			if got := texts.Text(keyNameReply, language.Value{Name: placeholderName, Text: callerName}); got != callerName+" et "+callerName {
				t.Fatalf("Text(%q) is %q, want %q", keyNameReply, got, callerName+" et "+callerName)
			}
		})
		t.Run("a name reply of {$NAME} and {$NAME} given no Value: both nothing", func(t *testing.T) {
			t.Parallel()
			texts := frWith(t, map[string]string{shortNameReply: twicePlaceholder})
			if got := texts.Text(keyNameReply); got != " et " {
				t.Fatalf("Text(%q) is %q, want %q", keyNameReply, got, " et ")
			}
		})
	})

	t.Run("If key is not one of the keys above, then Text shall return the empty string.", func(t *testing.T) {
		t.Parallel()
		for _, key := range []string{"session.farewell", "name", "parent", "", "farewell", shortGreeting, "session", "SESSION.GREETING", "session.greeting ", "menu.greeting"} {
			t.Run("the key "+key+", fr-fr holding session.farewell, menu.greeting and a parent: empty", func(t *testing.T) {
				t.Parallel()
				file := fileOf([]string{entry("name", frName), entry("parent", fallbackCode)},
					append(frSession(nil), entry("farewell", "Au revoir")), "", "[menu]", entry(shortGreeting, "Menu"))
				texts := expectLoaded(t, makeLang(t, map[string]string{fallbackCode: enUSFile(), frFR: file}), frFR)
				if got := texts.Text(key, language.Value{Name: placeholderName, Text: callerName}); got != "" {
					t.Fatalf("Text(%q) is %q, want the empty string", key, got)
				}
			})
		}
		t.Run("the edge inside, each of the three keys: its text", func(t *testing.T) {
			t.Parallel()
			expectShown(t, frWith(t, nil), frShown)
		})
	})
}
