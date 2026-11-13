// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The contract's lines on a text that counts as missing, through Load and Text: the board's
// language, fr-fr with no parent, holds the French texts with one written as the row gives it, as
// the greeting, which is given no placeholder, or as the name reply, given NAME. A text that
// counts as missing gives en-us's and is in Missing; one that is read gives what it says and is
// not.
package language_test

import (
	"fmt"
	"strings"
	"testing"
)

// expectMissing writes fr-fr with key's line as given, and fails the row unless Load reads it,
// key's text is en-us's, every other text fr-fr's, and Missing names key alone.
func expectMissing(t *testing.T, key, line string) {
	t.Helper()
	folder := makeLang(t, map[string]string{
		fallbackCode: enUSFile(),
		frFR:         frFile(map[string]string{shortKey(key): line}),
	})
	expectShown(t, expectLoaded(t, folder, frFR), frShown.from(key, enUSShown).missingFrom(key))
}

// expectRead writes fr-fr with key's line as given, and fails the row unless Load reads it,
// key's text is want, the name reply given callerName, every other text fr-fr's, and Missing names
// none.
func expectRead(t *testing.T, key, line, want string) {
	t.Helper()
	folder := makeLang(t, map[string]string{
		fallbackCode: enUSFile(),
		frFR:         frFile(map[string]string{shortKey(key): line}),
	})
	expectShown(t, expectLoaded(t, folder, frFR), frShown.with(key, want))
}

func TestCountedMissing(t *testing.T) {
	t.Parallel()

	t.Run("is not a string, or is not valid MessageFormat 2;", func(t *testing.T) {
		t.Parallel()
		for name, line := range map[string]string{
			"greeting = 5":                  "greeting = 5",
			"the greeting an array":         `greeting = ["Bonjour"]`,
			"the greeting a table":          `greeting = { text = "Bonjour" }`,
			"an unclosed placeholder":       entry(shortGreeting, "Bonjour {$NAME"),
			"a lone closing brace":          entry(shortGreeting, "Bonjour }"),
			"a backslash before a letter":   entry(shortGreeting, `Bonjour \n`),
			"a backslash at the end":        entry(shortGreeting, `Bonjour \`),
			"a placeholder with no name":    entry(shortGreeting, "Bonjour {$}"),
			"a variable with a space after": entry(shortGreeting, "Bonjour {$ NAME}"),
		} {
			t.Run(name+": missing, en-us's", func(t *testing.T) {
				t.Parallel()
				expectMissing(t, keyGreeting, line)
			})
		}
		t.Run("a 1 MiB file whose greeting is brackets nested to its end: Load returns, missing, en-us's", func(t *testing.T) {
			t.Parallel()
			head := fileOf([]string{entry("name", frName)}, []string{entry(shortNamePrompt, frNamePrompt), entry(shortNameReply, frNameReply)})
			depth := (mostFileBytes - len(head) - len("greeting = \"\"\n")) / 2
			nested := "greeting = \"" + strings.Repeat("{", depth) + strings.Repeat("}", depth) + "\"\n"
			file := head + nested
			if len(file) > mostFileBytes || len(file) < mostFileBytes-1 {
				t.Fatalf("the file is %d bytes, not 1 MiB: a fault in the test", len(file))
			}
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), frFR: file})
			expectShown(t, expectLoaded(t, folder, frFR), frShown.from(keyGreeting, enUSShown).missingFrom(keyGreeting))
		})
	})

	t.Run("is a complex message, one that begins with a declaration or is a quoted pattern, {{…}};", func(t *testing.T) {
		t.Parallel()
		for name, text := range map[string]string{
			"{{Bonjour}}":          "{{Bonjour}}",
			localDeclaration:       localDeclaration,
			".input {$NAME} {{a}}": ".input {$NAME} {{a}}",
		} {
			t.Run(name+": missing, en-us's", func(t *testing.T) {
				t.Parallel()
				expectMissing(t, keyNameReply, entry(shortNameReply, text))
			})
		}
	})

	t.Run("holds anything but characters, the escapes and variable placeholders with no function, option or attribute, a literal placeholder such as {BBSNAME} included;", func(t *testing.T) {
		t.Parallel()
		for name, text := range map[string]string{
			"{BBSNAME}, a literal placeholder":      "Bonjour {BBSNAME}",
			"{|x|}, a quoted literal":               "Bonjour {|x|}",
			"{$NAME :string}, a function":           "Bonjour {$NAME :string}",
			"{$NAME @a}, an attribute":              "Bonjour {$NAME @a}",
			"{#b}Bonjour{/b}, markup":               "{#b}Bonjour{/b}",
			"{:string}, a function alone":           "Bonjour {:string}",
			"{$NAME :string u:id=x}, with options":  "Bonjour {$NAME :string u:id=x}",
			"{#b/}, standalone markup":              "Bonjour {#b/}",
			"{1}, a number literal":                 "Bonjour {1}",
			"{$NAME} beside {BBSNAME}, one of each": "Bonjour {$NAME} {BBSNAME}",
		} {
			t.Run(name+": missing, en-us's", func(t *testing.T) {
				t.Parallel()
				expectMissing(t, keyNameReply, entry(shortNameReply, text))
			})
		}
		for name, row := range map[string]struct{ text, want string }{
			"characters alone":                     {"Bonjour à tous", "Bonjour à tous"},
			"each escape":                          {`\{\}\|\\`, `{}|\`},
			"an unescaped pipe, @ and a full stop": {"a|b @c d.e", "a|b @c d.e"},
			namePlaceholder:                        {frNameReply, "Bonjour " + callerName},
		} {
			t.Run(name+", the edge inside: read", func(t *testing.T) {
				t.Parallel()
				expectRead(t, keyNameReply, entry(shortNameReply, row.text), row.want)
			})
		}
	})

	t.Run("holds a placeholder its key is not given;", func(t *testing.T) {
		t.Parallel()
		t.Run("{$NAME} under the greeting, which is given no placeholder: missing, en-us's", func(t *testing.T) {
			t.Parallel()
			expectMissing(t, keyGreeting, entry(shortGreeting, "Bonjour {$NAME}"))
		})
		t.Run("{$NAME} under the name prompt, which is given no placeholder: missing, en-us's", func(t *testing.T) {
			t.Parallel()
			expectMissing(t, keyNamePrompt, entry(shortNamePrompt, "Votre nom, {$NAME} ? "))
		})
		for name, text := range map[string]string{
			"{$USER}":                              "Bonjour {$USER}",
			"{$name}, NAME in lower case":          "Bonjour {$name}",
			"{$NAME} beside {$USER}, one of each":  "Bonjour {$NAME} {$USER}",
			"{$NAME_}, a name NAME only begins":    "Bonjour {$NAME_}",
			"{$NAM}, a name only part of NAME":     "Bonjour {$NAM}",
			"{ $USER }, spaces inside the braces":  "Bonjour { $USER }",
			"{$NAME.x}, NAME and more after a dot": "Bonjour {$NAME.x}",
		} {
			t.Run(name+" under the name reply: missing, en-us's", func(t *testing.T) {
				t.Parallel()
				expectMissing(t, keyNameReply, entry(shortNameReply, text))
			})
		}
		for name, text := range map[string]string{
			namePlaceholder:                             "Bonjour {$NAME}",
			"{ $NAME }, spaces inside the braces":       "Bonjour { $NAME }",
			"{\u3000$NAME\u3000}, ideographic spaces":   "Bonjour {\u3000$NAME\u3000}",
			"{$NAME} twice":                             "Bonjour {$NAME} et {$NAME}",
			"{$NAME} at the start, no other characters": namePlaceholder,
		} {
			t.Run(name+" under the name reply, the edge inside: read", func(t *testing.T) {
				t.Parallel()
				want := strings.ReplaceAll(strings.NewReplacer("{ $NAME }", callerName, "{\u3000$NAME\u3000}", callerName).Replace(text), namePlaceholder, callerName)
				expectRead(t, keyNameReply, entry(shortNameReply, text), want)
			})
		}
	})

	t.Run("holds a control character, U+0000 to U+001F or U+007F to U+009F, or a bidi control, U+061C, U+200E, U+200F, U+202A to U+202E or U+2066 to U+2069.", func(t *testing.T) {
		t.Parallel()
		for _, character := range []rune{0x0000, 0x001F, 0x007F, 0x009F, 0x061C, 0x200E, 0x200F, 0x202A, 0x202E, 0x2066, 0x2069} {
			t.Run(fmt.Sprintf("U+%04X in the greeting: missing, en-us's", character), func(t *testing.T) {
				t.Parallel()
				expectMissing(t, keyGreeting, entry(shortGreeting, "Bon"+string(character)+"jour"))
			})
		}
		t.Run("a line feed at the end of the greeting: missing, en-us's", func(t *testing.T) {
			t.Parallel()
			expectMissing(t, keyGreeting, entry(shortGreeting, frGreeting+"\n"))
		})
		t.Run("a tab inside a placeholder's braces, which the standard allows: missing, en-us's", func(t *testing.T) {
			t.Parallel()
			expectMissing(t, keyNameReply, entry(shortNameReply, "Bonjour {\t$NAME}"))
		})
		t.Run("ESC in the name prompt: missing, en-us's", func(t *testing.T) {
			t.Parallel()
			expectMissing(t, keyNamePrompt, entry(shortNamePrompt, "Votre nom \x1b[31m? "))
		})
		for _, character := range []rune{0x0020, 0x00A0, 0x061B, 0x200D, 0x2010, 0x2029, 0x202F, 0x2065, 0x206A} {
			t.Run(fmt.Sprintf("U+%04X in the greeting, the edge inside: read", character), func(t *testing.T) {
				t.Parallel()
				text := "Bon" + string(character) + "jour"
				expectRead(t, keyGreeting, entry(shortGreeting, text), text)
			})
		}
	})
}
