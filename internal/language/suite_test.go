// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Unicode's MessageFormat 2 test suite, the page's oracle, through Load and Text: every case of
// the suite as the board's name reply, each sorted afresh by the suite's own errors and the
// test's reading of the part the contract reads. A case the suite calls a syntax error, and any
// case past that part, counts as missing and gives en-us's text; a case of characters and escapes
// alone is read as the suite's exp. Two cases whose one variable the suite gives a string read as
// the suite expects once that variable is named NAME.
package language_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/language"
)

// suiteFolder is the oracle's folder, from this package's own.
var suiteFolder = filepath.Join("..", "..", "oracle", "messageformat2")

// suiteTest is one case as the suite writes it; a field the case leaves out takes the file's
// defaultTestProperties.
type suiteTest struct {
	Source     *string           `json:"src"`
	Expected   *string           `json:"exp"`
	Errors     *[]suiteError     `json:"expErrors"`
	Parameters *[]suiteParameter `json:"params"`
}

type suiteError struct {
	Type string `json:"type"`
}

type suiteParameter struct {
	Name  string `json:"name"`
	Value any    `json:"value"`
}

type suiteFile struct {
	Defaults suiteTest   `json:"defaultTestProperties"`
	Tests    []suiteTest `json:"tests"`
}

// suiteCase is one case with the file's defaults applied, and its place in the suite.
type suiteCase struct {
	place      string
	source     string
	expected   *string
	errorTypes []string
	parameters []suiteParameter
}

// readSuite reads every case of every file in the oracle's folder. A folder that cannot be read,
// a file that is not the suite's form or no case at all fails the row: a missing oracle is a
// failure, never a skip.
func readSuite(t *testing.T) []suiteCase {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(suiteFolder, "*.json"))
	if err != nil || len(names) == 0 {
		t.Fatalf("the MessageFormat 2 suite is not in %s: %v", suiteFolder, err)
	}
	slices.Sort(names)
	var cases []suiteCase
	for _, name := range names {
		contents, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("reading the suite's %s: %v", name, err)
		}
		var file suiteFile
		if err := json.Unmarshal(contents, &file); err != nil {
			t.Fatalf("the suite's %s is not in its form: %v", name, err)
		}
		for index, test := range file.Tests {
			made := suiteCase{place: fmt.Sprintf("%s case %d", filepath.Base(name), index)}
			source := test.Source
			if source == nil {
				source = file.Defaults.Source
			}
			if source == nil {
				t.Fatalf("the suite's %s has no src", made.place)
			}
			made.source = *source
			made.expected = test.Expected
			if made.expected == nil {
				made.expected = file.Defaults.Expected
			}
			errors := test.Errors
			if errors == nil {
				errors = file.Defaults.Errors
			}
			if errors != nil {
				for _, each := range *errors {
					made.errorTypes = append(made.errorTypes, each.Type)
				}
			}
			if test.Parameters != nil {
				made.parameters = *test.Parameters
			}
			cases = append(cases, made)
		}
	}
	return cases
}

// lines are the contract's lines each kind of case proves, word for word.
var lines = map[string]string{
	kindSyntaxError: "is not a string, or is not valid MessageFormat 2;",
	kindComplex:     "is a complex message, one that begins with a declaration or is a quoted pattern, {{…}};",
	kindOutside:     "holds anything but characters, the escapes and variable placeholders with no function, option or attribute, a literal placeholder such as {BBSNAME} included;",
	kindPlaceholder: "holds a placeholder its key is not given;",
	kindControl:     "holds a control character, U+0000 to U+001F or U+007F to U+009F, or a bidi control, U+061C, U+200E, U+200F, U+202A to U+202E or U+2066 to U+2069.",
}

// renamedCase is a case whose one variable the suite gives a string, renamed NAME: its source
// with every placeholder of that variable written {$NAME}, and the string.
func renamedCase(made suiteCase, reading reading) (source, value string, ok bool) {
	if len(made.errorTypes) != 0 || made.expected == nil || len(reading.names) != 1 || len(made.parameters) != 1 {
		return "", "", false
	}
	parameter := made.parameters[0]
	text, isString := parameter.Value.(string)
	if parameter.Name != reading.names[0] || !isString {
		return "", "", false
	}
	var renamed strings.Builder
	for _, part := range reading.parts {
		if part.placeholder != "" {
			renamed.WriteString("{$" + placeholderName + "}")
			continue
		}
		renamed.WriteString(escapeText(part.characters))
	}
	return renamed.String(), text, true
}

// escapeText writes characters as MessageFormat 2 text, each character that needs it escaped.
func escapeText(characters string) string {
	var escaped strings.Builder
	for _, character := range characters {
		if strings.ContainsRune(`\{|}`, character) {
			escaped.WriteByte('\\')
		}
		escaped.WriteRune(character)
	}
	return escaped.String()
}

func TestMessageFormatSuite(t *testing.T) {
	t.Parallel()
	cases := readSuite(t)
	sorted := map[string][]suiteCase{}
	type renamed struct {
		place, source, value, expected string
	}
	var renames []renamed
	for _, made := range cases {
		reading := read(made.source, made.errorTypes, placeholderName)
		if reading.kind == kindRead && len(made.errorTypes) != 0 {
			t.Fatalf("the suite's %s, %q, is an error %v the test's reading reads: a fault in the test", made.place, made.source, made.errorTypes)
		}
		if reading.kind == kindRead && made.expected == nil {
			t.Fatalf("the suite's %s, %q, is read but has no exp: a fault in the test", made.place, made.source)
		}
		sorted[reading.kind] = append(sorted[reading.kind], made)
		if reading.kind == kindPlaceholder {
			if source, value, ok := renamedCase(made, read(made.source, nil, reading.names...)); ok {
				renames = append(renames, renamed{made.place, source, value, *made.expected})
			}
		}
	}
	// Every kind must hold a case, or the sorting proves nothing: a fault in the test.
	for _, kind := range []string{kindSyntaxError, kindControl, kindComplex, kindOutside, kindPlaceholder, kindRead} {
		if len(sorted[kind]) == 0 {
			t.Fatalf("no case of the suite is %s: a fault in the test", kind)
		}
		t.Logf("%s: %d cases", kind, len(sorted[kind]))
	}
	if len(renames) == 0 {
		t.Fatalf("no case of the suite gives its one variable a string: a fault in the test")
	}

	for _, kind := range []string{kindSyntaxError, kindComplex, kindOutside, kindPlaceholder, kindControl} {
		t.Run(lines[kind], func(t *testing.T) {
			t.Parallel()
			for _, made := range sorted[kind] {
				t.Run(fmt.Sprintf("the suite's %s, %s, %q: missing, en-us's", made.place, kind, made.source), func(t *testing.T) {
					t.Parallel()
					expectMissing(t, keyNameReply, entry(shortNameReply, made.source))
				})
			}
			// The inside edges: what the suite reads, under the line whose part it stays inside.
			switch kind {
			case kindOutside:
				for _, made := range sorted[kindRead] {
					t.Run(fmt.Sprintf("the suite's %s, %q, characters and escapes alone: read as its exp %q", made.place, made.source, *made.expected), func(t *testing.T) {
						t.Parallel()
						expectRead(t, keyNameReply, entry(shortNameReply, made.source), *made.expected)
					})
				}
			case kindPlaceholder:
				for _, each := range renames {
					t.Run(fmt.Sprintf("the suite's %s, its variable named NAME, %q given %q: read as its exp %q", each.place, each.source, each.value, each.expected), func(t *testing.T) {
						t.Parallel()
						folder := makeLang(t, map[string]string{
							fallbackCode: enUSFile(),
							frFR:         frFile(map[string]string{shortNameReply: entry(shortNameReply, each.source)}),
						})
						texts := expectLoaded(t, folder, frFR)
						if got := texts.Text(keyNameReply, language.Value{Name: placeholderName, Text: each.value}); got != each.expected {
							t.Errorf("Text(%q) is %q, want %q", keyNameReply, got, each.expected)
						}
						if got := texts.Missing(); len(got) != 0 {
							t.Errorf("Missing() is %q, want none", got)
						}
					})
				}
			}
		})
	}
}
