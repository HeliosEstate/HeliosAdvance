// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The test's own reading of the part of MessageFormat 2 the contract reads, written from the
// standard's syntax (LDML part 9) apart from the package: which kind a text is, and what a text
// the package reads gives. The suite's rows and the fuzz target sort and judge by it.
package language_test

import (
	"slices"
	"strings"
)

// The kinds of text, each under the line it falls under.
const (
	kindSyntaxError = "a syntax error"
	kindControl     = "a control or bidi character"
	kindComplex     = "a complex message"
	kindOutside     = "more than the part read"
	kindPlaceholder = "a placeholder not given"
	kindRead        = "read"
)

// isSpace is the standard's whitespace inside a placeholder's braces: space, tab, CR, LF and the
// ideographic space; the bidi marks it also allows are bidi controls, which count as missing.
func isSpace(character rune) bool {
	return character == ' ' || character == '\t' || character == '\r' || character == '\n' || character == 0x3000
}

// isNameStart and isNameCharacter are the standard's name characters as far as the suite and the
// rows use them; a name past them counts as missing either way, being no name the engine gives.
func isNameStart(character rune) bool {
	return character == '_' || (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z')
}

func isNameCharacter(character rune) bool {
	return isNameStart(character) || (character >= '0' && character <= '9') || character == '-' || character == '.'
}

// reading is what the test's own reading makes of a text: its kind, the names of its
// placeholders, and the text it gives with each placeholder named name given value.
type reading struct {
	kind  string
	names []string
	parts []readPart
}

// readPart is one run of characters, or a placeholder by its name.
type readPart struct {
	characters  string
	placeholder string
}

// read sorts source: a syntax error when the suite says so (errorTypes holds syntax-error), then
// a control or bidi character, a complex message (a declaration or a quoted pattern, after any
// leading whitespace), more than the part read (anything but characters, the four escapes and
// variable placeholders with no function, option or attribute), and a placeholder whose name is
// not one of given. What is left is read.
func read(source string, errorTypes []string, given ...string) reading {
	if slices.Contains(errorTypes, "syntax-error") {
		return reading{kind: kindSyntaxError}
	}
	if strings.ContainsFunc(source, isControlOrBidi) {
		return reading{kind: kindControl}
	}
	trimmed := strings.TrimLeftFunc(source, isSpace)
	if strings.HasPrefix(trimmed, ".") || strings.HasPrefix(trimmed, "{{") {
		return reading{kind: kindComplex}
	}
	var made reading
	characters := []rune(source)
	var run strings.Builder
	for index := 0; index < len(characters); index++ {
		switch character := characters[index]; character {
		case '\\':
			if index+1 == len(characters) || !strings.ContainsRune(`\{|}`, characters[index+1]) {
				return reading{kind: kindOutside}
			}
			index++
			run.WriteRune(characters[index])
		case '}':
			return reading{kind: kindOutside}
		case '{':
			name, end, ok := placeholderAt(characters, index)
			if !ok {
				return reading{kind: kindOutside}
			}
			made.parts = append(made.parts, readPart{characters: run.String()}, readPart{placeholder: name})
			run.Reset()
			if !slices.Contains(made.names, name) {
				made.names = append(made.names, name)
			}
			index = end
		default:
			run.WriteRune(character)
		}
	}
	made.parts = append(made.parts, readPart{characters: run.String()})
	for _, name := range made.names {
		if !slices.Contains(given, name) {
			return reading{kind: kindPlaceholder, names: made.names}
		}
	}
	made.kind = kindRead
	return made
}

// placeholderAt reads a variable placeholder with no function, option or attribute starting at
// the brace at start: its name and the index of its closing brace.
func placeholderAt(characters []rune, start int) (name string, end int, ok bool) {
	index := start + 1
	for index < len(characters) && isSpace(characters[index]) {
		index++
	}
	if index+1 >= len(characters) || characters[index] != '$' || !isNameStart(characters[index+1]) {
		return "", 0, false
	}
	index++
	first := index
	for index < len(characters) && isNameCharacter(characters[index]) {
		index++
	}
	name = string(characters[first:index])
	for index < len(characters) && isSpace(characters[index]) {
		index++
	}
	if index == len(characters) || characters[index] != '}' {
		return "", 0, false
	}
	return name, index, true
}

// gives is the text a read text gives, each placeholder named name replaced by value.
func (made reading) gives(name, value string) string {
	var given strings.Builder
	for _, part := range made.parts {
		if part.placeholder == name {
			given.WriteString(value)
		} else {
			given.WriteString(part.characters)
		}
	}
	return given.String()
}
