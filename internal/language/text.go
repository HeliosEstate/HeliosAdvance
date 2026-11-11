// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package language

import (
	"slices"
	"strings"
	"unicode/utf8"
)

// isSpace is the standard's space, without its tab, CR and LF, which are controls and fail a text
// before they are asked.
func isSpace(character rune) bool {
	return character == ' ' || character == '　'
}

// readText reads a text in one pass, with no recursion, so a text cannot nest the reader deeper.
// It reads only characters, the four escapes and the placeholders of given; anything else the
// standard allows, such as a declaration, a quoted pattern, a function or markup, counts as a text
// that cannot be read. An empty text reads, as no parts.
func readText(text string, given []string) ([]part, bool) {
	if strings.ContainsFunc(text, isControlOrBidi) {
		return nil, false
	}
	start := strings.TrimLeftFunc(text, isSpace)
	if strings.HasPrefix(start, ".") || strings.HasPrefix(start, "{{") {
		return nil, false
	}
	parts := []part{}
	var characters strings.Builder
	flush := func() {
		if characters.Len() > 0 {
			parts = append(parts, part{text: characters.String()})
			characters.Reset()
		}
	}
	for index := 0; index < len(text); {
		character, size := utf8.DecodeRuneInString(text[index:])
		index += size
		switch character {
		case '\\':
			escaped, escapedSize := utf8.DecodeRuneInString(text[index:])
			if !slices.Contains([]rune{'\\', '{', '|', '}'}, escaped) || escapedSize == 0 {
				return nil, false
			}
			characters.WriteRune(escaped)
			index += escapedSize
		case '}':
			return nil, false
		case '{':
			end := strings.IndexByte(text[index:], '}')
			if end < 0 {
				return nil, false
			}
			inner := strings.TrimFunc(text[index:index+end], isSpace)
			name, isVariable := strings.CutPrefix(inner, "$")
			if !isVariable || !slices.Contains(given, name) {
				return nil, false
			}
			flush()
			parts = append(parts, part{text: name, placeholder: true})
			index += end + 1
		default:
			characters.WriteRune(character)
		}
	}
	flush()
	return parts, true
}
