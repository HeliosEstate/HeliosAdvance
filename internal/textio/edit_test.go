// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests of Edit, the one place a line's bytes are read: every byte value in every state a line
// can be in, against the test's own reading of the contract's table, written here apart from the
// package's code and constants.
package textio_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/textio"
)

// The bytes the table names, and the longest line, as the contract states them.
const (
	backspace      byte = 0x08
	deleteKey      byte = 0x7F
	eraseLineKey   byte = 0x15
	carriageReturn byte = 0x0D
	lineFeed       byte = 0x0A
	mostLine            = 255
	nameLimit           = 30
)

var erase = []byte{backspace, ' ', backspace}

// edited is the test's own reading of a line: its characters, its limit and whether it ended.
type edited struct {
	text  string
	most  int
	ended bool
}

// read is the test's own reading of one byte, by the contract's table.
func (line edited) read(character byte) (edited, []byte) {
	switch {
	case line.ended:
		return line, nil
	case character >= 0x20 && character <= 0x7E:
		if len(line.text) >= line.most {
			return line, nil
		}
		line.text += string(character)
		return line, []byte{character}
	case character == backspace || character == deleteKey:
		if line.text == "" {
			return line, nil
		}
		line.text = line.text[:len(line.text)-1]
		return line, erase
	case character == eraseLineKey:
		if line.text == "" {
			return line, nil
		}
		echo := bytes.Repeat(erase, len(line.text))
		line.text = ""
		return line, echo
	case character == carriageReturn || character == lineFeed:
		if line.text == "" {
			return line, nil
		}
		line.ended = true
		return line, []byte{carriageReturn, lineFeed}
	}
	return line, nil
}

// clamped is a limit as NewLine keeps it.
func clamped(most int) int {
	return min(max(most, 0), mostLine)
}

// start is a line and the test's reading of it, made by hand with NewLine and Edit's adding of
// printable characters, which the rows of the first line prove.
func start(t *testing.T, most int, text string) (textio.Line, edited) {
	t.Helper()
	line := textio.NewLine(most)
	for index := range len(text) {
		line, _, _ = textio.Edit(line, text[index])
	}
	if line.Text() != text {
		t.Fatalf("setting up: a line of limit %d given %q holds %q", most, text, line.Text())
	}
	return line, edited{text: text, most: clamped(most)}
}

// expectEdit makes one Edit and checks the line, the echo and the end against the test's own
// reading, and against what the row says it must be.
func expectEdit(t *testing.T, line textio.Line, reading edited, character byte, wantText string, wantEcho []byte, wantEnded bool) textio.Line {
	t.Helper()
	next, wantByReading := reading.read(character)
	if next.text != wantText || !bytes.Equal(wantByReading, wantEcho) || next.ended != wantEnded {
		t.Fatalf("test fault: the row disagrees with the test's own reading of byte %#02x: %q % x %v", character, next.text, wantByReading, next.ended)
	}
	after, echo, ended := textio.Edit(line, character)
	if after.Text() != wantText || !bytes.Equal(echo, wantEcho) || ended != wantEnded {
		t.Fatalf("Edit of %q with byte %#02x gave %q, echo % x, ended %v; want %q, echo % x, ended %v",
			line.Text(), character, after.Text(), echo, ended, wantText, wantEcho, wantEnded)
	}
	return after
}

// probeLine shows a line is still open and keeps what it holds: one more character is added and
// echoed, or dropped when the line is full.
func probeLine(t *testing.T, line textio.Line, reading edited) {
	t.Helper()
	wantText, wantEcho := reading.text+"z", []byte("z")
	if len(reading.text) >= reading.most {
		wantText, wantEcho = reading.text, nil
	}
	expectEdit(t, line, reading, 'z', wantText, wantEcho, false)
}

// probeLive ends a row whose own bytes rightly change nothing: a new line of 30 takes a, echoes
// it and ends on CR, so code that does nothing fails the row.
func probeLive(t *testing.T) {
	t.Helper()
	line, reading := start(t, nameLimit, "")
	line = expectEdit(t, line, reading, 'a', "a", []byte("a"), false)
	reading.text = "a"
	expectEdit(t, line, reading, carriageReturn, "a", []byte{carriageReturn, lineFeed}, true)
}

// printable is every byte the table adds.
func printable() []byte {
	var characters []byte
	for character := byte(0x20); character <= 0x7E; character++ {
		characters = append(characters, character)
	}
	return characters
}

// dropped is every byte the table neither adds, removes with nor ends on.
func dropped() []byte {
	var characters []byte
	for code := range 256 {
		character := byte(code)
		isPrintable := character >= 0x20 && character <= 0x7E
		isNamed := character == backspace || character == deleteKey || character == eraseLineKey || character == carriageReturn || character == lineFeed
		if !isPrintable && !isNamed {
			characters = append(characters, character)
		}
	}
	return characters
}

func TestEdit(t *testing.T) {
	t.Parallel()
	t.Run("When the byte is from 0x20 to 0x7E and the line holds fewer than its limit, Edit shall add it to the line and echo it.", func(t *testing.T) {
		t.Parallel()
		rows := []struct {
			name string
			most int
			text string
		}{
			{name: "every printable byte into an empty line of 30", most: nameLimit},
			{name: "every printable byte into a line holding 29 of 30, the edge just inside the limit", most: nameLimit, text: strings.Repeat("n", nameLimit-1)},
			{name: "every printable byte into an empty line of 1", most: 1},
			{name: "every printable byte into a line holding 254 of 255", most: mostLine, text: strings.Repeat("n", mostLine-1)},
			{name: "every printable byte into a line of a limit above 255, clamped to 255, holding 254", most: mostLine + 1, text: strings.Repeat("n", mostLine-1)},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				for _, character := range printable() {
					line, reading := start(t, row.most, row.text)
					line = expectEdit(t, line, reading, character, row.text+string(character), []byte{character}, false)
					reading.text += string(character)
					probeLine(t, line, reading)
				}
			})
		}
	})
	t.Run("Edit shall drop every byte the table does not add, remove with or end on, and echo nothing for it.", func(t *testing.T) {
		t.Parallel()
		rows := []struct {
			name string
			most int
			text string
		}{
			{name: "an empty line", most: nameLimit},
			{name: "a line holding abc", most: nameLimit, text: "abc"},
			{name: "a full line of 30", most: nameLimit, text: strings.Repeat("n", nameLimit)},
		}
		for _, row := range rows {
			t.Run("every byte outside the table, into "+row.name, func(t *testing.T) {
				t.Parallel()
				for _, character := range dropped() {
					line, reading := start(t, row.most, row.text)
					line = expectEdit(t, line, reading, character, row.text, nil, false)
					probeLine(t, line, reading)
				}
			})
		}
		limits := []struct {
			name string
			most int
			text string
		}{
			{name: "a full line of 30, the 31st", most: nameLimit, text: strings.Repeat("n", nameLimit)},
			{name: "a full line of 1", most: 1, text: "n"},
			{name: "a full line of 255", most: mostLine, text: strings.Repeat("n", mostLine)},
			{name: "a line of limit 0", most: 0},
			{name: "a line of limit -1, clamped to 0", most: -1},
		}
		for _, row := range limits {
			t.Run("every printable byte into "+row.name, func(t *testing.T) {
				t.Parallel()
				for _, character := range printable() {
					line, reading := start(t, row.most, row.text)
					line = expectEdit(t, line, reading, character, row.text, nil, false)
					// The line is still open: a backspace removes from it, or does nothing
					// when it is empty.
					if row.text != "" {
						expectEdit(t, line, reading, backspace, row.text[:len(row.text)-1], erase, false)
					}
				}
				probeLive(t)
			})
		}
		t.Run("every printable byte into a zero Line, whose limit is 0", func(t *testing.T) {
			t.Parallel()
			for _, character := range printable() {
				expectEdit(t, textio.Line{}, edited{}, character, "", nil, false)
			}
			probeLive(t)
		})
	})
	t.Run("When the byte is BS or DEL and the line holds a character, Edit shall remove the last one and echo BS, space, BS.", func(t *testing.T) {
		t.Parallel()
		for _, key := range []byte{backspace, deleteKey} {
			for _, text := range []string{"abc", "a", " ", strings.Repeat("n", nameLimit-1) + "z"} {
				t.Run(fmt.Sprintf("%#02x on %q", key, text), func(t *testing.T) {
					t.Parallel()
					line, reading := start(t, nameLimit, text)
					line = expectEdit(t, line, reading, key, text[:len(text)-1], erase, false)
					reading.text = text[:len(text)-1]
					probeLine(t, line, reading)
				})
			}
			t.Run(fmt.Sprintf("%#02x twice on abc, then on a", key), func(t *testing.T) {
				t.Parallel()
				line, reading := start(t, nameLimit, "abc")
				line = expectEdit(t, line, reading, key, "ab", erase, false)
				reading.text = "ab"
				line = expectEdit(t, line, reading, key, "a", erase, false)
				reading.text = "a"
				line = expectEdit(t, line, reading, key, "", erase, false)
				reading.text = ""
				probeLine(t, line, reading)
			})
		}
	})
	t.Run("When the byte is Ctrl-U (0x15) and the line holds a character, Edit shall remove every character and echo the three bytes BS, space, BS once for each character, one group after another.", func(t *testing.T) {
		t.Parallel()
		for _, row := range []struct {
			most int
			text string
		}{
			{most: nameLimit, text: "a"},
			{most: nameLimit, text: "ab"},
			{most: nameLimit, text: "  a b  "},
			{most: nameLimit, text: strings.Repeat("n", nameLimit)},
			{most: mostLine, text: strings.Repeat("xy", mostLine/2) + "z"},
		} {
			t.Run(fmt.Sprintf("Ctrl-U on %d characters", len(row.text)), func(t *testing.T) {
				t.Parallel()
				line, reading := start(t, row.most, row.text)
				line = expectEdit(t, line, reading, eraseLineKey, "", bytes.Repeat(erase, len(row.text)), false)
				reading.text = ""
				probeLine(t, line, reading)
			})
		}
		t.Run("abc, BS, Ctrl-U: two groups, then d and CR end the line as d", func(t *testing.T) {
			t.Parallel()
			line, reading := start(t, nameLimit, "abc")
			line = expectEdit(t, line, reading, backspace, "ab", erase, false)
			reading.text = "ab"
			line = expectEdit(t, line, reading, eraseLineKey, "", bytes.Repeat(erase, 2), false)
			reading.text = ""
			line = expectEdit(t, line, reading, 'd', "d", []byte("d"), false)
			reading.text = "d"
			expectEdit(t, line, reading, carriageReturn, "d", []byte{carriageReturn, lineFeed}, true)
		})
		t.Run("Ctrl-U twice on abc: three groups, then nothing", func(t *testing.T) {
			t.Parallel()
			line, reading := start(t, nameLimit, "abc")
			line = expectEdit(t, line, reading, eraseLineKey, "", bytes.Repeat(erase, 3), false)
			reading.text = ""
			line = expectEdit(t, line, reading, eraseLineKey, "", nil, false)
			probeLine(t, line, reading)
		})
		t.Run("a full line of 30, Ctrl-U, then 30 more characters fit", func(t *testing.T) {
			t.Parallel()
			line, reading := start(t, nameLimit, strings.Repeat("n", nameLimit))
			line = expectEdit(t, line, reading, eraseLineKey, "", bytes.Repeat(erase, nameLimit), false)
			reading.text = ""
			for index := range nameLimit {
				line = expectEdit(t, line, reading, 'm', reading.text+"m", []byte("m"), false)
				reading.text = strings.Repeat("m", index+1)
			}
			probeLine(t, line, reading)
		})
	})
	t.Run("When the byte is CR or LF and the line holds a character, Edit shall end the line and echo CR LF.", func(t *testing.T) {
		t.Parallel()
		for _, key := range []byte{carriageReturn, lineFeed} {
			for _, text := range []string{"alice", "a", " ", strings.Repeat("n", nameLimit)} {
				t.Run(fmt.Sprintf("%#02x after %q", key, text), func(t *testing.T) {
					t.Parallel()
					line, reading := start(t, nameLimit, text)
					expectEdit(t, line, reading, key, text, []byte{carriageReturn, lineFeed}, true)
				})
			}
		}
	})
	t.Run("If the byte is BS, DEL, Ctrl-U, CR or LF and the line is empty, then Edit shall change nothing and echo nothing.", func(t *testing.T) {
		t.Parallel()
		for _, key := range []byte{backspace, deleteKey, eraseLineKey, carriageReturn, lineFeed} {
			t.Run(fmt.Sprintf("%#02x on a new line", key), func(t *testing.T) {
				t.Parallel()
				line, reading := start(t, nameLimit, "")
				line = expectEdit(t, line, reading, key, "", nil, false)
				probeLine(t, line, reading)
			})
			t.Run(fmt.Sprintf("%#02x on a line emptied by a backspace", key), func(t *testing.T) {
				t.Parallel()
				line, reading := start(t, nameLimit, "a")
				line = expectEdit(t, line, reading, backspace, "", erase, false)
				reading.text = ""
				line = expectEdit(t, line, reading, key, "", nil, false)
				probeLine(t, line, reading)
			})
		}
	})
	t.Run("Edit shall keep spaces as they come, leading and trailing ones included.", func(t *testing.T) {
		t.Parallel()
		for _, text := range []string{" ", "   ", "  a b  ", " a", "a ", strings.Repeat(" ", nameLimit)} {
			t.Run(fmt.Sprintf("%q, then CR", text), func(t *testing.T) {
				t.Parallel()
				line := textio.NewLine(nameLimit)
				reading := edited{most: nameLimit}
				for index := range len(text) {
					line = expectEdit(t, line, reading, text[index], reading.text+text[index:index+1], []byte{text[index]}, false)
					reading.text += text[index : index+1]
				}
				expectEdit(t, line, reading, carriageReturn, text, []byte{carriageReturn, lineFeed}, true)
			})
		}
	})
	t.Run("After the line has ended, Edit shall change nothing and echo nothing.", func(t *testing.T) {
		t.Parallel()
		for _, text := range []string{"alice", strings.Repeat("n", nameLimit)} {
			t.Run(fmt.Sprintf("every byte after %q and CR", text), func(t *testing.T) {
				t.Parallel()
				for code := range 256 {
					line, reading := start(t, nameLimit, text)
					line = expectEdit(t, line, reading, carriageReturn, text, []byte{carriageReturn, lineFeed}, true)
					reading.ended = true
					line = expectEdit(t, line, reading, byte(code), text, nil, true)
					// And again: an ended line stays ended whatever follows.
					expectEdit(t, line, reading, backspace, text, nil, true)
				}
			})
		}
	})
	t.Run("Edit shall return for every byte without panicking.", func(t *testing.T) {
		t.Parallel()
		lines := map[string]func() textio.Line{
			"a zero Line":                func() textio.Line { return textio.Line{} },
			"a line of limit -1":         func() textio.Line { return textio.NewLine(-1) },
			"a line of limit 0":          func() textio.Line { return textio.NewLine(0) },
			"a line of the largest int":  func() textio.Line { return textio.NewLine(int(^uint(0) >> 1)) },
			"a line of the smallest int": func() textio.Line { return textio.NewLine(-int(^uint(0)>>1) - 1) },
			"a full line of 255": func() textio.Line {
				line := textio.NewLine(mostLine)
				for range mostLine + 10 {
					line, _, _ = textio.Edit(line, 'n')
				}
				return line
			},
			"an ended line": func() textio.Line {
				line := textio.NewLine(nameLimit)
				line, _, _ = textio.Edit(line, 'a')
				line, _, _ = textio.Edit(line, carriageReturn)
				return line
			},
		}
		for name, build := range lines {
			t.Run("every byte into "+name, func(t *testing.T) {
				t.Parallel()
				for code := range 256 {
					line := build()
					before := line.Text()
					after, echo, _ := textio.Edit(line, byte(code))
					if len(after.Text()) > mostLine || len(echo) > len(erase)*max(len(before), 1) {
						t.Fatalf("byte %#02x into %q gave %q and echo % x", code, before, after.Text(), echo)
					}
				}
				probeLive(t)
			})
		}
	})
}
