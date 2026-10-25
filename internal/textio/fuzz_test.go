// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The fuzz target for Edit, the board's shared cleaner in its first form: the checks the Text I/O
// contract lists under untrusted input, on every input the fuzzer finds.
package textio_test

import (
	"bytes"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/textio"
)

func FuzzEdit(fuzzing *testing.F) {
	seeds := []struct {
		input []byte
		most  int
		cut   uint8
	}{
		{nil, nameLimit, 0},
		{[]byte("alice\r"), nameLimit, 3},
		{[]byte("abc\x08\x7fd\n tail"), nameLimit, 4},
		{[]byte("\x1b[2J\x9b\x07\x00\t\xff\xffname"), nameLimit, 2},
		{bytes.Repeat([]byte("n"), 40), nameLimit, 31},
		{[]byte("\r\n\x08\x7fa\x08\x08\r"), 1, 1},
		{bytes.Repeat([]byte("ab\x08"), 200), mostLine, 100},
		{[]byte("x"), -5, 0},
		{[]byte("x"), 1 << 20, 0},
	}
	for _, seed := range seeds {
		fuzzing.Add(seed.input, seed.most, seed.cut)
	}
	fuzzing.Fuzz(func(t *testing.T, input []byte, most int, cutAt uint8) {
		// Every run starts by showing Edit is live, so an input that rightly changes nothing
		// cannot pass for code that does nothing.
		probeLive(t)
		limit := clamped(most)
		line := textio.NewLine(most)
		reading := edited{most: limit}
		var echoed, wantEcho []byte
		ended := false
		for index, character := range input {
			var echo []byte
			var nowEnded bool
			line, echo, nowEnded = textio.Edit(line, character)
			var expected []byte
			reading, expected = reading.read(character)
			wantEcho = append(wantEcho, expected...)
			echoed = append(echoed, echo...)
			if ended && !nowEnded {
				t.Fatalf("the line ended, then byte %d (%#02x) reopened it", index, character)
			}
			ended = nowEnded
			text := line.Text()
			if len(text) > limit {
				t.Fatalf("a line of limit %d holds %d characters", limit, len(text))
			}
			for _, held := range []byte(text) {
				if held < 0x20 || held > 0x7E {
					t.Fatalf("the line holds byte %#02x", held)
				}
			}
			if text != reading.text || nowEnded != reading.ended {
				t.Fatalf("after % x the line is %q ended %v, want %q ended %v", input[:index+1], text, nowEnded, reading.text, reading.ended)
			}
		}
		// What it echoes is only bytes it added, BS SP BS for one removed and CR LF at the end,
		// which the test's own reading of the table gives in order.
		if !bytes.Equal(echoed, wantEcho) {
			t.Fatalf("for % x the echo was % x, want % x", input, echoed, wantEcho)
		}
		if len(echoed) > 2*len(input)+2 {
			t.Fatalf("%d bytes read gave an echo of %d", len(input), len(echoed))
		}
		// The same bytes split at any point give the same line and echo: Edit carries everything
		// in the Line it returns.
		cut := min(int(cutAt), len(input))
		first := textio.NewLine(most)
		var splitEcho []byte
		for _, character := range input[:cut] {
			var echo []byte
			first, echo, _ = textio.Edit(first, character)
			splitEcho = append(splitEcho, echo...)
		}
		second := first
		for _, character := range input[cut:] {
			var echo []byte
			second, echo, _ = textio.Edit(second, character)
			splitEcho = append(splitEcho, echo...)
		}
		if second.Text() != line.Text() || !bytes.Equal(splitEcho, echoed) {
			t.Fatalf("split at %d: %q and % x, in one pass: %q and % x", cut, second.Text(), splitEcho, line.Text(), echoed)
		}
	})
}
