// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The fuzz target for Receive, the one place a caller's bytes are read: the checks the Telnet
// contract lists under untrusted input, on every input the fuzzer finds.
package telnet_test

import (
	"bytes"
	"testing"
)

func FuzzReceive(fuzzing *testing.F) {
	seeds := [][]byte{
		nil,
		answers,
		join(request(doVerb, telnetTypeOption), request(will, windowSizeOption), answers),
		join([]byte{iac, subnegotiationBegin, telnetTypeOption, iac, iac, subnegotiationEnd, iac, subnegotiationEnd}, answers),
		join(request(dont, echo), request(doVerb, echo), request(dont, echo), request(doVerb, sga), request(doVerb, 1)),
		{iac, iac, iac, doVerb, iac},
		{iac, subnegotiationBegin, iac},
		join([]byte{iac, nop, iac, ayt, 0, 255, 255}, request(doVerb, 255)),
	}
	for _, seed := range seeds {
		fuzzing.Add(seed, uint8(3))
	}
	fuzzing.Fuzz(func(t *testing.T, input []byte, cutAt uint8) {
		cut := min(int(cutAt), len(input))
		inOne := fresh()
		whole, wholeEnded := receive(t, inOne, input, nil)
		checkReplies(t, whole, input)
		if want := expectedReplies(input); !bytes.Equal(whole, want) {
			t.Fatalf("replies to % x were\n% x\nwant\n% x", input, whole, want)
		}
		// The probe shows where the reading stands after the input, also when it replied nothing.
		probed, _ := receive(t, inOne, probe, nil)
		afterInput := &reading{}
		afterInput.readAll(input)
		if want, _ := afterInput.readAll(probe); !bytes.Equal(probed, want) {
			t.Fatalf("after % x the probe got % x, want % x", input, probed, want)
		}

		// The same bytes in two calls, and a byte at a time, give the same replies and end at the
		// same byte.
		inTwo := fresh()
		firstHalf, firstEnded := receive(t, inTwo, input[:cut], nil)
		if len(firstHalf) > cut+2 {
			t.Fatalf("one call appended %d bytes for %d of input", len(firstHalf), cut)
		}
		both, secondEnded := receive(t, inTwo, input[cut:], firstHalf)
		if len(both)-len(firstHalf) > len(input)-cut+2 {
			t.Fatalf("one call appended %d bytes for %d of input", len(both)-len(firstHalf), len(input)-cut)
		}
		if !bytes.Equal(both, whole) || secondEnded != wholeEnded {
			t.Fatalf("split at %d: % x %v, in one call: % x %v", cut, both, secondEnded, whole, wholeEnded)
		}
		oracle := &reading{}
		_, endedByOracle := oracle.readAll(input[:cut])
		if firstEnded != endedByOracle {
			t.Fatalf("after the first %d bytes Receive returned %v, want %v", cut, firstEnded, endedByOracle)
		}

		singly := fresh()
		var replies []byte
		oracle = &reading{}
		for index := range input {
			before := len(replies)
			var ended bool
			replies, ended = receive(t, singly, input[index:index+1], replies)
			if len(replies)-before > 3 {
				t.Fatalf("one byte got %d bytes of replies", len(replies)-before)
			}
			oracle.feed(input[index])
			if ended != oracle.ended {
				t.Fatalf("at byte %d Receive returned %v, want %v", index, ended, oracle.ended)
			}
		}
		if !bytes.Equal(replies, whole) {
			t.Fatalf("a byte at a time: % x, in one call: % x", replies, whole)
		}

		// Once ended it stays ended and nothing changes.
		if wholeEnded {
			after := fresh()
			_, _ = receive(t, after, input, nil)
			more, ended := receive(t, after, input, nil)
			if len(more) != 0 || !ended {
				t.Fatalf("after the end, the same input again gave % x %v", more, ended)
			}
		}
	})
}

// checkReplies holds every reply to the contract's bounds: well-formed 3-byte WILL, WONT or
// DONT, and no more bytes than the input held.
func checkReplies(t *testing.T, replies, input []byte) {
	t.Helper()
	if len(replies) > len(input) {
		t.Fatalf("%d bytes of replies for %d of input", len(replies), len(input))
	}
	if len(replies)%3 != 0 {
		t.Fatalf("replies are not whole requests: % x", replies)
	}
	for index := 0; index < len(replies); index += 3 {
		if replies[index] != iac || (replies[index+1] != will && replies[index+1] != wont && replies[index+1] != dont) {
			t.Fatalf("reply % x is not IAC WILL, WONT or DONT", replies[index:index+3])
		}
	}
}
