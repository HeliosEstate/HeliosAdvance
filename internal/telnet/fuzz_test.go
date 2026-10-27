// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The fuzz target for Receive, the one place a caller's bytes are read during negotiation: the
// checks the Telnet contract lists under untrusted input, on every input the fuzzer finds.
package telnet_test

import (
	"bytes"
	"testing"
)

func FuzzReceive(fuzzing *testing.F) {
	seeds := [][]byte{
		nil,
		answers,
		agreeAll,
		join(request(doVerb, telnetTypeOption), request(will, windowSizeOption), answers),
		join([]byte{iac, subnegotiationBegin, telnetTypeOption, iac, iac, subnegotiationEnd, iac, subnegotiationEnd}, answers),
		join(request(dont, echo), request(doVerb, echo), request(dont, echo), request(doVerb, sga), request(doVerb, 1)),
		join(request(wont, environOption), request(will, environOption), request(wont, environOption), request(will, environOption)),
		{iac, iac, iac, doVerb, iac},
		{iac, subnegotiationBegin, iac},
		join(command(nop), command(ayt), command(abortOutput), command(interruptProcess), []byte{0, 255, 255}, request(doVerb, 255)),
	}
	for _, seed := range seeds {
		fuzzing.Add(seed, uint8(3))
	}
	fuzzing.Fuzz(func(t *testing.T, input []byte, cutAt uint8) {
		cut := min(int(cutAt), len(input))
		inOne := fresh()
		whole, wholeEnded := receive(t, inOne, input, nil)
		wholeSynchs := inOne.TakeSynch()
		checkReplies(t, whole, input)
		oracle := freshReading()
		want, _ := oracle.readAll(input)
		if !bytes.Equal(whole, want) || wholeSynchs != oracle.synchs {
			t.Fatalf("replies to % x were\n% x, %d Synchs\nwant\n% x, %d", input, whole, wholeSynchs, want, oracle.synchs)
		}
		// The probe shows where the reading stands after the input, also when it replied nothing.
		probed, _ := receive(t, inOne, probe, nil)
		if want, _ := oracle.readAll(probe); !bytes.Equal(probed, want) {
			t.Fatalf("after % x the probe got % x, want % x", input, probed, want)
		}

		// The same bytes in two calls, and a byte at a time, give the same replies and Synchs and
		// end at the same byte.
		inTwo := fresh()
		firstHalf, firstEnded := receive(t, inTwo, input[:cut], nil)
		if len(firstHalf) > 5*cut+mostOneReply {
			t.Fatalf("one call appended %d bytes for %d of input", len(firstHalf), cut)
		}
		both, secondEnded := receive(t, inTwo, input[cut:], firstHalf)
		if len(both)-len(firstHalf) > 5*(len(input)-cut)+mostOneReply {
			t.Fatalf("one call appended %d bytes for %d of input", len(both)-len(firstHalf), len(input)-cut)
		}
		if synchs := inTwo.TakeSynch(); !bytes.Equal(both, whole) || secondEnded != wholeEnded || synchs != wholeSynchs {
			t.Fatalf("split at %d: % x %v %d Synchs, in one call: % x %v %d", cut, both, secondEnded, synchs, whole, wholeEnded, wholeSynchs)
		}
		halfway := freshReading()
		_, endedByOracle := halfway.readAll(input[:cut])
		if firstEnded != endedByOracle {
			t.Fatalf("after the first %d bytes Receive returned %v, want %v", cut, firstEnded, endedByOracle)
		}

		singly := fresh()
		var replies []byte
		bytewise := freshReading()
		for index := range input {
			before := len(replies)
			var ended bool
			replies, ended = receive(t, singly, input[index:index+1], replies)
			if len(replies)-before > mostOneReply {
				t.Fatalf("one byte got %d bytes of replies", len(replies)-before)
			}
			bytewise.feed(input[index])
			if ended != bytewise.ended {
				t.Fatalf("at byte %d Receive returned %v, want %v", index, ended, bytewise.ended)
			}
		}
		if synchs := singly.TakeSynch(); !bytes.Equal(replies, whole) || synchs != wholeSynchs {
			t.Fatalf("a byte at a time: % x, %d Synchs, in one call: % x, %d", replies, synchs, whole, wholeSynchs)
		}

		// Once ended it stays ended and nothing changes.
		if wholeEnded {
			after := fresh()
			_, _ = receive(t, after, input, nil)
			after.TakeSynch()
			more, ended := receive(t, after, input, nil)
			if len(more) != 0 || !ended || after.TakeSynch() != 0 {
				t.Fatalf("after the end, the same input again gave % x %v", more, ended)
			}
		}
	})
}

// checkReplies holds the replies to the contract's bounds: each one a well-formed 3-byte WILL,
// WONT, DO or DONT, one of the three SENDs, or AYT's answer; each SEND at most once; and no more
// bytes than five times the input held.
func checkReplies(t *testing.T, replies, input []byte) {
	t.Helper()
	if len(replies) > 5*len(input) {
		t.Fatalf("%d bytes of replies for %d of input", len(replies), len(input))
	}
	sends := map[string]int{}
	for rest := replies; len(rest) > 0; {
		switch {
		case bytes.HasPrefix(rest, []byte(aytAnswerBytes)):
			rest = rest[len(aytAnswerBytes):]
		case bytes.HasPrefix(rest, terminalTypeSend), bytes.HasPrefix(rest, speedSend), bytes.HasPrefix(rest, environSend):
			for _, send := range [][]byte{terminalTypeSend, speedSend, environSend} {
				if bytes.HasPrefix(rest, send) {
					sends[string(send)]++
					if sends[string(send)] > 1 {
						t.Fatalf("the SEND % x was appended twice: % x", send, replies)
					}
					rest = rest[len(send):]
				}
			}
		case len(rest) >= 3 && rest[0] == iac && (rest[1] == will || rest[1] == wont || rest[1] == doVerb || rest[1] == dont):
			rest = rest[3:]
		default:
			t.Fatalf("the replies hold % x, which is no reply the contract allows: % x", rest, replies)
		}
	}
}
