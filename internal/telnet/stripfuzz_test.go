// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The fuzz target for Strip, the reading of a caller's bytes after negotiation: the checks the
// Telnet contract lists under untrusted input, on every input the fuzzer finds.
package telnet_test

import (
	"bytes"
	"testing"
)

func FuzzStrip(fuzzing *testing.F) {
	seeds := []struct {
		input []byte
		cut   uint8
	}{
		{nil, 0},
		{join(answers, []byte("alice\r")), 24},
		{join(request(doVerb, echo), []byte{iac, doVerb}, []byte{telnetTypeOption, 'k'}), 5},
		{join(answers, []byte{iac, iac, 'a', iac, subnegotiationBegin, 24, iac, iac, subnegotiationEnd, 'x', iac, subnegotiationEnd, 'b'}), 24},
		{join(answers, request(dont, echo), request(doVerb, echo), request(will, 31), request(doVerb, 255)), 24},
		{join([]byte("typed during"), request(dont, sga)), 3},
		{join(answers, command(nop), command(ayt), command(abortOutput), command(eraseCharacter), command(eraseLine), []byte{0, 127, 255}), 24},
		{join(firstAnswers, request(wont, environOption), []byte("ab"), request(will, environOption)), 9},
	}
	for _, seed := range seeds {
		fuzzing.Add(seed.input, seed.cut)
	}
	fuzzing.Fuzz(func(t *testing.T, input []byte, cutAt uint8) {
		// Every run starts by showing Strip is live, so an input that rightly gives nothing cannot
		// pass for code that does nothing.
		probeStrip(t)
		cut := min(int(cutAt), len(input))
		// Receive takes the bytes one at a time up to the cut, stopping early once it returns
		// true; Strip takes the rest one at a time, as the Line hands them over.
		negotiation := fresh()
		during := freshReading()
		var replies []byte
		handedOver := cut
		for index := 0; index < cut; index++ {
			got, ended := receive(t, negotiation, input[index:index+1], nil)
			during.feed(input[index])
			replies = append(replies, got...)
			if ended {
				handedOver = index + 1
				break
			}
		}
		synchsDuring := negotiation.TakeSynch()
		want := expectedStrip(during.takeOver(), input[handedOver:])
		got := stripAll(t, negotiation, input[handedOver:])
		if !bytes.Equal(got.replies, want.replies) || !equalData(got.handed, want.handed) || !bytes.Equal(got.data, want.data) || got.synchs != want.synchs {
			t.Fatalf("after %d bytes to Receive, Strip of % x replied % x, handed on % x, %d Synchs; want % x, % x, %d",
				handedOver, input[handedOver:], got.replies, got.data, got.synchs, want.replies, want.data, want.synchs)
		}
		replies = append(replies, got.replies...)
		checkReplies(t, replies, input)
		// The same replies and Synchs as when Strip takes over at the first byte.
		fromStart := stripAll(t, fresh(), input)
		if !bytes.Equal(fromStart.replies, replies) || fromStart.synchs != synchsDuring+got.synchs {
			t.Fatalf("Strip from the first byte replied % x, %d Synchs; Receive then Strip % x, %d", fromStart.replies, fromStart.synchs, replies, synchsDuring+got.synchs)
		}
	})
}

// probeStrip shows Strip is live on a negotiation New returned: a is data, DO 24 is refused, WILL
// SGA agreed and EC handed on as BS.
func probeStrip(t *testing.T) {
	t.Helper()
	got := stripAll(t, fresh(), join([]byte("a"), request(doVerb, telnetTypeOption), request(will, sga), command(eraseCharacter)))
	if !bytes.Equal(got.replies, join(request(wont, telnetTypeOption), request(doVerb, sga))) || !bytes.Equal(got.data, []byte{'a', backspace}) {
		t.Fatalf("Strip of a, DO 24, WILL SGA and EC on a new negotiation replied % x, handed on % x", got.replies, got.data)
	}
}

func equalData(got, want []bool) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}
