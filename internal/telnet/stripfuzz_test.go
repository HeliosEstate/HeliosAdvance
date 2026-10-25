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
		{join(answers, []byte("alice\r")), 6},
		{join(request(doVerb, echo), []byte{iac, doVerb}, []byte{telnetTypeOption, 'k'}), 5},
		{join(answers, []byte{iac, iac, 'a', iac, subnegotiationBegin, 24, iac, iac, subnegotiationEnd, 'x', iac, subnegotiationEnd, 'b'}), 6},
		{join(answers, request(dont, echo), request(doVerb, echo), request(will, 31), request(doVerb, 255)), 6},
		{join([]byte("typed during"), request(dont, sga)), 3},
		{join(answers, []byte{iac, nop, iac, ayt, 0, 127, 255}), 6},
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
		during := &reading{}
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
		after := carryOn(during)
		want := expectedStrip(after, input[handedOver:])
		got := stripAll(t, negotiation, input[handedOver:])
		if !bytes.Equal(got.replies, want.replies) || !equalData(got.data, want.data) {
			t.Fatalf("after %d bytes to Receive, Strip of % x replied % x, data %v; want % x, data %v",
				handedOver, input[handedOver:], got.replies, got.data, want.replies, want.data)
		}
		replies = append(replies, got.replies...)
		checkReplies(t, replies, input)
		// The same replies as when Strip takes over at the first byte.
		fromStart := stripAll(t, fresh(), input)
		if !bytes.Equal(fromStart.replies, replies) {
			t.Fatalf("Strip from the first byte replied % x, Receive then Strip % x", fromStart.replies, replies)
		}
	})
}

// probeStrip shows Strip is live on a negotiation New returned: a is data, and DO 24 is refused.
func probeStrip(t *testing.T) {
	t.Helper()
	got := stripAll(t, fresh(), join([]byte("a"), request(doVerb, telnetTypeOption)))
	if !bytes.Equal(got.replies, request(wont, telnetTypeOption)) || !equalData(got.data, []bool{true, false, false, false}) {
		t.Fatalf("Strip of a and DO 24 on a new negotiation replied % x, data %v", got.replies, got.data)
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
