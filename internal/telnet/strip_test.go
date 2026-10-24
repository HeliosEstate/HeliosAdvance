// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests of Strip, the reading of a caller's bytes after negotiation: which bytes are data, the
// reply to every option request in every state ECHO and SGA can be left in, the commands it
// discards, and a sequence split across negotiation's end, against the test's own reading of
// RFC 854, RFC 855 and RFC 1143 section 7.
package telnet_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/telnet"
)

// afterReading is the test's own reading of the bytes after negotiation: the same tables as
// during it, kept going past its end, and which bytes are data.
type afterReading struct {
	reading
}

// carryOn is the test's reading taken over from where a reading of negotiation stopped.
func carryOn(during *reading) *afterReading {
	return &afterReading{reading: reading{states: during.states, phase: during.phase, verb: during.verb}}
}

// strip reads one byte after negotiation: the reply it completes, and whether it is data.
func (state *afterReading) strip(value byte) ([]byte, bool) {
	switch state.phase {
	case phaseData:
		if value == iac {
			state.phase = phaseAfterCommand
			return nil, false
		}
		return nil, true
	case phaseAfterCommand:
		switch value {
		case will, wont, doVerb, dont:
			state.verb = value
			state.phase = phaseAfterVerb
		case subnegotiationBegin:
			state.phase = phaseInSubnegotiation
		case iac:
			state.phase = phaseData
			return nil, true
		default:
			state.phase = phaseData
		}
		return nil, false
	case phaseAfterVerb:
		state.phase = phaseData
		// The tables do not end anything after negotiation: the count of answers is left alone.
		answers := state.answers
		reply := state.answer(state.verb, value)
		state.answers, state.ended = answers, false
		return reply, false
	case phaseInSubnegotiation:
		if value == iac {
			state.phase = phaseInSubnegotiationAfterCommand
		}
	case phaseInSubnegotiationAfterCommand:
		if value == subnegotiationEnd {
			state.phase = phaseData
		} else {
			state.phase = phaseInSubnegotiation
		}
	}
	return nil, false
}

// stripped is what Strip gave for some bytes, one call per byte.
type stripped struct {
	replies []byte
	data    []bool
}

// stripAll calls Strip once per byte, checking on each call that the bytes already in replies
// stay and that it appends at most one reply.
func stripAll(t *testing.T, negotiation *telnet.Negotiation, input []byte) stripped {
	t.Helper()
	var result stripped
	prior := []byte("prior")
	for index, value := range input {
		replies := append(make([]byte, 0, len(prior)), prior...)
		got, isData := stripOne(t, negotiation, value, replies)
		if len(got) < len(prior) || !bytes.Equal(got[:len(prior)], prior) || !bytes.Equal(replies, prior) {
			t.Fatalf("Strip of byte %d changed the bytes already in replies: % x", index, got)
		}
		appended := got[len(prior):]
		if len(appended) > 3 {
			t.Fatalf("one call of Strip appended %d bytes: % x", len(appended), appended)
		}
		result.replies = append(result.replies, appended...)
		result.data = append(result.data, isData)
	}
	return result
}

func stripOne(t *testing.T, negotiation *telnet.Negotiation, value byte, replies []byte) (got []byte, isData bool) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("Strip panicked on %#02x: %v", value, recovered)
		}
	}()
	return negotiation.Strip(value, replies)
}

// expectedStrip is the test's own reading of the same bytes.
func expectedStrip(state *afterReading, input []byte) stripped {
	var result stripped
	for _, value := range input {
		reply, isData := state.strip(value)
		result.replies = append(result.replies, reply...)
		result.data = append(result.data, isData)
	}
	return result
}

// stripProbe asks for ECHO and SGA to stop and start again, and for an option the engine
// refuses: the replies show the state each option was left in, and that the reading kept up.
var stripProbe = join([]byte{iac, subnegotiationEnd, iac, nop},
	request(dont, echo), request(doVerb, echo), request(dont, sga), request(doVerb, sga),
	request(doVerb, telnetTypeOption))

// ending is how negotiation ended before Strip took over, made by hand through New and Receive.
type ending struct {
	name  string
	input []byte
}

// endings are the states ECHO and SGA can be left in, Receive having returned true or not.
var endings = []ending{
	{name: "after DO DO", input: answers},
	{name: "after DONT DONT", input: join(request(dont, echo), request(dont, sga))},
	{name: "after DO ECHO, DONT SGA", input: join(request(doVerb, echo), request(dont, sga))},
	{name: "after DONT ECHO, DO SGA", input: join(request(dont, echo), request(doVerb, sga))},
	{name: "with no answer, as when 3 seconds pass", input: nil},
	{name: "after DO ECHO alone, as when 3 seconds pass", input: request(doVerb, echo)},
	{name: "after DONT SGA alone, as when 3 seconds pass", input: request(dont, sga)},
}

// negotiated runs Receive over the ending's bytes and returns the negotiation and the test's
// reading of where it stopped.
func negotiatedBy(t *testing.T, input []byte) (*telnet.Negotiation, *reading) {
	t.Helper()
	negotiation := fresh()
	during := &reading{}
	wantReplies, wantEnded := during.readAll(input)
	got, ended := receive(t, negotiation, input, nil)
	if !bytes.Equal(got, wantReplies) || ended != wantEnded {
		t.Fatalf("setting up: Receive of % x gave % x %v, want % x %v", input, got, ended, wantReplies, wantEnded)
	}
	return negotiation, during
}

// expectStrip strips the row's bytes and then the probe, checking both against the test's own
// reading, and that every reply is well-formed and the replies never outgrow the input.
func expectStrip(t *testing.T, before []byte, input []byte, wantReplies []byte, wantData []bool) {
	t.Helper()
	negotiation, during := negotiatedBy(t, before)
	oracle := carryOn(during)
	want := expectedStrip(oracle, input)
	if wantReplies != nil && !bytes.Equal(want.replies, wantReplies) || wantData != nil && fmt.Sprint(want.data) != fmt.Sprint(wantData) {
		t.Fatalf("test fault: the row disagrees with the test's own reading: % x %v", want.replies, want.data)
	}
	got := stripAll(t, negotiation, input)
	if !bytes.Equal(got.replies, want.replies) || fmt.Sprint(got.data) != fmt.Sprint(want.data) {
		t.Fatalf("Strip of % x replied\n% x\nand called data %v\nwant\n% x\n%v", input, got.replies, got.data, want.replies, want.data)
	}
	probeWant := expectedStrip(oracle, stripProbe)
	probed := stripAll(t, negotiation, stripProbe)
	if !bytes.Equal(probed.replies, probeWant.replies) {
		t.Fatalf("after % x the probe got % x, want % x", input, probed.replies, probeWant.replies)
	}
	all := join(before, input, stripProbe)
	duringReplies, _ := (&reading{}).readAll(before)
	checkReplies(t, join(duringReplies, got.replies, probed.replies), all)
}

func everyByte() []byte {
	var values []byte
	for code := range 256 {
		values = append(values, byte(code))
	}
	return values
}

func TestStrip(t *testing.T) {
	t.Parallel()
	t.Run("Strip shall return true for each data byte and false for each byte of a Telnet command.", func(t *testing.T) {
		t.Parallel()
		for _, end := range endings {
			t.Run("every byte but IAC is data, "+end.name, func(t *testing.T) {
				t.Parallel()
				input := everyByte()[:255]
				data := make([]bool, len(input))
				for index := range data {
					data[index] = true
				}
				expectStrip(t, end.input, input, []byte{}, data)
			})
		}
		commands := map[string][]byte{
			"IAC NOP":                      {iac, nop},
			"IAC AYT":                      {iac, ayt},
			"DO 24":                        request(doVerb, telnetTypeOption),
			"WILL 31":                      request(will, windowSizeOption),
			"WONT ECHO":                    request(wont, echo),
			"a subnegotiation":             {iac, subnegotiationBegin, telnetTypeOption, 1, 'x', iac, subnegotiationEnd},
			"text around a request":        join([]byte("ab"), request(doVerb, telnetTypeOption), []byte("c")),
			"text around a subnegotiation": join([]byte("a"), []byte{iac, subnegotiationBegin, windowSizeOption, 0, 80, iac, subnegotiationEnd}, []byte("b")),
		}
		for name, input := range commands {
			t.Run(name+", after DO DO", func(t *testing.T) {
				t.Parallel()
				expectStrip(t, answers, input, nil, nil)
			})
		}
	})
	t.Run("When the bytes hold IAC IAC outside a subnegotiation, Strip shall return false for the first IAC and true for the second, the data byte 255.", func(t *testing.T) {
		t.Parallel()
		for _, end := range endings {
			t.Run("IAC IAC, "+end.name, func(t *testing.T) {
				t.Parallel()
				expectStrip(t, end.input, []byte{iac, iac}, []byte{}, []bool{false, true})
			})
		}
		t.Run("a then IAC IAC IAC IAC then b: two data bytes 255", func(t *testing.T) {
			t.Parallel()
			expectStrip(t, answers, []byte{'a', iac, iac, iac, iac, 'b'}, []byte{}, []bool{true, false, true, false, true, true})
		})
		t.Run("IAC IAC then DO 24: the third IAC starts a request", func(t *testing.T) {
			t.Parallel()
			expectStrip(t, answers, join([]byte{iac, iac}, request(doVerb, telnetTypeOption)), request(wont, telnetTypeOption), []bool{false, true, false, false, false})
		})
	})
	t.Run("When a byte completes an option request, Strip shall answer it into replies and change the option's state exactly as Receive's lines do while negotiation lasts.", func(t *testing.T) {
		t.Parallel()
		for _, end := range endings {
			for _, verb := range []byte{will, wont, doVerb, dont} {
				t.Run(fmt.Sprintf("verb %d for every option, %s", verb, end.name), func(t *testing.T) {
					t.Parallel()
					for code := range 256 {
						expectStrip(t, end.input, request(verb, byte(code)), nil, []bool{false, false, false})
					}
				})
			}
		}
		t.Run("the RFC 1143 table after DO DO: DONT ECHO gives WONT ECHO, then DO ECHO gives WILL ECHO", func(t *testing.T) {
			t.Parallel()
			expectStrip(t, answers, join(request(dont, echo), request(doVerb, echo), request(doVerb, echo)),
				join(request(wont, echo), request(will, echo)), nil)
		})
		t.Run("a late yes: DO ECHO with ECHO still in WANTYES moves it to YES with no reply", func(t *testing.T) {
			t.Parallel()
			expectStrip(t, nil, join(request(doVerb, echo), request(dont, echo)), request(wont, echo), nil)
		})
	})
	t.Run("When the bytes hold IAC and then a byte other than WILL, WONT, DO, DONT, SB or IAC, or a subnegotiation, Strip shall discard them without reply.", func(t *testing.T) {
		t.Parallel()
		t.Run("IAC and every other byte, after DO DO", func(t *testing.T) {
			t.Parallel()
			for code := range 256 {
				value := byte(code)
				if value == will || value == wont || value == doVerb || value == dont || value == subnegotiationBegin || value == iac {
					continue
				}
				expectStrip(t, answers, []byte{iac, value}, []byte{}, []bool{false, false})
			}
		})
		subnegotiations := map[string][]byte{
			"requests inside a subnegotiation get no reply": join([]byte{iac, subnegotiationBegin, telnetTypeOption}, request(doVerb, telnetTypeOption), request(will, windowSizeOption), []byte{iac, subnegotiationEnd}),
			"IAC IAC SE inside does not end it":             {iac, subnegotiationBegin, telnetTypeOption, iac, iac, subnegotiationEnd, 'x', iac, subnegotiationEnd},
			"every byte inside a subnegotiation":            join([]byte{iac, subnegotiationBegin}, bytes.ReplaceAll(everyByte(), []byte{iac}, []byte{iac, iac}), []byte{iac, subnegotiationEnd}),
		}
		for name, input := range subnegotiations {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				data := make([]bool, len(input))
				expectStrip(t, answers, input, []byte{}, data)
			})
		}
	})
	t.Run("When a sequence is split across negotiation's end, Strip shall read it as it would had the sequence come after it whole.", func(t *testing.T) {
		t.Parallel()
		sequences := map[string][]byte{
			"DO 24":              request(doVerb, telnetTypeOption),
			"WILL 31":            request(will, windowSizeOption),
			"DONT ECHO":          request(dont, echo),
			"IAC IAC":            {iac, iac},
			"IAC NOP":            {iac, nop},
			"a subnegotiation":   {iac, subnegotiationBegin, telnetTypeOption, iac, iac, subnegotiationEnd, iac, subnegotiationEnd},
			"DO SGA, the answer": request(doVerb, sga),
		}
		for name, sequence := range sequences {
			for cut := 1; cut < len(sequence); cut++ {
				t.Run(fmt.Sprintf("%s, the first %d bytes read by negotiation before its 3 seconds passed", name, cut), func(t *testing.T) {
					t.Parallel()
					// One answer and the start of the sequence: negotiation has not ended, as when
					// 3 seconds pass with a read cut there.
					before := join(request(doVerb, echo), sequence[:cut])
					whole := carryOn(func() *reading {
						state := &reading{}
						state.readAll(request(doVerb, echo))
						return state
					}())
					want := expectedStrip(whole, sequence)
					expectStrip(t, before, sequence[cut:], want.replies, want.data[cut:])
				})
			}
		}
	})
	t.Run("Strip shall append its reply after the bytes already in replies, and leave those unchanged.", func(t *testing.T) {
		t.Parallel()
		for _, end := range endings {
			t.Run("DO 24, DONT ECHO and DO ECHO after the bytes prior, "+end.name, func(t *testing.T) {
				t.Parallel()
				// stripAll holds every call to the bytes already in replies.
				expectStrip(t, end.input, join(request(doVerb, telnetTypeOption), request(dont, echo), request(doVerb, echo)), nil, nil)
			})
		}
		t.Run("a reply into a slice with room to spare leaves the bytes past its length alone", func(t *testing.T) {
			t.Parallel()
			negotiation, _ := negotiatedBy(t, answers)
			backing := []byte("prior-and-spare")
			replies := backing[:5]
			for _, value := range request(doVerb, telnetTypeOption) {
				replies, _ = stripOne(t, negotiation, value, replies)
			}
			if !bytes.Equal(replies, join([]byte("prior"), request(wont, telnetTypeOption))) {
				t.Fatalf("replies were % x", replies)
			}
		})
	})
	t.Run("Strip shall append at most one reply, 3 bytes, in one call.", func(t *testing.T) {
		t.Parallel()
		for _, end := range endings {
			t.Run("every request for every option, one call per byte, "+end.name, func(t *testing.T) {
				t.Parallel()
				var input []byte
				for _, verb := range []byte{will, wont, doVerb, dont} {
					for code := range 256 {
						input = append(input, request(verb, byte(code))...)
					}
				}
				// stripAll fails a call that appends more than 3 bytes.
				expectStrip(t, end.input, input, nil, nil)
			})
		}
	})
	t.Run("Strip shall append to replies, over all its calls and Receive's on one negotiation, no more bytes than all their input held.", func(t *testing.T) {
		t.Parallel()
		for _, end := range endings {
			t.Run("a thousand toggles of ECHO and SGA and refused requests, "+end.name, func(t *testing.T) {
				t.Parallel()
				input := repeated(join(request(dont, echo), request(doVerb, echo), request(dont, sga), request(doVerb, sga), request(will, telnetTypeOption), request(doVerb, windowSizeOption)), 1000)
				// expectStrip holds the replies of Receive and Strip together to the input.
				expectStrip(t, end.input, input, nil, nil)
			})
		}
	})
	t.Run("After Strip's first call, Receive shall append no reply and change no state on that negotiation, for every later call.", func(t *testing.T) {
		t.Parallel()
		rows := map[string][]byte{
			"with no answer: Receive given the answers after Strip read a data byte":   nil,
			"after DO ECHO alone: Receive given DONT SGA after Strip read a data byte": request(doVerb, echo),
		}
		for name, before := range rows {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				negotiation, during := negotiatedBy(t, before)
				oracle := carryOn(during)
				expectedStrip(oracle, []byte("a"))
				stripAll(t, negotiation, []byte("a"))
				for _, input := range [][]byte{join(request(dont, echo), request(dont, sga)), request(doVerb, telnetTypeOption), request(will, windowSizeOption)} {
					got, ended := receive(t, negotiation, input, nil)
					if len(got) != 0 || ended {
						t.Fatalf("Receive of % x after Strip appended % x and returned %v", input, got, ended)
					}
				}
				// The states are as Strip left them: Receive's DONT moved nothing.
				want := expectedStrip(oracle, stripProbe)
				probed := stripAll(t, negotiation, stripProbe)
				if !bytes.Equal(probed.replies, want.replies) {
					t.Fatalf("after Receive's calls the probe got % x, want % x", probed.replies, want.replies)
				}
			})
		}
		t.Run("after DO DO: Receive after Strip appends nothing and still returns true", func(t *testing.T) {
			t.Parallel()
			negotiation, _ := negotiatedBy(t, answers)
			if stripped := stripAll(t, negotiation, request(dont, echo)); !bytes.Equal(stripped.replies, request(wont, echo)) {
				t.Fatalf("Strip of DONT ECHO after DO DO replied % x, want WONT ECHO", stripped.replies)
			}
			got, ended := receive(t, negotiation, join(request(doVerb, echo), request(doVerb, telnetTypeOption)), nil)
			if len(got) != 0 || !ended {
				t.Fatalf("Receive after Strip appended % x and returned %v", got, ended)
			}
			// ECHO is as Strip left it, NO: DO ECHO is answered with WILL ECHO.
			if stripped := stripAll(t, negotiation, request(doVerb, echo)); !bytes.Equal(stripped.replies, request(will, echo)) {
				t.Fatalf("after Receive, Strip of DO ECHO replied % x, want WILL ECHO", stripped.replies)
			}
		})
	})
	t.Run("Strip shall return for every byte without failing or panicking.", func(t *testing.T) {
		t.Parallel()
		prefixes := map[string][]byte{
			"in data":                         nil,
			"after IAC":                       {iac},
			"after IAC DO":                    {iac, doVerb},
			"inside a subnegotiation":         {iac, subnegotiationBegin},
			"after IAC inside one":            {iac, subnegotiationBegin, iac},
			"after IAC SB, the option unread": {iac, subnegotiationBegin, telnetTypeOption},
		}
		for _, end := range endings {
			for name, prefix := range prefixes {
				t.Run(fmt.Sprintf("every byte %s, %s", name, end.name), func(t *testing.T) {
					t.Parallel()
					for code := range 256 {
						expectStrip(t, end.input, join(prefix, []byte{byte(code)}), nil, nil)
					}
				})
			}
		}
		t.Run("a Negotiation not made by New", func(t *testing.T) {
			t.Parallel()
			var negotiation telnet.Negotiation
			for code := range 256 {
				stripOne(t, &negotiation, byte(code), nil)
			}
			// It reads as a negotiation New returned does: a is data, DO 24 is refused.
			var zero telnet.Negotiation
			got := stripAll(t, &zero, join([]byte("a"), request(doVerb, telnetTypeOption)))
			if !bytes.Equal(got.replies, request(wont, telnetTypeOption)) || fmt.Sprint(got.data) != fmt.Sprint([]bool{true, false, false, false}) {
				t.Fatalf("a zero Negotiation's Strip of a and DO 24 replied % x, data %v", got.replies, got.data)
			}
		})
	})
}
