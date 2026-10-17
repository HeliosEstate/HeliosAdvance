// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests of New and Receive: how every byte a caller sends is read, the reply to every option
// request, the RFC 1143 state of ECHO and SGA, and the end of negotiation, with RFC 854's command
// list and RFC 1143 section 7's table as the vectors.
package telnet_test

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/telnet"
)

// step is one call of Receive: its input, the bytes it must append, and what it must return.
type step struct {
	input []byte
	want  []byte
	ended bool
	// probe marks the closing request runSteps adds, whose expectation is the test's own reading.
	probe bool
}

// probe ends a subnegotiation if one is open, and is a two-byte command if not, then asks for an
// option the engine refuses: whatever state a row leaves, a reading that kept up answers it.
var probe = join([]byte{iac, subnegotiationEnd, iac, subnegotiationEnd}, request(doVerb, telnetTypeOption))

// receiveCase is one row: a fresh negotiation and the calls made on it.
type receiveCase struct {
	name  string
	steps []step
}

// receiveLine is a line and the rows that prove it.
type receiveLine struct {
	line  string
	cases []receiveCase
}

// one is a row of a single call.
func one(name string, input, want []byte, ended bool) receiveCase {
	return receiveCase{name: name, steps: []step{{input: input, want: want, ended: ended}}}
}

var answers = join(request(doVerb, echo), request(doVerb, sga))

// runSteps makes the calls of one row on negotiation and checks each: the bytes it appends, what
// it returns, that the bytes already in replies stay, and the contract's bounds on how much it
// appends. Each row is also read by the test's own reading, so a row that disagrees with RFC
// 1143 is a fault in the test, reported as one. Every row ends with a probe, a request the
// reading must reach and answer, unless negotiation has ended: so a row whose own calls rightly
// get no reply still shows the bytes before it were read as the line says, and are not merely
// ignored.
func runSteps(t *testing.T, negotiation *telnet.Negotiation, steps []step) {
	t.Helper()
	oracle := &reading{}
	prior := []byte("prior")
	totalInput, totalAppended := 0, 0
	steps = append(slices.Clone(steps), step{input: probe, probe: true})
	for index, call := range steps {
		wantByOracle, endedByOracle := oracle.readAll(call.input)
		if call.probe {
			call.want, call.ended = wantByOracle, endedByOracle
		}
		if !bytes.Equal(wantByOracle, call.want) || endedByOracle != call.ended {
			t.Fatalf("test fault: call %d's row disagrees with the test's own reading of RFC 1143: % x %v", index, wantByOracle, endedByOracle)
		}
		replies := append(make([]byte, 0, len(prior)), prior...)
		got, ended := receive(t, negotiation, call.input, replies)
		if len(got) < len(prior) || !bytes.Equal(got[:len(prior)], prior) || !bytes.Equal(replies, prior) {
			t.Fatalf("call %d changed the bytes already in replies: % x", index, got)
		}
		appended := got[len(prior):]
		if !bytes.Equal(appended, call.want) {
			t.Fatalf("call %d of % x appended\n% x\nwant\n% x", index, call.input, appended, call.want)
		}
		if ended != call.ended {
			t.Fatalf("call %d of % x returned %v, want %v", index, call.input, ended, call.ended)
		}
		if len(appended) > len(call.input)+2 {
			t.Fatalf("call %d appended %d bytes for %d of input", index, len(appended), len(call.input))
		}
		totalInput += len(call.input)
		totalAppended += len(appended)
		if totalAppended > totalInput {
			t.Fatalf("after call %d, %d bytes appended for %d of input", index, totalAppended, totalInput)
		}
	}
}

// receive calls Receive and turns a panic into a test failure that names the input.
func receive(t *testing.T, negotiation *telnet.Negotiation, input, replies []byte) (got []byte, ended bool) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("Receive panicked on % x: %v", input, recovered)
		}
	}()
	return negotiation.Receive(input, replies)
}

func fresh() *telnet.Negotiation {
	negotiation, _ := telnet.New()
	return negotiation
}

// everyOption is one row per option code, for the tables that hold for any Telnet option.
func everyOption(verb byte, reply func(option byte) []byte, skip func(option byte) bool) []receiveCase {
	var cases []receiveCase
	for code := range 256 {
		option := byte(code)
		if skip(option) {
			continue
		}
		cases = append(cases, one(fmt.Sprintf("option %d", code), request(verb, option), reply(option), false))
	}
	return cases
}

func isEchoOrSuppressGoAhead(option byte) bool { return option == echo || option == sga }

func noneSkipped(byte) bool { return false }

// stateRows is the RFC 1143 section 7 table, one row per entry and per option, each reached
// while the other option is still in WANTYES so negotiation lasts, and each followed by a request
// whose reply shows the state the entry left.
func stateRows(option byte) map[string][]receiveCase {
	name := map[byte]string{echo: "ECHO", sga: "SGA"}[option]
	return map[string][]receiveCase{
		"WANTYES DO": {{name: name + ": no reply, then DONT gets WONT, so YES", steps: []step{
			{input: request(doVerb, option)},
			{input: request(dont, option), want: request(wont, option)},
		}}},
		"WANTYES DONT": {{name: name + ": no reply, then DO gets WILL, so NO", steps: []step{
			{input: request(dont, option)},
			{input: request(doVerb, option), want: request(will, option)},
		}}},
		"YES DO": {{name: name + ": no reply, then DONT still gets WONT", steps: []step{
			{input: request(doVerb, option)},
			{input: request(doVerb, option)},
			{input: request(dont, option), want: request(wont, option)},
		}}},
		"YES DONT": {{name: name + ": WONT, then DO gets WILL, so NO", steps: []step{
			{input: request(doVerb, option)},
			{input: request(dont, option), want: request(wont, option)},
			{input: request(doVerb, option), want: request(will, option)},
		}}},
		"NO DO": {{name: name + ": WILL, then DONT gets WONT, so YES", steps: []step{
			{input: request(dont, option)},
			{input: request(doVerb, option), want: request(will, option)},
			{input: request(dont, option), want: request(wont, option)},
		}}},
		"NO DONT": {{name: name + ": no reply, then DO still gets WILL", steps: []step{
			{input: request(dont, option)},
			{input: request(dont, option)},
			{input: request(doVerb, option), want: request(will, option)},
		}}},
	}
}

func stateLine(line, entry string) receiveLine {
	return receiveLine{line: line, cases: append(stateRows(echo)[entry], stateRows(sga)[entry]...)}
}

// splitRows gives, for each input, every split into two calls and the split into single bytes,
// each call's expected replies taken from the test's own reading.
func splitRows() []receiveCase {
	inputs := map[string][]byte{
		"both answers":                 answers,
		"a refusal, then the answers":  join(request(doVerb, telnetTypeOption), request(will, windowSizeOption), request(doVerb, echo), request(dont, sga)),
		"a subnegotiation and answers": join([]byte{iac, subnegotiationBegin, telnetTypeOption, iac, iac, subnegotiationEnd, 1, iac, subnegotiationEnd}, answers),
		"data 255, then a refusal":     join([]byte{iac, iac}, request(doVerb, telnetTypeOption)),
		"bytes after the end":          join(answers, request(doVerb, telnetTypeOption), request(will, windowSizeOption)),
		"ECHO through NO and back":     join(request(dont, echo), request(doVerb, echo), request(dont, echo), request(doVerb, sga)),
		"commands and a refusal":       join([]byte{iac, nop, iac, ayt}, request(doVerb, telnetTypeOption), []byte("text")),
	}
	var cases []receiveCase
	for name, input := range inputs {
		for cut := 1; cut < len(input); cut++ {
			cases = append(cases, receiveCase{name: fmt.Sprintf("%s, cut after %d", name, cut), steps: stepsFor(input[:cut], input[cut:])})
		}
		var single [][]byte
		for index := range input {
			single = append(single, input[index:index+1])
		}
		cases = append(cases, receiveCase{name: name + ", a byte at a time", steps: stepsFor(single...)})
	}
	return cases
}

// stepsFor reads the calls with the test's own reading to give each call's expectation.
func stepsFor(calls ...[]byte) []step {
	oracle := &reading{}
	var steps []step
	for _, input := range calls {
		want, ended := oracle.readAll(input)
		steps = append(steps, step{input: input, want: want, ended: ended})
	}
	return steps
}

func receiveLines() []receiveLine {
	var everyCommand []receiveCase
	for code := 240; code <= 249; code++ {
		command := byte(code)
		everyCommand = append(everyCommand, one(fmt.Sprintf("IAC %d, then a refusal", code),
			join([]byte{iac, command}, request(doVerb, telnetTypeOption)), request(wont, telnetTypeOption), false))
	}
	for _, command := range []byte{0, 1, 24, 239} {
		everyCommand = append(everyCommand, one(fmt.Sprintf("IAC %d, not a command, then a refusal", command),
			join([]byte{iac, command}, request(doVerb, telnetTypeOption)), request(wont, telnetTypeOption), false))
	}
	var everyDataByte []byte
	for code := range 255 {
		everyDataByte = append(everyDataByte, byte(code))
	}
	return []receiveLine{
		{line: "When input holds IAC, then WILL, WONT, DO or DONT, then one more byte, Receive shall read those three bytes as one option request.", cases: []receiveCase{
			one("WILL 24 gets DONT 24", request(will, telnetTypeOption), request(dont, telnetTypeOption), false),
			one("DO 24 gets WONT 24", request(doVerb, telnetTypeOption), request(wont, telnetTypeOption), false),
			one("DO 0 gets WONT 0", request(doVerb, 0), request(wont, 0), false),
			one("DO 255 gets WONT 255, and the 255 starts nothing", join(request(doVerb, 255), request(doVerb, telnetTypeOption)), join(request(wont, 255), request(wont, telnetTypeOption)), false),
			one("DO 250 gets WONT 250 and starts no subnegotiation", join(request(doVerb, subnegotiationBegin), request(doVerb, telnetTypeOption)), join(request(wont, subnegotiationBegin), request(wont, telnetTypeOption)), false),
			one("WILL 240 gets DONT 240", request(will, subnegotiationEnd), request(dont, subnegotiationEnd), false),
			one("WONT 24 then DONT 25 then DO 26: only WONT 26", join(request(wont, telnetTypeOption), request(dont, 25), request(doVerb, 26)), request(wont, 26), false),
		}},
		{line: "When input holds IAC IAC outside a subnegotiation, Receive shall discard both bytes without reply.", cases: []receiveCase{
			one("IAC IAC", []byte{iac, iac}, nil, false),
			one("IAC IAC DO 24 is data", []byte{iac, iac, doVerb, telnetTypeOption}, nil, false),
			one("IAC IAC, then a request", join([]byte{iac, iac}, request(doVerb, telnetTypeOption)), request(wont, telnetTypeOption), false),
			one("IAC IAC four times, then the answers", join(repeated([]byte{iac, iac}, 4), answers), nil, true),
		}},
		{line: "When input holds IAC SB, Receive shall discard every byte up to and including the next IAC SE without reply.", cases: []receiveCase{
			one("a subnegotiation, then a request", join([]byte{iac, subnegotiationBegin, telnetTypeOption, 1, iac, subnegotiationEnd}, request(doVerb, 25)), request(wont, 25), false),
			one("a request inside is discarded", join([]byte{iac, subnegotiationBegin, telnetTypeOption}, request(doVerb, telnetTypeOption), []byte{iac, subnegotiationEnd}, request(doVerb, 25)), request(wont, 25), false),
			one("SE without IAC does not end it", join([]byte{iac, subnegotiationBegin, telnetTypeOption, subnegotiationEnd}, request(doVerb, telnetTypeOption), []byte{iac, subnegotiationEnd}, request(doVerb, 25)), request(wont, 25), false),
			{name: "answers inside do not end negotiation", steps: []step{
				{input: join([]byte{iac, subnegotiationBegin, telnetTypeOption}, answers, []byte{iac, subnegotiationEnd})},
				{input: answers, ended: true},
			}},
			one("a subnegotiation that never ends swallows every request", join([]byte{iac, subnegotiationBegin, telnetTypeOption}, repeated(request(doVerb, telnetTypeOption), 300), answers), nil, false),
		}},
		{line: "While it is inside a subnegotiation, Receive shall read IAC IAC as one data byte, so that IAC IAC SE does not end the subnegotiation.", cases: []receiveCase{
			one("IAC IAC SE inside, then IAC SE", join([]byte{iac, subnegotiationBegin, telnetTypeOption, iac, iac, subnegotiationEnd}, request(doVerb, 25), []byte{iac, subnegotiationEnd}, request(doVerb, 26)), request(wont, 26), false),
			one("IAC IAC then IAC SE", join([]byte{iac, subnegotiationBegin, iac, iac, iac, subnegotiationEnd}, request(doVerb, 26)), request(wont, 26), false),
		}},
		{line: "When input holds IAC and then a byte other than WILL, WONT, DO, DONT, SB or IAC, Receive shall discard both bytes without reply.", cases: everyCommand},
		{line: "When input holds a byte that is not part of a sequence starting with IAC, Receive shall discard it without reply.", cases: []receiveCase{
			one("every byte but IAC", everyDataByte, nil, false),
			one("the answers without IAC", []byte{doVerb, echo, doVerb, sga}, nil, false),
			one("text, then a request", join([]byte("hello\r\n"), request(doVerb, telnetTypeOption)), request(wont, telnetTypeOption), false),
		}},
		{line: "When a sequence is split across calls, Receive shall reply to it and end negotiation as it would had the sequence come in one call.", cases: splitRows()},
		{line: "When the byte that completes the caller's second answer arrives, Receive shall return true.", cases: []receiveCase{
			one("DO ECHO DO SGA in one call", answers, nil, true),
			{name: "DO ECHO, then DO SGA", steps: []step{{input: request(doVerb, echo)}, {input: request(doVerb, sga), ended: true}}},
			{name: "DONT SGA, then DONT ECHO", steps: []step{{input: request(dont, sga)}, {input: request(dont, echo), ended: true}}},
			{name: "DO SGA, then DONT ECHO", steps: []step{{input: request(doVerb, sga)}, {input: request(dont, echo), ended: true}}},
			{name: "DONT ECHO, then DO SGA", steps: []step{{input: request(dont, echo)}, {input: request(doVerb, sga), ended: true}}},
			{name: "a byte at a time: true on the last byte only", steps: []step{
				{input: []byte{iac}}, {input: []byte{doVerb}}, {input: []byte{echo}},
				{input: []byte{iac}}, {input: []byte{doVerb}}, {input: []byte{sga}, ended: true},
			}},
			{name: "a second DO ECHO is no answer", steps: []step{{input: request(doVerb, echo)}, {input: request(doVerb, echo)}, {input: request(doVerb, sga), ended: true}}},
			{name: "DO ECHO in NO is no answer", steps: []step{{input: request(dont, echo)}, {input: request(doVerb, echo), want: request(will, echo)}, {input: request(doVerb, sga), ended: true}}},
			one("WILL and WONT are no answers", join(request(will, echo), request(will, sga), request(wont, echo), request(wont, sga)), join(request(dont, echo), request(dont, sga)), false),
			one("answers, then data in the same call", join(answers, []byte("x")), nil, true),
		}},
		{line: "After the byte that completes the caller's second answer, Receive shall append no reply and change no state, for the rest of that input and every later call.", cases: []receiveCase{
			{name: "requests after the end, in that call and later", steps: []step{
				{input: join(answers, request(doVerb, telnetTypeOption), request(will, windowSizeOption), request(dont, echo)), ended: true},
				{input: request(doVerb, telnetTypeOption), ended: true},
				{input: request(dont, echo), ended: true},
				{input: request(dont, sga), ended: true},
				{input: request(will, echo), ended: true},
			}},
			{name: "a request begun after the end and finished later", steps: []step{
				{input: join(answers, []byte{iac, doVerb}), ended: true},
				{input: []byte{telnetTypeOption}, ended: true},
			}},
		}},
		{line: "After it has returned true, Receive shall return true on every later call.", cases: []receiveCase{
			{name: "empty, data, a lone IAC, a request", steps: []step{
				{input: answers, ended: true},
				{input: nil, ended: true},
				{input: []byte("data"), ended: true},
				{input: []byte{iac}, ended: true},
				{input: request(doVerb, telnetTypeOption), ended: true},
				{input: []byte{}, ended: true},
			}},
		}},
		{line: "Receive shall append at most one reply per option request.", cases: []receiveCase{
			one("DO 24 ten times: ten WONT 24", repeated(request(doVerb, telnetTypeOption), 10), repeated(request(wont, telnetTypeOption), 10), false),
			one("WILL ECHO four times: four DONT ECHO", repeated(request(will, echo), 4), repeated(request(dont, echo), 4), false),
			one("DO ECHO three times: no reply", repeated(request(doVerb, echo), 3), nil, false),
			one("DONT ECHO, DO ECHO: one WILL ECHO", join(request(dont, echo), request(doVerb, echo)), request(will, echo), false),
		}},
		{line: "Receive shall append at most the length of input plus 2 bytes to replies in one call.", cases: []receiveCase{
			{name: "IAC DO, then 24 alone: 3 bytes for 1", steps: []step{{input: []byte{iac, doVerb}}, {input: []byte{telnetTypeOption}, want: request(wont, telnetTypeOption)}}},
			{name: "IAC, DO, 24 in three calls", steps: []step{{input: []byte{iac}}, {input: []byte{doVerb}}, {input: []byte{telnetTypeOption}, want: request(wont, telnetTypeOption)}}},
		}},
		{line: "Receive shall append, over all its calls on one negotiation, no more bytes than all their input held.", cases: []receiveCase{
			{name: "requests split a byte at a time", steps: stepsFor([]byte{iac}, []byte{doVerb}, []byte{telnetTypeOption}, []byte{iac, will}, []byte{windowSizeOption})},
			one("a hundred refusals", repeated(join(request(doVerb, telnetTypeOption), request(will, windowSizeOption)), 50), repeated(join(request(wont, telnetTypeOption), request(dont, windowSizeOption)), 50), false),
		}},
		{line: "If input is empty, then Receive shall append nothing and return what it returned on the call before, or false on the first call.", cases: []receiveCase{
			{name: "empty on the first call", steps: []step{{input: []byte{}}}},
			{name: "nil on the first call", steps: []step{{input: nil}}},
			{name: "empty after a request", steps: []step{{input: request(doVerb, telnetTypeOption), want: request(wont, telnetTypeOption)}, {input: nil}}},
			{name: "empty between halves of a request", steps: []step{{input: []byte{iac, doVerb}}, {input: nil}, {input: []byte{telnetTypeOption}, want: request(wont, telnetTypeOption)}}},
			{name: "empty after the end", steps: []step{{input: answers, ended: true}, {input: nil, ended: true}}},
		}},
		stateLine("While negotiation lasts, when the caller sends DO for ECHO or SGA while that Telnet option is in WANTYES, Receive shall move it to YES and append no reply.", "WANTYES DO"),
		stateLine("While negotiation lasts, when the caller sends DONT for ECHO or SGA while that Telnet option is in WANTYES, Receive shall move it to NO and append no reply.", "WANTYES DONT"),
		stateLine("While negotiation lasts, when the caller sends DO for ECHO or SGA while that Telnet option is in YES, Receive shall append no reply and leave its state unchanged.", "YES DO"),
		stateLine("While negotiation lasts, when the caller sends DONT for ECHO or SGA while that Telnet option is in YES, Receive shall move it to NO and append IAC WONT and that Telnet option.", "YES DONT"),
		stateLine("While negotiation lasts, when the caller sends DO for ECHO or SGA while that Telnet option is in NO, Receive shall move it to YES and append IAC WILL and that Telnet option.", "NO DO"),
		stateLine("While negotiation lasts, when the caller sends DONT for ECHO or SGA while that Telnet option is in NO, Receive shall append no reply and leave its state unchanged.", "NO DONT"),
		{line: "While negotiation lasts, when the caller sends WILL for any Telnet option, Receive shall append IAC DONT and that Telnet option.",
			cases: everyOption(will, func(option byte) []byte { return request(dont, option) }, noneSkipped)},
		{line: "While negotiation lasts, when the caller sends WONT for any Telnet option, Receive shall append no reply.",
			cases: everyOption(wont, func(byte) []byte { return nil }, noneSkipped)},
		{line: "While negotiation lasts, when the caller sends DO for a Telnet option other than ECHO and SGA, Receive shall append IAC WONT and that Telnet option.",
			cases: everyOption(doVerb, func(option byte) []byte { return request(wont, option) }, isEchoOrSuppressGoAhead)},
		{line: "While negotiation lasts, when the caller sends DONT for a Telnet option other than ECHO and SGA, Receive shall append no reply.",
			cases: everyOption(dont, func(byte) []byte { return nil }, isEchoOrSuppressGoAhead)},
	}
}

func TestReceive(t *testing.T) {
	t.Parallel()
	for _, group := range receiveLines() {
		t.Run(group.line, func(t *testing.T) {
			t.Parallel()
			for _, row := range group.cases {
				t.Run(row.name, func(t *testing.T) {
					t.Parallel()
					runSteps(t, fresh(), row.steps)
				})
			}
		})
	}
}

func TestReceiveKeepsWhatRepliesHeld(t *testing.T) {
	t.Parallel()
	t.Run("Receive shall append its replies after the bytes already in replies and leave those bytes unchanged.", func(t *testing.T) {
		t.Parallel()
		rows := []struct {
			name    string
			replies []byte
		}{
			{name: "nil replies", replies: nil},
			{name: "three bytes, no spare room", replies: []byte("abc")},
			{name: "three bytes with spare room", replies: append(make([]byte, 0, 64), "abc"...)},
			{name: "a reply already there", replies: request(wont, 99)},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				before := bytes.Clone(row.replies)
				got, ended := receive(t, fresh(), request(doVerb, telnetTypeOption), row.replies)
				want := join(before, request(wont, telnetTypeOption))
				if !bytes.Equal(got, want) || ended {
					t.Fatalf("got % x %v, want % x false", got, ended, want)
				}
				if !bytes.Equal(row.replies, before) {
					t.Fatalf("the caller's slice changed from % x to % x", before, row.replies)
				}
			})
		}
	})
}

func TestReceiveNeverFails(t *testing.T) {
	t.Parallel()
	t.Run("Receive shall return for every input without failing or panicking.", func(t *testing.T) {
		t.Parallel()
		t.Run("every single byte, on a fresh negotiation", func(t *testing.T) {
			t.Parallel()
			for code := range 256 {
				runSteps(t, fresh(), stepsFor([]byte{byte(code)}))
			}
		})
		t.Run("every pair of bytes, on a fresh negotiation", func(t *testing.T) {
			t.Parallel()
			for first := range 256 {
				for second := range 256 {
					runSteps(t, fresh(), stepsFor([]byte{byte(first), byte(second)}))
				}
			}
		})
		t.Run("every pair of bytes inside a subnegotiation", func(t *testing.T) {
			t.Parallel()
			for first := range 256 {
				for second := range 256 {
					runSteps(t, fresh(), stepsFor([]byte{iac, subnegotiationBegin}, []byte{byte(first), byte(second)}, answers))
				}
			}
		})
		t.Run("a lone IAC at the end of each call", func(t *testing.T) {
			t.Parallel()
			runSteps(t, fresh(), stepsFor([]byte{iac}, []byte{iac}, []byte{iac}, []byte{doVerb}, []byte{iac}, []byte{subnegotiationBegin, iac}))
		})
	})
}

func TestNew(t *testing.T) {
	t.Parallel()
	t.Run("New shall return the opening requests as the six bytes IAC WILL ECHO IAC WILL SGA, in that order.", func(t *testing.T) {
		t.Parallel()
		_, requests := telnet.New()
		if !bytes.Equal(requests[:], opening) {
			t.Fatalf("New's opening requests are % x, want % x", requests, opening)
		}
	})
	t.Run("New shall return a negotiation with ECHO and SGA both in the WANTYES state.", func(t *testing.T) {
		t.Parallel()
		// Only WANTYES answers both DO and DONT with no reply: YES answers DONT with WONT and NO
		// answers DO with WILL.
		for _, option := range []byte{echo, sga} {
			for _, verb := range []byte{doVerb, dont} {
				t.Run(fmt.Sprintf("verb %d for option %d gets no reply", verb, option), func(t *testing.T) {
					t.Parallel()
					runSteps(t, fresh(), []step{{input: request(verb, option)}})
				})
			}
		}
		t.Run("both answered ends negotiation", func(t *testing.T) {
			t.Parallel()
			runSteps(t, fresh(), []step{{input: join(request(dont, echo), request(doVerb, sga)), ended: true}})
		})
	})
	t.Run("New shall return a negotiation that shares no state with any other negotiation.", func(t *testing.T) {
		t.Parallel()
		rows := []struct {
			name         string
			first        []byte
			second       []byte
			secondWant   []byte
			secondEnded  bool
			firstEnded   bool
			firstReplies []byte
		}{
			{name: "ECHO moved to NO on one stays WANTYES on the other", first: request(dont, echo), second: request(doVerb, echo)},
			{name: "one ended, the other not", first: answers, firstEnded: true, second: nil},
			{name: "half a request on one is not carried to the other", first: []byte{iac, doVerb}, second: []byte{telnetTypeOption}},
			{name: "a subnegotiation on one does not swallow the other's request", first: []byte{iac, subnegotiationBegin}, second: request(doVerb, telnetTypeOption), secondWant: request(wont, telnetTypeOption)},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				first, second := fresh(), fresh()
				got, ended := receive(t, first, row.first, nil)
				if !bytes.Equal(got, row.firstReplies) || ended != row.firstEnded {
					t.Fatalf("the first negotiation gave % x %v", got, ended)
				}
				got, ended = receive(t, second, row.second, nil)
				if !bytes.Equal(got, row.secondWant) || ended != row.secondEnded {
					t.Fatalf("the second negotiation gave % x %v, want % x %v", got, ended, row.secondWant, row.secondEnded)
				}
				got, _ = receive(t, second, probe, nil)
				if !bytes.Equal(got, request(wont, telnetTypeOption)) {
					t.Fatalf("the second negotiation answered the probe with % x", got)
				}
			})
		}
	})
	t.Run("A Negotiation not made by New shall behave as one New returned, with ECHO and SGA both in the WANTYES state.", func(t *testing.T) {
		t.Parallel()
		makers := map[string]func() *telnet.Negotiation{
			"a composite literal": func() *telnet.Negotiation { return &telnet.Negotiation{} },
			"new":                 func() *telnet.Negotiation { return new(telnet.Negotiation) },
		}
		for makerName, maker := range makers {
			for _, group := range receiveLines() {
				for _, row := range group.cases {
					t.Run(makerName+": "+group.line[:40]+": "+row.name, func(t *testing.T) {
						t.Parallel()
						runSteps(t, maker(), row.steps)
					})
				}
			}
			t.Run(makerName+": both answered ends negotiation", func(t *testing.T) {
				t.Parallel()
				runSteps(t, maker(), []step{{input: answers, ended: true}})
			})
		}
	})
}
