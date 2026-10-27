// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests of New, Receive and TakeSynch: how every byte a caller sends during negotiation is read,
// the reply to every option request on both sides, the SENDs, AYT, the Synchs AO and IP owe,
// and the end of negotiation at the eighth answer, with RFC 854's command list and RFC 1143
// section 7's tables as the vectors.
package telnet_test

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/telnet"
)

// step is one call of Receive: its input, the bytes it must append, the Synchs it must owe and
// what it must return.
type step struct {
	input  []byte
	want   []byte
	synchs int
	ended  bool
	// probe marks the closing request runSteps adds, whose expectation is the test's own reading.
	probe bool
}

// probe ends a subnegotiation if one is open, and is a two-byte command if not, then sends WILL
// SGA, which the engine answers DO while the caller's SGA is in NO, and asks for an option the
// engine refuses: whatever state a row leaves, a reading that kept up answers it, and one still
// on Part 1's table answers WILL SGA with DONT.
var probe = join(command(subnegotiationEnd), command(subnegotiationEnd), request(will, sga), request(doVerb, telnetTypeOption))

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

// The eight answers split where Part 1's table would already have ended: ECHO and SGA first,
// then the other six, so a row that ends negotiation is told from one that ends it at the
// second.
var (
	firstAnswers = answers[:6]
	restAnswers  = answers[6:]
)

// ending is the steps that end negotiation after the bytes given: those bytes and the first two
// answers, which must not end it, then the other six, which must.
func ending(before []byte) []step {
	return stepsFor(join(before, firstAnswers), restAnswers)
}

// runSteps makes the calls of one row on negotiation and checks each: the bytes it appends, the
// Synchs TakeSynch then returns, what it returns, that the bytes already in replies stay, and the
// contract's bounds on how much it appends. Each row is also read by the test's own reading, so a
// row that disagrees with RFC 1143 is a fault in the test, reported as one. Every row ends with a
// probe, requests the reading must reach and answer, unless negotiation has ended: so a row whose
// own calls rightly get no reply still shows the bytes before it were read as the line says, and
// are not merely ignored.
func runSteps(t *testing.T, negotiation *telnet.Negotiation, steps []step) {
	t.Helper()
	oracle := freshReading()
	prior := []byte("prior")
	totalInput, totalAppended := 0, 0
	steps = append(slices.Clone(steps), step{input: probe, probe: true})
	for index, call := range steps {
		synchsBefore := oracle.synchs
		wantByOracle, endedByOracle := oracle.readAll(call.input)
		synchsByOracle := oracle.synchs - synchsBefore
		if call.probe {
			call.want, call.ended, call.synchs = wantByOracle, endedByOracle, synchsByOracle
		}
		if !bytes.Equal(wantByOracle, call.want) || endedByOracle != call.ended || synchsByOracle != call.synchs {
			t.Fatalf("test fault: call %d's row disagrees with the test's own reading of RFC 1143: % x, %d Synchs, %v", index, wantByOracle, synchsByOracle, endedByOracle)
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
		if synchs := negotiation.TakeSynch(); synchs != call.synchs {
			t.Fatalf("after call %d of % x TakeSynch returned %d, want %d", index, call.input, synchs, call.synchs)
		}
		if ended != call.ended {
			t.Fatalf("call %d of % x returned %v, want %v", index, call.input, ended, call.ended)
		}
		if len(appended) > 5*len(call.input)+mostOneReply {
			t.Fatalf("call %d appended %d bytes for %d of input", index, len(appended), len(call.input))
		}
		totalInput += len(call.input)
		totalAppended += len(appended)
		if totalAppended > 5*totalInput {
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

// stepsFor reads the calls with the test's own reading to give each call's expectation.
func stepsFor(calls ...[]byte) []step {
	oracle := freshReading()
	var steps []step
	for _, input := range calls {
		before := oracle.synchs
		want, ended := oracle.readAll(input)
		steps = append(steps, step{input: input, want: want, ended: ended, synchs: oracle.synchs - before})
	}
	return steps
}

// oneRead is a row of a single call whose expectation is the test's own reading.
func oneRead(name string, input []byte) receiveCase {
	return receiveCase{name: name, steps: stepsFor(input)}
}

func isOn(side []byte) func(byte) bool {
	return func(option byte) bool { return slices.Contains(side, option) }
}

// everyOption is one row per option code not skipped, for the tables that hold for any Telnet
// option, each followed by the probe.
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

// sendOf is the SEND that follows the caller's side of an option moving to YES, if it has one.
func sendOf(option byte) []byte {
	switch option {
	case telnetTypeOption:
		return terminalTypeSend
	case speedOption:
		return speedSend
	case environOption:
		return environSend
	}
	return nil
}

// optionName names an option in a row's name.
func optionName(option byte) string {
	return map[byte]string{binary: "BINARY", echo: "ECHO", sga: "SGA", telnetTypeOption: "TTYPE",
		windowSizeOption: "NAWS", speedOption: "TSPEED", environOption: "NEW-ENVIRON"}[option]
}

// engineRows is RFC 1143 section 7's table for the engine's side, one row per entry and per
// option, each reached while other options are still in WANTYES so negotiation lasts, and each
// followed by a request whose reply shows the state the entry left.
func engineRows() []receiveCase {
	var cases []receiveCase
	for _, option := range engineSide {
		name := optionName(option)
		cases = append(cases,
			receiveCase{name: name + ": WANTYES DO: no reply, then DONT gets WONT, so YES", steps: []step{
				{input: request(doVerb, option)},
				{input: request(dont, option), want: request(wont, option)},
			}},
			receiveCase{name: name + ": WANTYES DONT: no reply, then DO gets WILL, so NO", steps: []step{
				{input: request(dont, option)},
				{input: request(doVerb, option), want: request(will, option)},
			}},
			receiveCase{name: name + ": YES DO: no reply, then DONT still gets WONT", steps: []step{
				{input: request(doVerb, option)},
				{input: request(doVerb, option)},
				{input: request(dont, option), want: request(wont, option)},
			}},
			receiveCase{name: name + ": YES DONT: WONT, then DO gets WILL, so NO", steps: []step{
				{input: request(doVerb, option)},
				{input: request(dont, option), want: request(wont, option)},
				{input: request(doVerb, option), want: request(will, option)},
			}},
			receiveCase{name: name + ": NO DO: WILL, then DONT gets WONT, so YES", steps: []step{
				{input: request(dont, option)},
				{input: request(doVerb, option), want: request(will, option)},
				{input: request(dont, option), want: request(wont, option)},
			}},
			receiveCase{name: name + ": NO DONT: no reply, then DO still gets WILL", steps: []step{
				{input: request(dont, option)},
				{input: request(dont, option)},
				{input: request(doVerb, option), want: request(will, option)},
			}},
		)
	}
	return cases
}

// callerRows is RFC 1143 section 7's table for the caller's side, the same way, with the SEND
// where an option with one moves to YES for the first time. SGA starts in NO, so its WANTYES
// entries are reached from nothing it can be sent.
func callerRows() []receiveCase {
	var cases []receiveCase
	for _, option := range callerSide {
		name := optionName(option)
		send := sendOf(option)
		if option == sga {
			cases = append(cases,
				receiveCase{name: "SGA: NO WILL: DO, then WONT gets DONT, so YES", steps: []step{
					{input: request(will, option), want: request(doVerb, option)},
					{input: request(wont, option), want: request(dont, option)},
				}},
				receiveCase{name: "SGA: NO WONT: no reply, then WILL still gets DO", steps: []step{
					{input: request(wont, option)},
					{input: request(will, option), want: request(doVerb, option)},
				}},
				receiveCase{name: "SGA: YES WILL: no reply, then WONT still gets DONT", steps: []step{
					{input: request(will, option), want: request(doVerb, option)},
					{input: request(will, option)},
					{input: request(wont, option), want: request(dont, option)},
				}},
				receiveCase{name: "SGA: YES WONT: DONT, then WILL gets DO, so NO", steps: []step{
					{input: request(will, option), want: request(doVerb, option)},
					{input: request(wont, option), want: request(dont, option)},
					{input: request(will, option), want: request(doVerb, option)},
				}},
			)
			continue
		}
		cases = append(cases,
			receiveCase{name: name + ": WANTYES WILL: no reply but its SEND, then WONT gets DONT, so YES", steps: []step{
				{input: request(will, option), want: send},
				{input: request(wont, option), want: request(dont, option)},
			}},
			receiveCase{name: name + ": WANTYES WONT: no reply, then WILL gets DO and its SEND, so NO", steps: []step{
				{input: request(wont, option)},
				{input: request(will, option), want: join(request(doVerb, option), send)},
			}},
			receiveCase{name: name + ": YES WILL: no reply, then WONT still gets DONT", steps: []step{
				{input: request(will, option), want: send},
				{input: request(will, option)},
				{input: request(wont, option), want: request(dont, option)},
			}},
			receiveCase{name: name + ": YES WONT: DONT, then WILL gets DO and no second SEND, so NO", steps: []step{
				{input: request(will, option), want: send},
				{input: request(wont, option), want: request(dont, option)},
				{input: request(will, option), want: request(doVerb, option)},
			}},
			receiveCase{name: name + ": NO WILL: DO and its SEND, then WONT gets DONT, so YES", steps: []step{
				{input: request(wont, option)},
				{input: request(will, option), want: join(request(doVerb, option), send)},
				{input: request(wont, option), want: request(dont, option)},
			}},
			receiveCase{name: name + ": NO WONT: no reply, then WILL still gets DO", steps: []step{
				{input: request(wont, option)},
				{input: request(wont, option)},
				{input: request(will, option), want: join(request(doVerb, option), send)},
			}},
		)
	}
	return cases
}

// splitRows gives, for each input, every split into two calls and the split into single bytes,
// each call's expected replies and Synchs taken from the test's own reading.
func splitRows() []receiveCase {
	inputs := map[string][]byte{
		"the eight answers, WILL SGA among them": join(firstAnswers, request(will, sga), restAnswers),
		"a refusal, then the answers":            join(request(doVerb, telnetTypeOption), request(will, 25), firstAnswers, request(will, sga), restAnswers),
		"a subnegotiation and the answers":       join([]byte{iac, subnegotiationBegin, telnetTypeOption, iac, iac, subnegotiationEnd, 1, iac, subnegotiationEnd}, firstAnswers, request(will, sga), restAnswers),
		"data 255, then a refusal":               join(command(iac), request(doVerb, telnetTypeOption)),
		"bytes after the end":                    join(firstAnswers, request(will, sga), restAnswers, request(doVerb, telnetTypeOption), command(ayt), command(abortOutput)),
		"ECHO through NO and back":               join(request(dont, echo), request(doVerb, echo), request(dont, echo), firstAnswers[3:]),
		"commands and a refusal":                 join(command(nop), command(ayt), request(doVerb, telnetTypeOption), []byte("text")),
		"AO and IP among the answers":            join(command(abortOutput), firstAnswers, command(interruptProcess), command(abortOutput), restAnswers),
		"WILL TTYPE, WILL NEW-ENVIRON last":      join(firstAnswers, request(doVerb, binary), request(will, binary), request(wont, windowSizeOption), request(wont, speedOption), request(will, telnetTypeOption), request(will, environOption)),
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

func receiveLines() []receiveLine {
	var otherCommands []receiveCase
	for _, code := range []byte{subnegotiationEnd, nop, dataMark, breakCommand, eraseCharacter, eraseLine, goAhead, endOfRecord, 0, 1, 24, 100} {
		otherCommands = append(otherCommands, oneRead(fmt.Sprintf("IAC %d, then WILL SGA and a refusal", code),
			join(command(code), request(will, sga), request(doVerb, telnetTypeOption))))
	}
	var everyDataByte []byte
	for code := range 255 {
		everyDataByte = append(everyDataByte, byte(code))
	}
	insideSubnegotiation := func(name string, inside []byte) receiveCase {
		return receiveCase{name: name, steps: []step{
			{input: join([]byte{iac, subnegotiationBegin, telnetTypeOption}, inside, command(subnegotiationEnd))},
			{input: request(will, sga), want: request(doVerb, sga)},
		}}
	}
	return []receiveLine{
		{line: "When input holds IAC, then WILL, WONT, DO or DONT, then one more byte, Receive shall read those three bytes as one option request.", cases: []receiveCase{
			one("WILL 25 gets DONT 25", request(will, 25), request(dont, 25), false),
			one("DO 24 gets WONT 24", request(doVerb, telnetTypeOption), request(wont, telnetTypeOption), false),
			one("DO 2 gets WONT 2", request(doVerb, 2), request(wont, 2), false),
			one("DO 255 gets WONT 255, and the 255 starts nothing", join(request(doVerb, 255), request(doVerb, telnetTypeOption)), join(request(wont, 255), request(wont, telnetTypeOption)), false),
			one("DO 250 gets WONT 250 and starts no subnegotiation", join(request(doVerb, subnegotiationBegin), request(doVerb, telnetTypeOption)), join(request(wont, subnegotiationBegin), request(wont, telnetTypeOption)), false),
			one("WILL 240 gets DONT 240", request(will, subnegotiationEnd), request(dont, subnegotiationEnd), false),
			one("WILL 246 gets DONT 246, no AYT answer", request(will, ayt), request(dont, ayt), false),
			one("WONT 25 then DONT 26 then DO 27: only WONT 27", join(request(wont, 25), request(dont, 26), request(doVerb, 27)), request(wont, 27), false),
		}},
		{line: "When input holds IAC IAC outside a subnegotiation, Receive shall discard both bytes without reply.", cases: []receiveCase{
			one("IAC IAC", command(iac), nil, false),
			one("IAC IAC DO 24 is data", []byte{iac, iac, doVerb, telnetTypeOption}, nil, false),
			one("IAC IAC AYT is data", []byte{iac, iac, ayt}, nil, false),
			one("IAC IAC, then a request", join(command(iac), request(doVerb, telnetTypeOption)), request(wont, telnetTypeOption), false),
			{name: "IAC IAC four times, then the answers", steps: ending(repeated(command(iac), 4))},
		}},
		{line: "When input holds IAC SB, Receive shall discard every byte up to and including the next IAC SE without reply.", cases: []receiveCase{
			one("a subnegotiation, then a request", join([]byte{iac, subnegotiationBegin, telnetTypeOption, 1, iac, subnegotiationEnd}, request(doVerb, 25)), request(wont, 25), false),
			one("a request inside is discarded", join([]byte{iac, subnegotiationBegin, telnetTypeOption}, request(doVerb, telnetTypeOption), command(subnegotiationEnd), request(doVerb, 25)), request(wont, 25), false),
			one("SE without IAC does not end it", join([]byte{iac, subnegotiationBegin, telnetTypeOption, subnegotiationEnd}, request(doVerb, telnetTypeOption), command(subnegotiationEnd), request(doVerb, 25)), request(wont, 25), false),
			{name: "answers inside do not end negotiation", steps: append([]step{
				{input: join([]byte{iac, subnegotiationBegin, telnetTypeOption}, answers, command(subnegotiationEnd))},
			}, ending(nil)...)},
			one("a subnegotiation that never ends swallows every request", join([]byte{iac, subnegotiationBegin, telnetTypeOption}, repeated(request(doVerb, telnetTypeOption), 300), answers, command(ayt), command(abortOutput)), nil, false),
		}},
		{line: "While it is inside a subnegotiation, Receive shall read IAC IAC as one data byte, so that IAC IAC SE does not end the subnegotiation.", cases: []receiveCase{
			one("IAC IAC SE inside, then IAC SE", join([]byte{iac, subnegotiationBegin, telnetTypeOption, iac, iac, subnegotiationEnd}, request(doVerb, 25), command(subnegotiationEnd), request(doVerb, 26)), request(wont, 26), false),
			one("IAC IAC then IAC SE", join([]byte{iac, subnegotiationBegin, iac, iac, iac, subnegotiationEnd}, request(doVerb, 26)), request(wont, 26), false),
			one("NAWS of 65535 by 65535, each 255 doubled", join([]byte{iac, subnegotiationBegin, windowSizeOption}, repeated(command(iac), 4), command(subnegotiationEnd), request(doVerb, 26)), request(wont, 26), false),
		}},
		{line: "When input holds IAC AYT, Receive shall append AYTAnswer.", cases: []receiveCase{
			one("AYT alone", command(ayt), []byte(aytAnswerBytes), false),
			one("AYT twice, and a refusal between", join(command(ayt), request(doVerb, 25), command(ayt)), join([]byte(aytAnswerBytes), request(wont, 25), []byte(aytAnswerBytes)), false),
			{name: "IAC, then AYT in the next call", steps: []step{{input: []byte{iac}}, {input: []byte{ayt}, want: []byte(aytAnswerBytes)}}},
			{name: "AYT among the answers, before the eighth", steps: stepsFor(join(firstAnswers, command(ayt)), restAnswers)},
		}},
		{line: "When input holds IAC AO or IAC IP, Receive shall owe a Synch, appending no reply.", cases: []receiveCase{
			{name: "AO", steps: []step{{input: command(abortOutput), synchs: 1}}},
			{name: "IP", steps: []step{{input: command(interruptProcess), synchs: 1}}},
			{name: "AO, IP, AO in one call: three", steps: []step{{input: join(command(abortOutput), command(interruptProcess), command(abortOutput)), synchs: 3}}},
			{name: "AO, a refusal, IP: two, and the refusal's reply", steps: []step{{input: join(command(abortOutput), request(doVerb, 25), command(interruptProcess)), want: request(wont, 25), synchs: 2}}},
			{name: "IAC, then IP in the next call", steps: []step{{input: []byte{iac}}, {input: []byte{interruptProcess}, synchs: 1}}},
			{name: "AO among the answers, before the eighth", steps: stepsFor(join(firstAnswers, command(abortOutput)), restAnswers)},
		}},
		{line: "When input holds IAC and then a byte other than WILL, WONT, DO, DONT, SB, IAC, AYT, AO or IP, Receive shall discard both bytes without reply.", cases: otherCommands},
		{line: "When input holds a byte that is not part of a sequence starting with IAC, Receive shall discard it without reply.", cases: []receiveCase{
			one("every byte but IAC", everyDataByte, nil, false),
			one("the answers without IAC", []byte{doVerb, echo, doVerb, sga, doVerb, binary, will, binary}, nil, false),
			one("text, then a request", join([]byte("hello\r\n"), request(doVerb, telnetTypeOption)), request(wont, telnetTypeOption), false),
		}},
		{line: "When a sequence is split across calls, Receive shall reply to it, owe a Synch and end negotiation as it would had the sequence come in one call.", cases: splitRows()},
		{line: "When the byte that completes the caller's last answer to the eight opening requests arrives, Receive shall return true.", cases: []receiveCase{
			{name: "the eight in two calls, ECHO and SGA first", steps: ending(nil)},
			{name: "the eight with ECHO and SGA last", steps: stepsFor(restAnswers, firstAnswers[3:], firstAnswers[:3])},
			{name: "every one refused", steps: stepsFor(join(request(dont, echo), request(dont, sga)),
				join(request(dont, binary), request(wont, binary), request(wont, telnetTypeOption), request(wont, windowSizeOption), request(wont, environOption), request(wont, speedOption)))},
			{name: "every one agreed, the SENDs with them", steps: stepsFor(firstAnswers,
				join(request(doVerb, binary), request(will, binary), request(will, telnetTypeOption), request(will, windowSizeOption), request(will, environOption), request(will, speedOption)))},
			{name: "a byte at a time: true on the 24th byte only", steps: func() []step {
				var calls [][]byte
				for index := range answers {
					calls = append(calls, answers[index:index+1])
				}
				return stepsFor(calls...)
			}()},
			{name: "seven answers do not end it", steps: stepsFor(answers[:21])},
			{name: "a second DO ECHO is no answer", steps: stepsFor(join(firstAnswers, request(doVerb, echo)), answers[6:21], answers[21:])},
			{name: "DO ECHO in NO is no answer", steps: stepsFor(join(request(dont, echo), request(doVerb, echo), firstAnswers[3:]), restAnswers)},
			{name: "WILL SGA is no answer", steps: stepsFor(join(firstAnswers, request(will, sga)), restAnswers)},
			{name: "the eighth answer, then data in the same call", steps: stepsFor(firstAnswers, join(restAnswers, []byte("x")))},
		}},
		{line: "After the byte that completes the caller's last answer, Receive shall append no reply, owe no Synch and change no state, for the rest of that input and every later call.", cases: []receiveCase{
			{name: "requests, AYT and AO after the end, in that call and later", steps: []step{
				{input: firstAnswers},
				{input: join(restAnswers, request(doVerb, telnetTypeOption), request(will, 25), request(dont, echo), command(ayt), command(abortOutput)), ended: true},
				{input: request(doVerb, telnetTypeOption), ended: true},
				{input: request(dont, echo), ended: true},
				{input: join(command(interruptProcess), command(ayt)), ended: true},
				{input: request(will, telnetTypeOption), ended: true},
			}},
			{name: "a request begun after the end and finished later", steps: []step{
				{input: firstAnswers},
				{input: join(restAnswers, []byte{iac, doVerb}), ended: true},
				{input: []byte{telnetTypeOption}, ended: true},
			}},
		}},
		{line: "After it has returned true, Receive shall return true on every later call.", cases: []receiveCase{
			{name: "empty, data, a lone IAC, a request", steps: []step{
				{input: firstAnswers},
				{input: restAnswers, ended: true},
				{input: nil, ended: true},
				{input: []byte("data"), ended: true},
				{input: []byte{iac}, ended: true},
				{input: request(doVerb, telnetTypeOption), ended: true},
				{input: []byte{}, ended: true},
			}},
		}},
		{line: "Receive shall append at most one reply per option request, and after it at most one SEND.", cases: []receiveCase{
			one("DO 24 ten times: ten WONT 24", repeated(request(doVerb, telnetTypeOption), 10), repeated(request(wont, telnetTypeOption), 10), false),
			one("WILL ECHO four times: four DONT ECHO", repeated(request(will, echo), 4), repeated(request(dont, echo), 4), false),
			one("DO ECHO three times: no reply", repeated(request(doVerb, echo), 3), nil, false),
			one("WILL TTYPE three times: one SEND", repeated(request(will, telnetTypeOption), 3), terminalTypeSend, false),
			oneRead("WONT, WILL, WONT, WILL, WILL NEW-ENVIRON: DO and one SEND, DONT, DO", join(request(wont, environOption), request(will, environOption), request(wont, environOption), request(will, environOption), request(will, environOption))),
			oneRead("WILL TSPEED, then WONT and WILL again in a later call: no second SEND", join(request(will, speedOption), request(wont, speedOption))),
		}},
		{line: "Receive shall append at most five times the length of input plus MostReply bytes to replies in one call.", cases: []receiveCase{
			{name: "WILL NEW-ENVIRON after WONT, its last byte alone: 14 bytes for 1", steps: stepsFor(request(wont, environOption), []byte{iac, will}, []byte{environOption})},
			{name: "AYT, its last byte alone: 9 bytes for 1", steps: stepsFor([]byte{iac}, []byte{ayt})},
			oneRead("a thousand AYTs in one call", repeated(command(ayt), 1000)),
		}},
		{line: "Receive shall append, over all its calls on one negotiation, no more bytes than five times all their input held.", cases: []receiveCase{
			{name: "AYTs a byte at a time", steps: stepsFor([]byte{iac}, []byte{ayt}, []byte{iac}, []byte{ayt}, []byte{iac}, []byte{ayt})},
			oneRead("NEW-ENVIRON, TTYPE and TSPEED each refused and agreed, then toggled", join(request(wont, environOption), request(will, environOption), request(wont, telnetTypeOption), request(will, telnetTypeOption), request(wont, speedOption), request(will, speedOption), repeated(join(request(wont, environOption), request(will, environOption)), 50))),
			oneRead("a hundred refusals", repeated(join(request(doVerb, telnetTypeOption), request(will, 25)), 50)),
		}},
		{line: "If input is empty, then Receive shall append nothing and return what it returned on the call before, or false on the first call.", cases: []receiveCase{
			{name: "empty on the first call", steps: []step{{input: []byte{}}}},
			{name: "nil on the first call", steps: []step{{input: nil}}},
			{name: "empty after a request", steps: []step{{input: request(doVerb, telnetTypeOption), want: request(wont, telnetTypeOption)}, {input: nil}}},
			{name: "empty between halves of a request", steps: []step{{input: []byte{iac, doVerb}}, {input: nil}, {input: []byte{telnetTypeOption}, want: request(wont, telnetTypeOption)}}},
			{name: "empty after the end", steps: append(ending(nil), step{input: nil, ended: true})},
		}},
		{line: "While negotiation lasts, Receive shall answer each option request about ECHO, SGA or BINARY on the engine's side by the first table above, moving its state and appending the reply that table gives.", cases: engineRows()},
		{line: "While negotiation lasts, Receive shall answer each option request about SGA, BINARY, TTYPE, NAWS, NEW-ENVIRON or TSPEED on the caller's side by the second table above, moving its state and appending the reply that table gives.", cases: callerRows()},
		{line: "When the caller's side of TTYPE or TSPEED moves to YES and that option's SEND has not been appended on this negotiation, Receive shall append that SEND after any reply.", cases: []receiveCase{
			one("WILL TTYPE from WANTYES: the SEND alone", request(will, telnetTypeOption), terminalTypeSend, false),
			one("WILL TSPEED from WANTYES: the SEND alone", request(will, speedOption), speedSend, false),
			{name: "WONT then WILL TTYPE: DO, then the SEND", steps: []step{{input: request(wont, telnetTypeOption)}, {input: request(will, telnetTypeOption), want: join(request(doVerb, telnetTypeOption), terminalTypeSend)}}},
			{name: "WONT then WILL TSPEED: DO, then the SEND", steps: []step{{input: request(wont, speedOption)}, {input: request(will, speedOption), want: join(request(doVerb, speedOption), speedSend)}}},
			{name: "TTYPE agreed, refused and agreed again: one SEND", steps: []step{
				{input: request(will, telnetTypeOption), want: terminalTypeSend},
				{input: request(wont, telnetTypeOption), want: request(dont, telnetTypeOption)},
				{input: request(will, telnetTypeOption), want: request(doVerb, telnetTypeOption)},
			}},
			{name: "WILL TTYPE as the eighth answer: the SEND with it", steps: stepsFor(answers[:12], join(answers[15:], request(will, telnetTypeOption)))},
		}},
		{line: "When the caller's side of NEW-ENVIRON moves to YES and its SEND has not been appended on this negotiation, Receive shall append the SEND for the variable USER alone after any reply.", cases: []receiveCase{
			one("WILL NEW-ENVIRON from WANTYES: SEND VAR USER alone", request(will, environOption), environSend, false),
			{name: "WONT then WILL NEW-ENVIRON: DO, then the SEND", steps: []step{{input: request(wont, environOption)}, {input: request(will, environOption), want: join(request(doVerb, environOption), environSend)}}},
			{name: "NEW-ENVIRON agreed, refused and agreed again: one SEND", steps: []step{
				{input: request(will, environOption), want: environSend},
				{input: request(wont, environOption), want: request(dont, environOption)},
				{input: request(will, environOption), want: request(doVerb, environOption)},
			}},
		}},
		{line: "While negotiation lasts, when the caller sends WILL for a Telnet option other than SGA, BINARY, TTYPE, NAWS, NEW-ENVIRON and TSPEED, Receive shall append IAC DONT and that Telnet option.",
			cases: everyOption(will, func(option byte) []byte { return request(dont, option) }, isOn(callerSide))},
		{line: "While negotiation lasts, when the caller sends DO for a Telnet option other than ECHO, SGA and BINARY, Receive shall append IAC WONT and that Telnet option.",
			cases: everyOption(doVerb, func(option byte) []byte { return request(wont, option) }, isOn(engineSide))},
		{line: "While negotiation lasts, when the caller sends WONT for a Telnet option other than SGA, BINARY, TTYPE, NAWS, NEW-ENVIRON and TSPEED, or DONT for one other than ECHO, SGA and BINARY, Receive shall append no reply and change no state.",
			cases: append(everyOption(wont, func(byte) []byte { return nil }, isOn(callerSide)),
				everyOption(dont, func(byte) []byte { return nil }, isOn(engineSide))...)},
		{line: "Receive shall let nothing inside a subnegotiation change a reply, a state or whether a Synch is owed.", cases: []receiveCase{
			insideSubnegotiation("the eight answers inside", answers),
			insideSubnegotiation("AYT, AO and IP inside", join(command(ayt), command(abortOutput), command(interruptProcess))),
			insideSubnegotiation("WILL TTYPE and WILL SGA inside", join(request(will, telnetTypeOption), request(will, sga))),
			insideSubnegotiation("DONT ECHO inside", request(dont, echo)),
			insideSubnegotiation("escape codes and text inside", []byte("\x1b[2J\x1b[31mred\r\n")),
			insideSubnegotiation("a long subnegotiation, 10000 bytes", repeated([]byte("abcdefghij"), 1000)),
			insideSubnegotiation("NAWS of 0 by 0", []byte{0, 0, 0, 0}),
			{name: "a subnegotiation for an option never agreed, then the answers", steps: append([]step{
				{input: join([]byte{iac, subnegotiationBegin, 99, 1, 2, 3}, command(subnegotiationEnd))},
			}, ending(nil)...)},
		}},
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
				input := join(request(doVerb, telnetTypeOption), request(will, environOption), command(ayt))
				got, ended := receive(t, fresh(), input, row.replies)
				want := join(before, request(wont, telnetTypeOption), environSend, []byte(aytAnswerBytes))
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

func TestTakeSynch(t *testing.T) {
	t.Parallel()
	t.Run("TakeSynch shall return the number of Synchs Receive's and Strip's lines have owed since the last TakeSynch, or since New.", func(t *testing.T) {
		t.Parallel()
		t.Run("none since New, then one after an AO", func(t *testing.T) {
			t.Parallel()
			negotiation := fresh()
			if got := negotiation.TakeSynch(); got != 0 {
				t.Fatalf("TakeSynch on a fresh negotiation returned %d", got)
			}
			receive(t, negotiation, command(abortOutput), nil)
			if got := negotiation.TakeSynch(); got != 1 {
				t.Fatalf("TakeSynch after an AO returned %d, want 1", got)
			}
		})
		t.Run("AO, IP and AO in Receive's calls, then AO twice in Strip's: three, then two", func(t *testing.T) {
			t.Parallel()
			negotiation := fresh()
			receive(t, negotiation, join(command(abortOutput), command(interruptProcess)), nil)
			receive(t, negotiation, join(request(doVerb, 25), command(abortOutput)), nil)
			if got := negotiation.TakeSynch(); got != 3 {
				t.Fatalf("TakeSynch after Receive's AO, IP and AO returned %d, want 3", got)
			}
			for _, value := range join(command(abortOutput), []byte("x"), command(abortOutput)) {
				stripOne(t, negotiation, value, nil)
			}
			if got := negotiation.TakeSynch(); got != 2 {
				t.Fatalf("TakeSynch after Strip's two AO returned %d, want 2", got)
			}
		})
		t.Run("a Negotiation not made by New: IP twice, two", func(t *testing.T) {
			t.Parallel()
			var negotiation telnet.Negotiation
			receive(t, &negotiation, join(command(interruptProcess), command(interruptProcess)), nil)
			if got := negotiation.TakeSynch(); got != 2 {
				t.Fatalf("TakeSynch returned %d, want 2", got)
			}
		})
	})
	t.Run("After it returns, TakeSynch shall return zero until Receive or Strip owes another.", func(t *testing.T) {
		t.Parallel()
		negotiation := fresh()
		receive(t, negotiation, command(abortOutput), nil)
		if got := negotiation.TakeSynch(); got != 1 {
			t.Fatalf("TakeSynch returned %d, want 1", got)
		}
		for range 3 {
			if got := negotiation.TakeSynch(); got != 0 {
				t.Fatalf("TakeSynch again returned %d, want 0", got)
			}
		}
		receive(t, negotiation, join(request(doVerb, 25), command(ayt)), nil)
		if got := negotiation.TakeSynch(); got != 0 {
			t.Fatalf("TakeSynch after a refusal and AYT returned %d, want 0", got)
		}
		receive(t, negotiation, command(interruptProcess), nil)
		if got := negotiation.TakeSynch(); got != 1 {
			t.Fatalf("TakeSynch after one more IP returned %d, want 1", got)
		}
	})
}

func TestNew(t *testing.T) {
	t.Parallel()
	t.Run("New shall return the opening requests as the 24 bytes IAC WILL ECHO, IAC WILL SGA, IAC WILL BINARY, IAC DO BINARY, IAC DO TTYPE, IAC DO NAWS, IAC DO NEW-ENVIRON and IAC DO TSPEED, in that order.", func(t *testing.T) {
		t.Parallel()
		_, requests := telnet.New()
		want := []byte{255, 251, 1, 255, 251, 3, 255, 251, 0, 255, 253, 0, 255, 253, 24, 255, 253, 31, 255, 253, 39, 255, 253, 32}
		if !bytes.Equal(requests[:], want) || !bytes.Equal(opening, want) {
			t.Fatalf("New's opening requests are % x, want % x", requests, want)
		}
	})
	t.Run("New shall return a negotiation with ECHO, SGA and BINARY on the engine's side and BINARY, TTYPE, NAWS, NEW-ENVIRON and TSPEED on the caller's side in the WANTYES state, SGA on the caller's side in the NO state, and no SEND sent.", func(t *testing.T) {
		t.Parallel()
		// Only WANTYES answers both verbs with no reply: YES answers the refusal and NO the
		// agreement. Each request here is read on a fresh negotiation, so the row shows the state
		// New left it in.
		for _, option := range engineSide {
			for _, verb := range []byte{doVerb, dont} {
				t.Run(fmt.Sprintf("the engine's %s: verb %d gets no reply", optionName(option), verb), func(t *testing.T) {
					t.Parallel()
					runSteps(t, fresh(), []step{{input: request(verb, option)}})
				})
			}
		}
		for _, option := range callerSide[1:] {
			for _, verb := range []byte{will, wont} {
				t.Run(fmt.Sprintf("the caller's %s: verb %d gets no reply, and WILL its SEND if it has one", optionName(option), verb), func(t *testing.T) {
					t.Parallel()
					want := []byte(nil)
					if verb == will {
						want = sendOf(option)
					}
					runSteps(t, fresh(), []step{{input: request(verb, option), want: want}})
				})
			}
		}
		t.Run("the caller's SGA: WILL gets DO, so NO", func(t *testing.T) {
			t.Parallel()
			runSteps(t, fresh(), []step{{input: request(will, sga), want: request(doVerb, sga)}})
		})
		t.Run("the caller's SGA: WONT gets no reply and answers nothing", func(t *testing.T) {
			t.Parallel()
			runSteps(t, fresh(), []step{{input: join(request(wont, sga), answers[:21])}, {input: answers[21:], ended: true}})
		})
		t.Run("all eight answered ends negotiation", func(t *testing.T) {
			t.Parallel()
			runSteps(t, fresh(), ending(nil))
		})
	})
	t.Run("New shall return a negotiation that shares no state with any other negotiation.", func(t *testing.T) {
		t.Parallel()
		rows := []struct {
			name        string
			first       []byte
			second      []byte
			secondWant  []byte
			secondEnded bool
		}{
			{name: "ECHO moved to NO on one stays WANTYES on the other", first: request(dont, echo), second: request(doVerb, echo)},
			{name: "one ended, the other not", first: answers, second: nil},
			{name: "half a request on one is not carried to the other", first: []byte{iac, doVerb}, second: []byte{telnetTypeOption}},
			{name: "a subnegotiation on one does not swallow the other's request", first: []byte{iac, subnegotiationBegin}, second: request(doVerb, telnetTypeOption), secondWant: request(wont, telnetTypeOption)},
			{name: "a SEND sent on one is still owed on the other", first: request(will, telnetTypeOption), second: request(will, telnetTypeOption), secondWant: terminalTypeSend},
			{name: "a Synch owed on one is not owed on the other", first: command(abortOutput), second: nil},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				first, second := fresh(), fresh()
				receive(t, first, row.first, nil)
				got, ended := receive(t, second, row.second, nil)
				if !bytes.Equal(got, row.secondWant) || ended != row.secondEnded {
					t.Fatalf("the second negotiation gave % x %v, want % x %v", got, ended, row.secondWant, row.secondEnded)
				}
				if synchs := second.TakeSynch(); synchs != 0 {
					t.Fatalf("the second negotiation owes %d Synchs", synchs)
				}
				got, _ = receive(t, second, probe, nil)
				if !bytes.Equal(got, join(request(doVerb, sga), request(wont, telnetTypeOption))) {
					t.Fatalf("the second negotiation answered the probe with % x", got)
				}
			})
		}
	})
	t.Run("A Negotiation not made by New shall behave as one New returned.", func(t *testing.T) {
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
			t.Run(makerName+": all eight answered ends negotiation", func(t *testing.T) {
				t.Parallel()
				runSteps(t, maker(), ending(nil))
			})
		}
	})
}
