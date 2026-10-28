// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests of Strip, the reading of a caller's bytes after negotiation: which bytes are data and
// which byte each hands on, EC and EL handed on as BS and Ctrl-U, the reply to every option
// request in every state negotiation can leave the options in, the SENDs once across Receive and
// Strip, AYT, the Synchs AO and IP owe, the commands it discards, and a sequence split across
// negotiation's end, against the test's own reading of RFC 854, RFC 855 and RFC 1143 section 7.
package telnet_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/telnet"
)

// stripped is what Strip gave for some bytes, one call per byte: the replies, whether each byte
// handed one on, and the bytes handed on.
type stripped struct {
	replies []byte
	handed  []bool
	data    []byte
	synchs  int
}

// stripAll calls Strip once per byte, checking on each call that the bytes already in replies
// stay and that it appends at most MostReply bytes.
func stripAll(t *testing.T, negotiation *telnet.Negotiation, input []byte) stripped {
	t.Helper()
	var result stripped
	prior := []byte("prior")
	for index, value := range input {
		replies := append(make([]byte, 0, len(prior)), prior...)
		got, handed, isData := stripOne(t, negotiation, value, replies)
		if len(got) < len(prior) || !bytes.Equal(got[:len(prior)], prior) || !bytes.Equal(replies, prior) {
			t.Fatalf("Strip of byte %d changed the bytes already in replies: % x", index, got)
		}
		appended := got[len(prior):]
		if len(appended) > mostOneReply {
			t.Fatalf("one call of Strip appended %d bytes: % x", len(appended), appended)
		}
		result.replies = append(result.replies, appended...)
		result.handed = append(result.handed, isData)
		if isData {
			result.data = append(result.data, handed)
		}
	}
	result.synchs = negotiation.TakeSynch()
	return result
}

func stripOne(t *testing.T, negotiation *telnet.Negotiation, value byte, replies []byte) (got []byte, handed byte, isData bool) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("Strip panicked on %#02x: %v", value, recovered)
		}
	}()
	return negotiation.Strip(value, replies)
}

// expectedStrip is the test's own reading of the same bytes.
func expectedStrip(state *reading, input []byte) stripped {
	var result stripped
	before := state.synchs
	for _, value := range input {
		reply, handed, isData := state.feed(value)
		result.replies = append(result.replies, reply...)
		result.handed = append(result.handed, isData)
		if isData {
			result.data = append(result.data, handed)
		}
	}
	result.synchs = state.synchs - before
	return result
}

// stripProbe ends a subnegotiation if one is open, then asks for ECHO and BINARY to stop and
// start again on the engine's side, for SGA on the caller's, BINARY to stop and start on the
// caller's, and an option the engine refuses: the replies show the state each option was left
// in, and that the reading kept up.
var stripProbe = join(command(subnegotiationEnd), command(nop),
	request(dont, echo), request(doVerb, echo), request(dont, binary), request(doVerb, binary),
	request(will, sga), request(wont, binary), request(will, binary),
	request(doVerb, telnetTypeOption))

// agreeAll answers all eight, every one agreed: the three SENDs follow.
var agreeAll = join(request(doVerb, echo), request(doVerb, sga), request(doVerb, binary), request(will, binary),
	request(will, telnetTypeOption), request(will, windowSizeOption), request(will, environOption), request(will, speedOption))

// refuseAll answers all eight, every one refused.
var refuseAll = join(request(dont, echo), request(dont, sga), request(dont, binary), request(wont, binary),
	request(wont, telnetTypeOption), request(wont, windowSizeOption), request(wont, environOption), request(wont, speedOption))

// negotiationEnding is how negotiation ended before Strip took over, made by hand through New
// and Receive.
type negotiationEnding struct {
	name  string
	input []byte
}

// endings are the states negotiation can leave the options in, Receive having returned true or
// not, with the SENDs sent or not.
var endings = []negotiationEnding{
	{name: "after the answers", input: answers},
	{name: "after every one refused", input: refuseAll},
	{name: "after every one agreed, the SENDs sent", input: agreeAll},
	{name: "after ECHO refused and the rest agreed", input: join(request(dont, echo), agreeAll[3:])},
	{name: "with no answer, as when 3 seconds pass", input: nil},
	{name: "after ECHO and SGA alone, as when 3 seconds pass", input: firstAnswers},
	{name: "after WILL TTYPE alone, its SEND sent, as when 3 seconds pass", input: request(will, telnetTypeOption)},
}

// negotiatedBy runs Receive over the bytes and returns the negotiation and the test's reading of
// where it stopped.
func negotiatedBy(t *testing.T, input []byte) (*telnet.Negotiation, *reading) {
	t.Helper()
	negotiation := fresh()
	during := freshReading()
	wantReplies, wantEnded := during.readAll(input)
	got, ended := receive(t, negotiation, input, nil)
	if !bytes.Equal(got, wantReplies) || ended != wantEnded {
		t.Fatalf("setting up: Receive of % x gave % x %v, want % x %v", input, got, ended, wantReplies, wantEnded)
	}
	negotiation.TakeSynch()
	return negotiation, during
}

// expectStrip strips the row's bytes and then the probe, checking both against the test's own
// reading, and that every reply is well formed and the replies never outgrow the input. A want
// left nil is the reading's alone; one given must agree with it, or the row is a fault in the
// test.
func expectStrip(t *testing.T, before, input []byte, want *stripped) {
	t.Helper()
	negotiation, during := negotiatedBy(t, before)
	oracle := during.takeOver()
	expected := expectedStrip(oracle, input)
	if want != nil && (!bytes.Equal(want.replies, expected.replies) || fmt.Sprint(want.handed) != fmt.Sprint(expected.handed) ||
		!bytes.Equal(want.data, expected.data) || want.synchs != expected.synchs) {
		t.Fatalf("test fault: the row disagrees with the test's own reading: % x %v % x %d", expected.replies, expected.handed, expected.data, expected.synchs)
	}
	got := stripAll(t, negotiation, input)
	if !bytes.Equal(got.replies, expected.replies) || fmt.Sprint(got.handed) != fmt.Sprint(expected.handed) || !bytes.Equal(got.data, expected.data) {
		t.Fatalf("Strip of % x replied\n% x\nhanded on %v, % x\nwant\n% x\n%v, % x", input, got.replies, got.handed, got.data, expected.replies, expected.handed, expected.data)
	}
	if got.synchs != expected.synchs {
		t.Fatalf("Strip of % x owed %d Synchs, want %d", input, got.synchs, expected.synchs)
	}
	probeWant := expectedStrip(oracle, stripProbe)
	probed := stripAll(t, negotiation, stripProbe)
	if !bytes.Equal(probed.replies, probeWant.replies) {
		t.Fatalf("after % x the probe got % x, want % x", input, probed.replies, probeWant.replies)
	}
	duringReplies, _ := freshReading().readAll(before)
	checkReplies(t, join(duringReplies, got.replies, probed.replies), join(before, input, stripProbe))
}

func everyByte() []byte {
	var values []byte
	for code := range 256 {
		values = append(values, byte(code))
	}
	return values
}

func allTrue(count int) []bool {
	values := make([]bool, count)
	for index := range values {
		values[index] = true
	}
	return values
}

func TestStrip(t *testing.T) {
	t.Parallel()
	t.Run("Strip shall return true, with the byte to hand on, for each data byte, for the second IAC of IAC IAC outside a subnegotiation, and for the last byte of IAC EC and of IAC EL; and false for every other byte.", func(t *testing.T) {
		t.Parallel()
		for _, end := range endings {
			t.Run("every byte but IAC is data and handed on as itself, "+end.name, func(t *testing.T) {
				t.Parallel()
				input := everyByte()[:255]
				expectStrip(t, end.input, input, &stripped{replies: nil, handed: allTrue(len(input)), data: input})
			})
		}
		commands := map[string][]byte{
			"IAC NOP":                      command(nop),
			"IAC AYT":                      command(ayt),
			"IAC AO":                       command(abortOutput),
			"IAC DM":                       command(dataMark),
			"DO 24":                        request(doVerb, telnetTypeOption),
			"WILL 31":                      request(will, windowSizeOption),
			"WONT ECHO":                    request(wont, echo),
			"a subnegotiation":             {iac, subnegotiationBegin, telnetTypeOption, 0, 'x', iac, subnegotiationEnd},
			"text around a request":        join([]byte("ab"), request(doVerb, telnetTypeOption), []byte("c")),
			"text around a subnegotiation": join([]byte("a"), []byte{iac, subnegotiationBegin, windowSizeOption, 0, 80, 0, 24, iac, subnegotiationEnd}, []byte("b")),
			"IAC IAC, IAC EC, IAC EL":      join(command(iac), command(eraseCharacter), command(eraseLine)),
		}
		for name, input := range commands {
			t.Run(name+", after the answers", func(t *testing.T) {
				t.Parallel()
				expectStrip(t, answers, input, nil)
			})
		}
	})
	t.Run("When the bytes hold IAC IAC outside a subnegotiation, Strip shall return false for the first IAC and the data byte 255 with true for the second.", func(t *testing.T) {
		t.Parallel()
		for _, end := range endings {
			t.Run("IAC IAC, "+end.name, func(t *testing.T) {
				t.Parallel()
				expectStrip(t, end.input, command(iac), &stripped{handed: []bool{false, true}, data: []byte{iac}})
			})
		}
		t.Run("a then IAC IAC IAC IAC then b: two data bytes 255", func(t *testing.T) {
			t.Parallel()
			expectStrip(t, answers, []byte{'a', iac, iac, iac, iac, 'b'}, &stripped{handed: []bool{true, false, true, false, true, true}, data: []byte{'a', iac, iac, 'b'}})
		})
		t.Run("IAC IAC then DO 24: the third IAC starts a request", func(t *testing.T) {
			t.Parallel()
			expectStrip(t, answers, join(command(iac), request(doVerb, telnetTypeOption)), &stripped{replies: request(wont, telnetTypeOption), handed: []bool{false, true, false, false, false}, data: []byte{iac}})
		})
	})
	t.Run("When the bytes hold IAC EC, Strip shall return false for IAC and BS, 0x08, with true for EC.", func(t *testing.T) {
		t.Parallel()
		for _, end := range endings {
			t.Run("IAC EC, "+end.name, func(t *testing.T) {
				t.Parallel()
				expectStrip(t, end.input, command(eraseCharacter), &stripped{handed: []bool{false, true}, data: []byte{backspace}})
			})
		}
		t.Run("ab, IAC EC, c: a, b, BS, c", func(t *testing.T) {
			t.Parallel()
			expectStrip(t, answers, join([]byte("ab"), command(eraseCharacter), []byte("c")), &stripped{handed: []bool{true, true, false, true, true}, data: []byte{'a', 'b', backspace, 'c'}})
		})
		t.Run("IAC EC inside a subnegotiation hands nothing on", func(t *testing.T) {
			t.Parallel()
			expectStrip(t, answers, join([]byte{iac, subnegotiationBegin, telnetTypeOption}, command(eraseCharacter), command(subnegotiationEnd)), &stripped{handed: make([]bool, 7)})
		})
	})
	t.Run("When the bytes hold IAC EL, Strip shall return false for IAC and Ctrl-U, 0x15, with true for EL.", func(t *testing.T) {
		t.Parallel()
		for _, end := range endings {
			t.Run("IAC EL, "+end.name, func(t *testing.T) {
				t.Parallel()
				expectStrip(t, end.input, command(eraseLine), &stripped{handed: []bool{false, true}, data: []byte{eraseLineByte}})
			})
		}
		t.Run("abc, IAC EL, d: a, b, c, Ctrl-U, d", func(t *testing.T) {
			t.Parallel()
			expectStrip(t, answers, join([]byte("abc"), command(eraseLine), []byte("d")), &stripped{handed: []bool{true, true, true, false, true, true}, data: []byte{'a', 'b', 'c', eraseLineByte, 'd'}})
		})
	})
	t.Run("When a byte completes an option request, Strip shall answer it into replies, change the option's state and append a SEND exactly as Receive's lines do while negotiation lasts.", func(t *testing.T) {
		t.Parallel()
		for _, end := range endings {
			for _, verb := range []byte{will, wont, doVerb, dont} {
				t.Run(fmt.Sprintf("verb %d for every option, %s", verb, end.name), func(t *testing.T) {
					t.Parallel()
					for code := range 256 {
						asked := request(verb, byte(code))
						state := freshReading()
						state.readAll(end.input)
						replies, _, _ := state.takeOver().readLine(asked)
						expectStrip(t, end.input, asked, &stripped{handed: []bool{false, false, false}, replies: replies})
					}
				})
			}
		}
		t.Run("the engine's table after the answers: DONT ECHO gives WONT ECHO, then DO ECHO gives WILL ECHO", func(t *testing.T) {
			t.Parallel()
			expectStrip(t, answers, join(request(dont, echo), request(doVerb, echo), request(doVerb, echo)),
				&stripped{replies: join(request(wont, echo), request(will, echo)), handed: make([]bool, 9)})
		})
		t.Run("the caller's table after the answers: WILL TTYPE gives DO and the SEND, WILL SGA gives DO", func(t *testing.T) {
			t.Parallel()
			expectStrip(t, answers, join(request(will, telnetTypeOption), request(will, sga)),
				&stripped{replies: join(request(doVerb, telnetTypeOption), terminalTypeSend, request(doVerb, sga)), handed: make([]bool, 6)})
		})
		t.Run("a SEND sent during negotiation is not sent again: after all agreed, WONT and WILL NEW-ENVIRON give DONT and DO", func(t *testing.T) {
			t.Parallel()
			expectStrip(t, agreeAll, join(request(wont, environOption), request(will, environOption)),
				&stripped{replies: join(request(dont, environOption), request(doVerb, environOption)), handed: make([]bool, 6)})
		})
		t.Run("a late yes: DO ECHO with ECHO still in WANTYES moves it to YES with no reply", func(t *testing.T) {
			t.Parallel()
			expectStrip(t, nil, join(request(doVerb, echo), request(dont, echo)), &stripped{replies: request(wont, echo), handed: make([]bool, 6)})
		})
		t.Run("all eight answered late, after 3 seconds with no answer, then DO 24, WILL 25 and AYT: still answered", func(t *testing.T) {
			t.Parallel()
			expectStrip(t, nil, join(answers, request(doVerb, telnetTypeOption), request(will, 25), command(ayt)),
				&stripped{replies: join(request(wont, telnetTypeOption), request(dont, 25), []byte(aytAnswerBytes)), handed: make([]bool, len(answers)+8)})
		})
		t.Run("the last six answered late, after ECHO and SGA alone, then DONT ECHO: WONT ECHO", func(t *testing.T) {
			t.Parallel()
			expectStrip(t, firstAnswers, join(restAnswers, request(dont, echo)), &stripped{replies: request(wont, echo), handed: make([]bool, len(restAnswers)+3)})
		})
		t.Run("a late yes: WILL TSPEED still in WANTYES gives the SEND alone", func(t *testing.T) {
			t.Parallel()
			expectStrip(t, nil, request(will, speedOption), &stripped{replies: speedSend, handed: make([]bool, 3)})
		})
	})
	t.Run("When the bytes hold IAC AYT, Strip shall append AYTAnswer.", func(t *testing.T) {
		t.Parallel()
		for _, end := range endings {
			t.Run("AYT, "+end.name, func(t *testing.T) {
				t.Parallel()
				expectStrip(t, end.input, command(ayt), &stripped{replies: []byte(aytAnswerBytes), handed: make([]bool, 2)})
			})
		}
		t.Run("a, AYT, b, AYT: two answers, a and b handed on", func(t *testing.T) {
			t.Parallel()
			expectStrip(t, answers, join([]byte("a"), command(ayt), []byte("b"), command(ayt)),
				&stripped{replies: []byte(aytAnswerBytes + aytAnswerBytes), handed: []bool{true, false, false, true, false, false}, data: []byte("ab")})
		})
	})
	t.Run("When the bytes hold IAC AO or IAC IP, Strip shall owe a Synch, appending no reply.", func(t *testing.T) {
		t.Parallel()
		for _, end := range endings {
			t.Run("AO and IP, "+end.name, func(t *testing.T) {
				t.Parallel()
				expectStrip(t, end.input, join(command(abortOutput), command(interruptProcess)), &stripped{handed: make([]bool, 4), synchs: 2})
			})
		}
		t.Run("a, AO, b: one Synch, a and b handed on", func(t *testing.T) {
			t.Parallel()
			expectStrip(t, answers, join([]byte("a"), command(abortOutput), []byte("b")), &stripped{handed: []bool{true, false, false, true}, data: []byte("ab"), synchs: 1})
		})
	})
	t.Run("When the bytes hold IAC and then a byte other than WILL, WONT, DO, DONT, SB, IAC, AYT, AO, IP, EC or EL, or a subnegotiation, Strip shall discard them without reply.", func(t *testing.T) {
		t.Parallel()
		t.Run("IAC and every other byte, after the answers", func(t *testing.T) {
			t.Parallel()
			for code := range 256 {
				value := byte(code)
				switch value {
				case will, wont, doVerb, dont, subnegotiationBegin, iac, ayt, abortOutput, interruptProcess, eraseCharacter, eraseLine:
					continue
				}
				expectStrip(t, answers, command(value), &stripped{handed: make([]bool, 2)})
			}
		})
		subnegotiations := map[string][]byte{
			"requests inside a subnegotiation get no reply": join([]byte{iac, subnegotiationBegin, telnetTypeOption}, request(doVerb, telnetTypeOption), request(will, windowSizeOption), command(subnegotiationEnd)),
			"IAC IAC SE inside does not end it":             {iac, subnegotiationBegin, telnetTypeOption, iac, iac, subnegotiationEnd, 'x', iac, subnegotiationEnd},
			"every byte inside a subnegotiation":            join([]byte{iac, subnegotiationBegin}, bytes.ReplaceAll(everyByte(), []byte{iac}, []byte{iac, iac}), command(subnegotiationEnd)),
			"a TTYPE IS, a NEW-ENVIRON IS and a NAWS":       join([]byte{iac, subnegotiationBegin, telnetTypeOption, isCode}, []byte("XTERM"), command(subnegotiationEnd), []byte{iac, subnegotiationBegin, environOption, isCode, variableCode}, []byte("USER"), []byte{valueCode}, []byte("marker"), command(subnegotiationEnd), []byte{iac, subnegotiationBegin, windowSizeOption, 0, 80, 0, 24, iac, subnegotiationEnd}),
		}
		for name, input := range subnegotiations {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				expectStrip(t, answers, input, &stripped{handed: make([]bool, len(input))})
			})
		}
	})
	t.Run("When a sequence is split across negotiation's end, Strip shall read it as it would had the sequence come after it whole.", func(t *testing.T) {
		t.Parallel()
		sequences := map[string][]byte{
			"DO 24":             request(doVerb, telnetTypeOption),
			"WILL 31":           request(will, windowSizeOption),
			"DONT ECHO":         request(dont, echo),
			"WILL TTYPE":        request(will, telnetTypeOption),
			"IAC IAC":           command(iac),
			"IAC NOP":           command(nop),
			"IAC AYT":           command(ayt),
			"IAC AO":            command(abortOutput),
			"IAC EC":            command(eraseCharacter),
			"IAC EL":            command(eraseLine),
			"a subnegotiation":  {iac, subnegotiationBegin, telnetTypeOption, iac, iac, subnegotiationEnd, iac, subnegotiationEnd},
			"DO SGA, an answer": request(doVerb, sga),
		}
		for name, sequence := range sequences {
			for cut := 1; cut < len(sequence); cut++ {
				t.Run(fmt.Sprintf("%s, the first %d bytes read by negotiation before its 3 seconds passed", name, cut), func(t *testing.T) {
					t.Parallel()
					// One answer and the start of the sequence: negotiation has not ended, as when
					// 3 seconds pass with a read cut there.
					before := join(request(doVerb, echo), sequence[:cut])
					whole := freshReading()
					whole.readAll(request(doVerb, echo))
					want := expectedStrip(whole.takeOver(), sequence)
					rest := stripped{replies: want.replies, handed: want.handed[cut:], synchs: want.synchs}
					for index, isData := range want.handed[cut:] {
						if isData {
							rest.data = want.data[len(want.data)-len(want.handed[cut:])+index:]
							break
						}
					}
					expectStrip(t, before, sequence[cut:], &rest)
				})
			}
		}
	})
	t.Run("Strip shall append its reply after the bytes already in replies, and leave those unchanged.", func(t *testing.T) {
		t.Parallel()
		for _, end := range endings {
			t.Run("DO 24, WILL NEW-ENVIRON, AYT, DONT ECHO and DO ECHO after the bytes prior, "+end.name, func(t *testing.T) {
				t.Parallel()
				// stripAll holds every call to the bytes already in replies.
				expectStrip(t, end.input, join(request(doVerb, telnetTypeOption), request(will, environOption), command(ayt), request(dont, echo), request(doVerb, echo)), nil)
			})
		}
		t.Run("a reply into a slice with room to spare leaves the bytes past its length alone", func(t *testing.T) {
			t.Parallel()
			negotiation, _ := negotiatedBy(t, answers)
			backing := []byte("prior-and-spare")
			replies := backing[:5]
			for _, value := range request(doVerb, telnetTypeOption) {
				replies, _, _ = stripOne(t, negotiation, value, replies)
			}
			if !bytes.Equal(replies, join([]byte("prior"), request(wont, telnetTypeOption))) {
				t.Fatalf("replies were % x", replies)
			}
		})
	})
	t.Run("Strip shall append at most MostReply bytes in one call.", func(t *testing.T) {
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
				// stripAll fails a call that appends more than MostReply bytes.
				expectStrip(t, end.input, input, nil)
			})
		}
		t.Run("WILL NEW-ENVIRON after WONT, its SEND not yet sent: exactly 14 bytes from its last byte", func(t *testing.T) {
			t.Parallel()
			negotiation, _ := negotiatedBy(t, nil)
			stripAll(t, negotiation, request(wont, environOption))
			stripAll(t, negotiation, []byte{iac, will})
			got, _, _ := stripOne(t, negotiation, environOption, nil)
			if !bytes.Equal(got, join(request(doVerb, environOption), environSend)) {
				t.Fatalf("the last byte appended % x, want DO NEW-ENVIRON and its SEND", got)
			}
		})
	})
	t.Run("Strip shall append to replies, over all its calls and Receive's on one negotiation, no more bytes than five times all their input held.", func(t *testing.T) {
		t.Parallel()
		for _, end := range endings {
			t.Run("a thousand toggles, refusals and AYTs, "+end.name, func(t *testing.T) {
				t.Parallel()
				input := repeated(join(request(dont, echo), request(doVerb, echo), request(wont, environOption), request(will, environOption), request(will, telnetTypeOption), request(doVerb, windowSizeOption), command(ayt)), 1000)
				// expectStrip holds the replies of Receive and Strip together to five times the
				// input.
				expectStrip(t, end.input, input, nil)
			})
		}
	})
	t.Run("After Strip's first call, Receive shall append no reply and change no state on that negotiation, for every later call.", func(t *testing.T) {
		t.Parallel()
		rows := map[string][]byte{
			"with no answer: Receive given the answers after Strip read a data byte":        nil,
			"after ECHO and SGA alone: Receive given the rest after Strip read a data byte": firstAnswers,
		}
		for name, before := range rows {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				negotiation, during := negotiatedBy(t, before)
				oracle := during.takeOver()
				expectedStrip(oracle, []byte("a"))
				stripAll(t, negotiation, []byte("a"))
				for _, input := range [][]byte{refuseAll, request(doVerb, telnetTypeOption), request(will, windowSizeOption), command(ayt), command(abortOutput)} {
					got, ended := receive(t, negotiation, input, nil)
					if len(got) != 0 || ended {
						t.Fatalf("Receive of % x after Strip appended % x and returned %v", input, got, ended)
					}
				}
				if synchs := negotiation.TakeSynch(); synchs != 0 {
					t.Fatalf("Receive's AO after Strip owed %d Synchs", synchs)
				}
				// The states are as Strip left them: Receive's refusals moved nothing.
				want := expectedStrip(oracle, stripProbe)
				probed := stripAll(t, negotiation, stripProbe)
				if !bytes.Equal(probed.replies, want.replies) {
					t.Fatalf("after Receive's calls the probe got % x, want % x", probed.replies, want.replies)
				}
			})
		}
		t.Run("after the answers: Receive after Strip appends nothing and still returns true", func(t *testing.T) {
			t.Parallel()
			negotiation, _ := negotiatedBy(t, answers)
			if result := stripAll(t, negotiation, request(dont, echo)); !bytes.Equal(result.replies, request(wont, echo)) {
				t.Fatalf("Strip of DONT ECHO after the answers replied % x, want WONT ECHO", result.replies)
			}
			got, ended := receive(t, negotiation, join(request(doVerb, echo), request(doVerb, telnetTypeOption)), nil)
			if len(got) != 0 || !ended {
				t.Fatalf("Receive after Strip appended % x and returned %v", got, ended)
			}
			// ECHO is as Strip left it, NO: DO ECHO is answered with WILL ECHO.
			if result := stripAll(t, negotiation, request(doVerb, echo)); !bytes.Equal(result.replies, request(will, echo)) {
				t.Fatalf("after Receive, Strip of DO ECHO replied % x, want WILL ECHO", result.replies)
			}
		})
	})
	t.Run("Strip shall let nothing inside a subnegotiation change a reply, a state, a byte handed on or whether a Synch is owed.", func(t *testing.T) {
		t.Parallel()
		insides := map[string][]byte{
			"option requests":                   join(request(dont, echo), request(will, telnetTypeOption), request(will, sga), request(doVerb, 99)),
			"AYT, AO, IP, EC and EL":            join(command(ayt), command(abortOutput), command(interruptProcess), command(eraseCharacter), command(eraseLine)),
			"text and escape codes":             []byte("name\r\n\x1b[2J\x08\x15\x7f"),
			"NAWS of 65535 by 65535":            repeated(command(iac), 4),
			"a long run of 10000 bytes":         repeated([]byte("abcdefghij"), 1000),
			"IAC IAC SE, which does not end it": join(command(iac), []byte{subnegotiationEnd}, request(will, sga)),
		}
		for _, end := range endings {
			for name, inside := range insides {
				t.Run(name+", "+end.name, func(t *testing.T) {
					t.Parallel()
					input := join([]byte{iac, subnegotiationBegin, windowSizeOption}, inside, command(subnegotiationEnd))
					expectStrip(t, end.input, input, &stripped{handed: make([]bool, len(input))})
				})
			}
		}
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
						expectStrip(t, end.input, join(prefix, []byte{byte(code)}), nil)
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
			// It reads as a negotiation New returned does: a is data, DO 24 is refused, WILL SGA
			// agreed, EC handed on as BS.
			var zero telnet.Negotiation
			got := stripAll(t, &zero, join([]byte("a"), request(doVerb, telnetTypeOption), request(will, sga), command(eraseCharacter)))
			if !bytes.Equal(got.replies, join(request(wont, telnetTypeOption), request(doVerb, sga))) || !bytes.Equal(got.data, []byte{'a', backspace}) {
				t.Fatalf("a zero Negotiation's Strip replied % x, handed on % x", got.replies, got.data)
			}
		})
	})
}
