// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests of the Telnet options a caller's terminal negotiates, through the Listener on real
// loopback sockets: the eight opening requests, RFC 1143's rules on both sides, the refusals, and
// the SENDs for TTYPE, TSPEED and NEW-ENVIRON, each call followed to its end.
package listener_test

import (
	"bytes"
	"slices"
	"testing"
	"time"
)

// The SENDs, by RFC 1091, RFC 1079 and RFC 1572, written here from the RFCs.
var (
	terminalTypeSend = []byte{iac, subnegotiationBegin, telnetTypeOption, 1, iac, subnegotiationEnd}
	speedSend        = []byte{iac, subnegotiationBegin, speedOption, 1, iac, subnegotiationEnd}
	environSend      = []byte{iac, subnegotiationBegin, environOption, 1, 0, 'U', 'S', 'E', 'R', iac, subnegotiationEnd}
)

// The options on each side, as Part 4's lines name them.
var (
	engineOptions = []byte{echo, sga, binary}
	callerOptions = []byte{sga, binary, telnetTypeOption, windowSizeOption, environOption, speedOption}
)

// agreed answers all eight, every one agreed: the SENDs follow, in the order of the answers.
var agreed = join(request(doVerb, echo), request(doVerb, sga), request(doVerb, binary), request(will, binary),
	request(will, telnetTypeOption), request(will, windowSizeOption), request(will, environOption), request(will, speedOption))

// optionCall sends the bytes of the negotiation in one write, then, once the prompt has come, the
// bytes typed and n CR, and checks the whole stream to its end.
func optionCall(t *testing.T, negotiation, typed, want []byte) {
	t.Helper()
	call := dial(t, startEngine(t, 1)[0])
	stream := call.record(call.connected.Add(negotiationLimit + patient(5*time.Second)))
	call.send(t, negotiation)
	stream.waitFor(t, bytes.Index(want, asked)+len(asked), call.connected.Add(negotiationLimit+progressLimit))
	call.send(t, join(typed, []byte("n\r")))
	stream.expectStream(t, want)
}

func TestOptions(t *testing.T) {
	t.Parallel()
	t.Run("When it accepts a Telnet caller, the engine shall send IAC WILL ECHO, IAC WILL SGA, IAC WILL BINARY, IAC DO BINARY, IAC DO TTYPE, IAC DO NAWS, IAC DO NEW-ENVIRON and IAC DO TSPEED, in that order, and no other option request.", func(t *testing.T) {
		t.Parallel()
		t.Run("a caller that agrees to every one: the opening, the three SENDs, the greeting, no other request", func(t *testing.T) {
			t.Parallel()
			optionCall(t, agreed, nil, join(opening, terminalTypeSend, environSend, speedSend, asked, echoed("n")))
		})
		t.Run("a caller that refuses every one: the opening and the greeting, no other request", func(t *testing.T) {
			t.Parallel()
			refuseAll := join(request(dont, echo), request(dont, sga), request(dont, binary), request(wont, binary),
				request(wont, telnetTypeOption), request(wont, windowSizeOption), request(wont, environOption), request(wont, speedOption))
			optionCall(t, refuseAll, nil, join(opening, asked, helloTo("n")))
		})
		t.Run("a silent caller: the opening, then nothing until the greeting at 3 seconds", func(t *testing.T) {
			t.Parallel()
			optionCall(t, nil, nil, join(opening, asked, helloTo("n")))
		})
	})
	t.Run("The engine shall answer requests about ECHO, SGA and BINARY on its own side, and about SGA, BINARY, TTYPE, NAWS, NEW-ENVIRON and TSPEED on the caller's side, by RFC 1143's rules.", func(t *testing.T) {
		t.Parallel()
		// Each row's caller types its bytes, then n and CR; after is everything past the opening.
		rows := []struct {
			name        string
			negotiation []byte
			typed       []byte
			after       []byte
		}{
			{name: "ECHO refused, then a and DO ECHO mid-name: a not echoed, WILL ECHO, then n echoed",
				negotiation: refused, typed: join([]byte("a"), request(doVerb, echo)),
				after: join(asked, request(will, echo), []byte("n\r\n"), helloTo("an"))},
			{name: "ECHO agreed, then a and DONT ECHO mid-name: a echoed, WONT ECHO, then n not echoed",
				negotiation: answers, typed: join([]byte("a"), request(dont, echo)),
				after: join(asked, []byte("a"), request(wont, echo), helloTo("an"))},
			{name: "the engine's SGA: DONT gets WONT, DO again gets WILL",
				negotiation: answers, typed: join(request(dont, sga), request(doVerb, sga)),
				after: join(asked, request(wont, sga), request(will, sga), echoed("n"))},
			{name: "the engine's BINARY: DONT gets WONT, DO again gets WILL",
				negotiation: answers, typed: join(request(dont, binary), request(doVerb, binary)),
				after: join(asked, request(wont, binary), request(will, binary), echoed("n"))},
			{name: "the caller's BINARY: WONT gets DONT, WILL again gets DO",
				negotiation: answers, typed: join(request(wont, binary), request(will, binary)),
				after: join(asked, request(dont, binary), request(doVerb, binary), echoed("n"))},
			{name: "the caller's SGA, never asked for: WILL gets DO, WONT gets DONT, during negotiation",
				negotiation: join(request(will, sga), request(wont, sga), answers),
				after:       join(request(doVerb, sga), request(dont, sga), asked, echoed("n"))},
			{name: "the caller's NAWS refused, then offered mid-name: DO NAWS, and no SEND",
				negotiation: answers, typed: request(will, windowSizeOption),
				after: join(asked, request(doVerb, windowSizeOption), echoed("n"))},
			{name: "agreements repeated get no reply: DO ECHO, DO BINARY and WILL BINARY again mid-name",
				negotiation: answers, typed: join(request(doVerb, echo), request(doVerb, binary), request(will, binary)),
				after: join(asked, echoed("n"))},
			{name: "refusals repeated get no reply: WONT TTYPE and WONT TSPEED again mid-name",
				negotiation: answers, typed: join(request(wont, telnetTypeOption), request(wont, speedOption)),
				after: join(asked, echoed("n"))},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				optionCall(t, row.negotiation, row.typed, join(opening, row.after))
			})
		}
	})
	t.Run("If the caller sends WILL for a Telnet option other than SGA, BINARY, TTYPE, NAWS, NEW-ENVIRON and TSPEED, or DO for one other than ECHO, SGA and BINARY, then the engine shall refuse it, WILL with DONT and DO with WONT.", func(t *testing.T) {
		t.Parallel()
		var asks, refusals []byte
		for code := range 256 {
			option := byte(code)
			if !slices.Contains(callerOptions, option) {
				asks = append(asks, request(will, option)...)
				refusals = append(refusals, request(dont, option)...)
			}
			if !slices.Contains(engineOptions, option) {
				asks = append(asks, request(doVerb, option)...)
				refusals = append(refusals, request(wont, option)...)
			}
		}
		t.Run("WILL and DO for every option outside the tables during negotiation: DONT and WONT for each, in order", func(t *testing.T) {
			t.Parallel()
			optionCall(t, join(asks, answers), nil, join(opening, refusals, asked, echoed("n")))
		})
		t.Run("WILL ECHO, WILL 25 and DO 2 mid-name: DONT ECHO, DONT 25 and WONT 2", func(t *testing.T) {
			t.Parallel()
			optionCall(t, answers, join(request(will, echo), request(will, 25), request(doVerb, 2)),
				join(opening, asked, request(dont, echo), request(dont, 25), request(wont, 2), echoed("n")))
		})
		t.Run("WILL 255 and DO 255 with ECHO refused: DONT 255 and WONT 255", func(t *testing.T) {
			t.Parallel()
			optionCall(t, refused, join(request(will, 255), request(doVerb, 255)),
				join(opening, asked, request(dont, 255), request(wont, 255), helloTo("n")))
		})
	})
	t.Run("When the caller agrees to TTYPE or TSPEED, the engine shall send that option's SEND, at most once in the call.", func(t *testing.T) {
		t.Parallel()
		withTerminal := join(answers[:12], request(will, telnetTypeOption), request(wont, windowSizeOption), request(wont, environOption), request(will, speedOption))
		t.Run("TTYPE and TSPEED agreed as answers: each SEND once, before the greeting", func(t *testing.T) {
			t.Parallel()
			optionCall(t, withTerminal, nil, join(opening, terminalTypeSend, speedSend, asked, echoed("n")))
		})
		t.Run("TTYPE refused as an answer, offered mid-name: DO TTYPE and its SEND", func(t *testing.T) {
			t.Parallel()
			optionCall(t, answers, request(will, telnetTypeOption), join(opening, asked, request(doVerb, telnetTypeOption), terminalTypeSend, echoed("n")))
		})
		t.Run("TSPEED agreed, then refused and agreed again mid-name: one SEND in the call", func(t *testing.T) {
			t.Parallel()
			optionCall(t, withTerminal, join(request(wont, speedOption), request(will, speedOption), request(wont, speedOption), request(will, speedOption)),
				join(opening, terminalTypeSend, speedSend, asked, repeated(join(request(dont, speedOption), request(doVerb, speedOption)), 2), echoed("n")))
		})
		t.Run("TTYPE offered three times during negotiation: one SEND", func(t *testing.T) {
			t.Parallel()
			optionCall(t, join(request(will, telnetTypeOption), request(will, telnetTypeOption), withTerminal), nil,
				join(opening, terminalTypeSend, speedSend, asked, echoed("n")))
		})
	})
	t.Run("When the caller agrees to NEW-ENVIRON, the engine shall send SEND for the variable USER alone, at most once in the call.", func(t *testing.T) {
		t.Parallel()
		withEnviron := join(answers[:18], request(will, environOption), answers[21:])
		t.Run("NEW-ENVIRON agreed as an answer: SEND VAR USER once, before the greeting", func(t *testing.T) {
			t.Parallel()
			optionCall(t, withEnviron, nil, join(opening, environSend, asked, echoed("n")))
		})
		t.Run("NEW-ENVIRON refused as an answer, offered mid-name: DO NEW-ENVIRON and its SEND", func(t *testing.T) {
			t.Parallel()
			optionCall(t, answers, request(will, environOption), join(opening, asked, request(doVerb, environOption), environSend, echoed("n")))
		})
		t.Run("NEW-ENVIRON agreed, then refused and agreed again mid-name: one SEND in the call", func(t *testing.T) {
			t.Parallel()
			optionCall(t, withEnviron, join(request(wont, environOption), request(will, environOption)),
				join(opening, environSend, asked, request(dont, environOption), request(doVerb, environOption), echoed("n")))
		})
	})
}
