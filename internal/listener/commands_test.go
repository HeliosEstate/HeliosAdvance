// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests of the Telnet commands a caller sends, through the Listener on real loopback sockets: AYT
// answered, AO and IP answered with a Synch sent as urgent data, EC and EL editing the name,
// every other command discarded with the data around it kept, Ctrl-U erasing the name, and what
// a caller sends inside a subnegotiation kept from the stream and changing nothing written.
package listener_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// The commands of RFC 854 and RFC 885 these rows send, from the RFCs.
const (
	goAhead          byte = 249
	eraseLine        byte = 248
	eraseCharacter   byte = 247
	abortOutput      byte = 245
	interruptProcess byte = 244
	breakCommand     byte = 243
	endOfRecord      byte = 239
	eraseLineKey     byte = 0x15
)

// aytAnswer is AYT's answer as Part 4's line gives it: CR LF, [Yes] and CR LF.
const aytAnswer = "\r\n[Yes]\r\n"

// erase is what the echo writes for one character removed.
var erase = []byte{backspace, ' ', backspace}

func command(code byte) []byte {
	return []byte{iac, code}
}

// expectNext reads exactly the bytes given, next, by the deadline. It reads no further, so an
// urgent byte after them is still there to take.
func (call caller) expectNext(t *testing.T, want []byte, deadline time.Time) {
	t.Helper()
	_ = call.connection.SetReadDeadline(deadline)
	got := make([]byte, len(want))
	count, err := io.ReadFull(call.connection, got)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("the caller received % x and %v, want % x", got[:count], err, want)
	}
}

// expectSynchNext reads the bytes before a Synch and its IAC, then takes its DM as urgent data, out
// of band: the caller keeps urgent data out of line, as every socket does by default.
func (call caller) expectSynchNext(t *testing.T, before []byte, deadline time.Time) {
	t.Helper()
	call.expectNext(t, join(before, []byte{iac}), deadline)
	urgent, err := receiveUrgent(t, call.connection, deadline)
	if err != nil || !bytes.Equal(urgent, []byte{dataMark}) {
		t.Fatalf("the urgent data was % x and %v, want DM, %#02x", urgent, err, dataMark)
	}
}

// expectEndNext reads the bytes given and then end of stream, by the deadline.
func (call caller) expectEndNext(t *testing.T, want []byte, deadline time.Time) {
	t.Helper()
	call.expectNext(t, want, deadline)
	rest := make([]byte, 64)
	count, err := call.connection.Read(rest)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("after % x the caller received % x and %v, want end of stream", want, rest[:count], err)
	}
}

// commandFloodCallers is how many callers the ceiling's command flood runs at once, each against
// its own engine: AYT's answers and AO's and IP's Synchs fill the caller's buffers, so only the
// ceiling can wake the engine's waiting write, an urgent one included.
const commandFloodCallers = 6

// floodCommands sends AYT, AO and IP and never reads, until its own writes stop going through. The
// caller keeps urgent data in line, so the Synchs pile up in its stream like any other byte:
// Windows resets a connection whose receiver keeps them out of line and lets them pile up.
func (call caller) floodCommands(t *testing.T) {
	t.Helper()
	keepUrgentInLine(t, call.connection)
	commands := repeated(join(command(ayt), command(abortOutput), command(interruptProcess)), 512)
	for {
		_ = call.connection.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
		_, err := call.connection.Write(commands)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return
		}
		if err != nil {
			t.Errorf("flooding: %v", err)
			return
		}
	}
}

// commandCall is a caller that has answered with the bytes given and read the greeting and the
// prompt: the call stands at its name.
func commandCall(t *testing.T, answer []byte) caller {
	t.Helper()
	call := dial(t, startEngine(t, 1)[0])
	call.send(t, answer)
	call.expectNext(t, join(opening, asked), call.connected.Add(progressLimit))
	return call
}

func TestCommands(t *testing.T) {
	t.Parallel()
	t.Run("When a Telnet caller sends AYT before its name ends, the engine shall write CR LF, `[Yes]` and CR LF.", func(t *testing.T) {
		t.Parallel()
		t.Run("AYT during negotiation, before the answers: the answer before the greeting", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			call.expectNext(t, opening, call.connected.Add(progressLimit))
			call.send(t, command(ayt))
			call.expectNext(t, []byte(aytAnswer), time.Now().Add(progressLimit))
			call.send(t, answers)
			call.expectNext(t, asked, time.Now().Add(progressLimit))
			call.send(t, []byte("n\r"))
			call.expectEndNext(t, echoed("n"), time.Now().Add(progressLimit))
		})
		rows := []nameRow{
			{name: "a, AYT, b mid-name, ECHO agreed: the answer in its place among the echo", answer: answers,
				typed: join([]byte("a"), command(ayt), []byte("b\r")), after: join([]byte("a"+aytAnswer+"b\r\n"), helloTo("ab"))},
			{name: "AYT at the prompt, ECHO refused: the answer all the same", answer: refused,
				typed: join(command(ayt), []byte("b\r")), after: join([]byte(aytAnswer), helloTo("b"))},
			{name: "AYT three times: three answers", answer: answers,
				typed: join(repeated(command(ayt), 3), []byte("b\r")), after: join([]byte(strings.Repeat(aytAnswer, 3)+"b\r\n"), helloTo("b"))},
			{name: "the edge: AYT after the name ends: no answer", answer: answers,
				typed: join([]byte("b\r"), command(ayt)), after: echoed("b")},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				runNameRow(t, row)
			})
		}
	})
	t.Run("When a Telnet caller sends AO or IP before its name ends, the engine shall send IAC DM, with DM as TCP urgent data.", func(t *testing.T) {
		t.Parallel()
		t.Run("AO during negotiation, before the answers: IAC, then DM urgent, before the greeting", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			call.expectNext(t, opening, call.connected.Add(progressLimit))
			call.send(t, command(abortOutput))
			call.expectSynchNext(t, nil, time.Now().Add(progressLimit))
			call.send(t, answers)
			call.expectNext(t, asked, time.Now().Add(progressLimit))
			call.send(t, []byte("n\r"))
			call.expectEndNext(t, echoed("n"), time.Now().Add(progressLimit))
		})
		for _, code := range []byte{abortOutput, interruptProcess} {
			t.Run(fmt.Sprintf("a, IAC %d, b mid-name, ECHO agreed: a, the Synch, then b and the name whole", code), func(t *testing.T) {
				t.Parallel()
				call := commandCall(t, answers)
				call.send(t, join([]byte("a"), command(code)))
				call.expectSynchNext(t, []byte("a"), time.Now().Add(progressLimit))
				call.send(t, []byte("b\r"))
				call.expectEndNext(t, join([]byte("b\r\n"), helloTo("ab")), time.Now().Add(progressLimit))
			})
		}
		t.Run("IP at the prompt, ECHO refused: the Synch all the same", func(t *testing.T) {
			t.Parallel()
			call := commandCall(t, refused)
			call.send(t, command(interruptProcess))
			call.expectSynchNext(t, nil, time.Now().Add(progressLimit))
			call.send(t, []byte("b\r"))
			call.expectEndNext(t, helloTo("b"), time.Now().Add(progressLimit))
		})
		t.Run("the edge: AO after the name ends: no Synch", func(t *testing.T) {
			t.Parallel()
			call := commandCall(t, answers)
			call.send(t, join([]byte("b\r"), command(abortOutput)))
			call.expectEndNext(t, echoed("b"), time.Now().Add(progressLimit))
		})
	})
	t.Run("When a Telnet caller sends EC after negotiation and before its name ends, the engine shall do as it does for BS.", func(t *testing.T) {
		t.Parallel()
		rows := []nameRow{
			{name: "ab, EC, c, ECHO agreed: BS, space, BS for b, then Hello ac", answer: answers,
				typed: join([]byte("ab"), command(eraseCharacter), []byte("c\r")), after: join([]byte("ab"), erase, []byte("c\r\n"), helloTo("ac"))},
			{name: "ab, EC, c, ECHO refused: nothing echoed, Hello ac", answer: refused,
				typed: join([]byte("ab"), command(eraseCharacter), []byte("c\r")), after: helloTo("ac")},
			{name: "ab, EC twice and BS: the name emptied, then c", answer: answers,
				typed: join([]byte("ab"), command(eraseCharacter), command(eraseCharacter), []byte{backspace}, []byte("c\r")),
				after: join([]byte("ab"), erase, erase, []byte("c\r\n"), helloTo("c"))},
			{name: "30 characters, EC, y, ECHO agreed: BS, space, BS, then Hello the first 29 and y", answer: answers,
				typed: join([]byte(strings.Repeat("x", nameMost)), command(eraseCharacter), []byte("y\r")),
				after: join([]byte(strings.Repeat("x", nameMost)), erase, []byte("y\r\n"), helloTo(strings.Repeat("x", nameMost-1)+"y"))},
			{name: "30 characters, EC, y, ECHO refused: Hello the first 29 and y", answer: refused,
				typed: join([]byte(strings.Repeat("x", nameMost)), command(eraseCharacter), []byte("y\r")),
				after: helloTo(strings.Repeat("x", nameMost-1) + "y")},
			{name: "EC on an empty name: nothing written, then n", answer: answers,
				typed: join(command(eraseCharacter), []byte("n\r")), after: echoed("n")},
			{name: "EC during negotiation does nothing to the name: x and EC before the answers", answer: join([]byte("x"), command(eraseCharacter), answers),
				typed: []byte("ab\r"), after: echoed("ab")},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				runNameRow(t, row)
			})
		}
	})
	t.Run("When a Telnet caller sends EL after negotiation and before its name ends, the engine shall remove every character of the name, writing BS, space, BS for each while it echoes.", func(t *testing.T) {
		t.Parallel()
		thirty := strings.Repeat("x", nameMost)
		rows := []nameRow{
			{name: "abc, EL, d, ECHO agreed: three groups, then Hello d", answer: answers,
				typed: join([]byte("abc"), command(eraseLine), []byte("d\r")), after: join([]byte("abc"), repeated(erase, 3), []byte("d\r\n"), helloTo("d"))},
			{name: "abc, EL, d, ECHO refused: nothing echoed, Hello d", answer: refused,
				typed: join([]byte("abc"), command(eraseLine), []byte("d\r")), after: helloTo("d")},
			{name: "30 characters, EL, then 30 more: thirty groups, Hello the second thirty", answer: answers,
				typed: join([]byte(thirty), command(eraseLine), []byte(strings.Repeat("y", nameMost)+"\r")),
				after: join([]byte(thirty), repeated(erase, nameMost), []byte(strings.Repeat("y", nameMost)+"\r\n"), helloTo(strings.Repeat("y", nameMost)))},
			{name: "EL on an empty name: nothing written, then n", answer: answers,
				typed: join(command(eraseLine), []byte("n\r")), after: echoed("n")},
			{name: "EL during negotiation does nothing to the name: x and EL before the answers", answer: join([]byte("x"), command(eraseLine), answers),
				typed: []byte("ab\r"), after: echoed("ab")},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				runNameRow(t, row)
			})
		}
	})
	t.Run("When a Telnet caller sends DM, NOP, GA, BRK, EOR or any other command, the engine shall discard it without reply, and discard none of the data before it.", func(t *testing.T) {
		t.Parallel()
		var rows []nameRow
		for _, code := range []byte{dataMark, nop, goAhead, breakCommand, endOfRecord, subnegotiationEnd, 0, 1, 100, 238} {
			rows = append(rows, nameRow{name: fmt.Sprintf("ab, IAC %d, cd mid-name: no reply, Hello abcd", code), answer: answers,
				typed: join([]byte("ab"), command(code), []byte("cd\r")), after: echoed("abcd")})
		}
		rows = append(rows,
			nameRow{name: "a, IAC DM, b, ECHO refused: no reply, Hello ab", answer: refused,
				typed: join([]byte("a"), command(dataMark), []byte("b\r")), after: helloTo("ab")},
			nameRow{name: "DM, NOP, GA, BRK and EOR during negotiation, before the answers: no reply", answer: join(command(dataMark), command(nop), command(goAhead), command(breakCommand), command(endOfRecord), answers),
				typed: []byte("ab\r"), after: echoed("ab")})
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				runNameRow(t, row)
			})
		}
	})
	t.Run("When the caller sends Ctrl-U (0x15) while the name holds a character, the engine shall remove every character of the name.", func(t *testing.T) {
		t.Parallel()
		thirty := strings.Repeat("x", nameMost)
		rows := []nameRow{
			{name: "abc, Ctrl-U, d, ECHO agreed: three groups, then Hello d", answer: answers,
				typed: []byte("abc\x15d\r"), after: join([]byte("abc"), repeated(erase, 3), []byte("d\r\n"), helloTo("d"))},
			{name: "abc, Ctrl-U, d, ECHO refused: nothing echoed, Hello d", answer: refused,
				typed: []byte("abc\x15d\r"), after: helloTo("d")},
			{name: "30 characters, Ctrl-U, e: thirty groups, Hello e", answer: answers,
				typed: join([]byte(thirty), []byte{eraseLineKey}, []byte("e\r")), after: join([]byte(thirty), repeated(erase, nameMost), []byte("e\r\n"), helloTo("e"))},
			{name: "a, BS, b, Ctrl-U twice, c: one group for b, nothing for the second, Hello c", answer: answers,
				typed: []byte("a\x08b\x15\x15c\r"), after: join([]byte("a"), erase, []byte("b"), erase, []byte("c\r\n"), helloTo("c"))},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				runNameRow(t, row)
			})
		}
	})
	t.Run("The engine shall not store, log or show anything a caller sends inside a subnegotiation.", func(t *testing.T) {
		t.Parallel()
		marker := "subnegotiation-marker"
		reports := join(
			[]byte{iac, subnegotiationBegin, telnetTypeOption, 0}, []byte(marker), command(subnegotiationEnd),
			[]byte{iac, subnegotiationBegin, environOption, 0, 0}, []byte("USER"), []byte{1}, []byte(marker), command(subnegotiationEnd),
			[]byte{iac, subnegotiationBegin, windowSizeOption, 0, 80, 0, 24, iac, subnegotiationEnd})
		rows := []nameRow{
			{name: "a TTYPE IS, a NEW-ENVIRON IS and a NAWS mid-name, ECHO agreed: none of it shown, Hello ab", answer: agreed,
				typed: join([]byte("a"), reports, []byte("b\r")), after: echoed("ab")},
			{name: "the same during negotiation, before the answers: none of it shown", answer: join(reports, answers),
				typed: []byte("ab\r"), after: echoed("ab")},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				call, stream, _ := answeredCall(t, row.answer, nil, patient(5*time.Second))
				stream.waitFor(t, bytes.Index(join(opening, sendsFor(row.answer), asked), asked)+len(asked), time.Now().Add(progressLimit))
				call.send(t, row.typed)
				stream.expectStream(t, join(opening, sendsFor(row.answer), asked, row.after))
				if bytes.Contains(stream.received, []byte(marker)) {
					t.Fatalf("the stream shows what the caller sent inside a subnegotiation")
				}
			})
		}
	})
	t.Run("The engine shall write the same to a caller, whatever it sends inside a subnegotiation.", func(t *testing.T) {
		t.Parallel()
		insides := map[string][]byte{
			"nothing":        {windowSizeOption},
			"TTYPE IS XTERM": join([]byte{telnetTypeOption, 0}, []byte("XTERM")),
			"TTYPE IS VT100": join([]byte{telnetTypeOption, 0}, []byte("VT100")),
			"NAWS of 0 by 0": {windowSizeOption, 0, 0, 0, 0},
			"NAWS of 65535 by 65535, each 255 doubled": join([]byte{windowSizeOption}, repeated(command(iac), 4)),
			"NEW-ENVIRON IS USER and a name":           join([]byte{environOption, 0, 0}, []byte("USER"), []byte{1}, []byte("sysop")),
			"10000 bytes":                              join([]byte{telnetTypeOption}, repeated([]byte("0123456789"), 1000)),
			"escape codes and line breaks":             join([]byte{telnetTypeOption}, []byte("\x1b[2J\x1b[31m\r\n\x08\x15\x7f")),
			"an option never agreed, 99":               {99, 1, 2, 3},
			"requests and commands inside":             join([]byte{telnetTypeOption}, request(doVerb, telnetTypeOption), command(ayt), command(abortOutput), command(eraseLine), request(dont, echo)),
		}
		for name, inside := range insides {
			t.Run("mid-name, "+name+": the stream of a call with none", func(t *testing.T) {
				t.Parallel()
				subnegotiation := join([]byte{iac, subnegotiationBegin}, inside, command(subnegotiationEnd))
				runNameRow(t, nameRow{answer: answers, typed: join([]byte("a"), subnegotiation, []byte("b\r")), after: echoed("ab")})
			})
			t.Run("during negotiation, "+name+": the stream of a call with none", func(t *testing.T) {
				t.Parallel()
				subnegotiation := join([]byte{iac, subnegotiationBegin}, inside, command(subnegotiationEnd))
				runNameRow(t, nameRow{answer: join(subnegotiation, answers), typed: []byte("ab\r"), after: echoed("ab")})
			})
		}
	})
}

// sendsFor is the SENDs a caller's answers draw, in the order the answers agree.
func sendsFor(answer []byte) []byte {
	var sends []byte
	sent := map[byte]bool{}
	for index := 0; index+2 < len(answer); index++ {
		if answer[index] != iac || answer[index+1] != will || sent[answer[index+2]] {
			continue
		}
		switch answer[index+2] {
		case telnetTypeOption:
			sends = append(sends, terminalTypeSend...)
		case environOption:
			sends = append(sends, environSend...)
		case speedOption:
			sends = append(sends, speedSend...)
		default:
			continue
		}
		sent[answer[index+2]] = true
	}
	return sends
}
