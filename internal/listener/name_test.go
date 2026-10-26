// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests of the call through the Listener on real loopback sockets once negotiation ends: the
// greeting and the prompt, the name a caller types and what it may hold, the echo, correcting a
// name, Hello and the name, the 60 seconds for the name, the 70-second ceiling on the whole call,
// urgent data kept in line, and how the call ends.
package listener_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/listener"
	"github.com/heliosestate/heliosadvance/internal/telnet"
)

// The page's prompt and limits, written here so a changed constant in the engine cannot move a
// test with it.
const (
	prompt            = "What is your name? "
	reply             = "Hello "
	nameLimit         = 60 * time.Second
	ceilingLimit      = 70 * time.Second
	nameMost          = 30
	dataMark     byte = 242
	backspace    byte = 0x08
	del          byte = 0x7F
	nul          byte = 0x00
)

// The answers that leave ECHO agreed, and those that leave it refused.
var (
	refused = join(request(dont, echo), request(doVerb, sga))
	asked   = join([]byte(greeting), []byte(prompt))
)

// echoOf is what the engine echoes for a name ended by CR or LF, ECHO agreed.
func echoOf(name string) []byte {
	return join([]byte(name), []byte("\r\n"))
}

// helloTo is the engine's answer to a name.
func helloTo(name string) []byte {
	return []byte(reply + name + "\r\n")
}

// echoed is what a caller with ECHO agreed receives after the prompt for a name typed plainly.
func echoed(name string) []byte {
	return join(echoOf(name), helloTo(name))
}

// answeredCall dials, starts recording, and sends the answers and the bytes after them in one
// write. It returns the caller, the recording and when the write began and returned.
func answeredCall(t *testing.T, answer, after []byte, record time.Duration) (caller, *recording, sending) {
	t.Helper()
	call := dial(t, startEngine(t, 1)[0])
	stream := call.record(call.connected.Add(record))
	sent := call.send(t, join(answer, after))
	return call, stream, sent
}

// promptAt is when the prompt's last byte arrived, the stream holding the opening, any replies,
// the greeting and the prompt from offset start.
func (stream *recording) byteAt(t *testing.T, offset int) time.Time {
	t.Helper()
	return stream.arrivedAt(t, offset)
}

// expectAskedAt checks the greeting and the prompt start at offset and arrived together in their
// window.
func (stream *recording) expectAskedAt(t *testing.T, offset int, notBefore, notAfter time.Time) {
	t.Helper()
	expectWithin(t, "the greeting", stream.byteAt(t, offset), notBefore, notAfter)
	expectWithin(t, "the prompt's last byte", stream.byteAt(t, offset+len(asked)-1), notBefore, notAfter)
}

// waitFor blocks until the stream holds at least count bytes, or the stream ends.
func (stream *recording) waitFor(t *testing.T, count int, deadline time.Time) []byte {
	t.Helper()
	for time.Now().Before(deadline) {
		stream.mutex.Lock()
		got := bytes.Clone(stream.received)
		ended := stream.end != nil
		stream.mutex.Unlock()
		if len(got) >= count || ended {
			return got
		}
		wait(t, time.Now().Add(5*time.Millisecond))
	}
	t.Fatalf("the caller had not received %d bytes by the deadline", count)
	return nil
}

// expectNameRows runs rows of a name typed after DO DO or after the refusal, each to the end of
// the call.
type nameRow struct {
	name   string
	answer []byte
	typed  []byte
	after  []byte
}

func runNameRow(t *testing.T, row nameRow) {
	t.Helper()
	call, stream, _ := answeredCall(t, row.answer, nil, 5*time.Second)
	stream.waitFor(t, len(opening)+len(asked), time.Now().Add(progressLimit))
	call.send(t, row.typed)
	stream.expectStream(t, join(opening, asked, row.after))
}

func TestName(t *testing.T) {
	t.Parallel()
	t.Run("When a Telnet caller has answered both option requests, or 3 seconds after the engine sent them, whichever comes first, the engine shall write `Hello Helios Advance BBS!` and CR LF, then `What is your name? `.", func(t *testing.T) {
		t.Parallel()
		rows := []struct {
			name   string
			answer []byte
			echoes bool
		}{
			{name: "DO DO", answer: answers, echoes: true},
			{name: "DONT DONT", answer: join(request(dont, echo), request(dont, sga))},
			{name: "DO DONT", answer: join(request(doVerb, echo), request(dont, sga)), echoes: true},
			{name: "DONT DO", answer: refused},
		}
		for _, row := range rows {
			t.Run("answered "+row.name+": the greeting and the prompt at once, then nothing until a name", func(t *testing.T) {
				t.Parallel()
				call, stream, sent := answeredCall(t, row.answer, nil, 5*time.Second)
				stream.waitFor(t, len(opening)+len(asked), sent.done.Add(progressLimit))
				wait(t, time.Now().Add(quietFor))
				call.send(t, []byte("ann\r"))
				after := helloTo("ann")
				if row.echoes {
					after = echoed("ann")
				}
				stream.expectStream(t, join(opening, asked, after))
				// The nearest fault misses the answers, so the greeting waits for negotiation's 3
				// seconds from the dial.
				stream.expectAskedAt(t, len(opening), sent.began,
					windowEnd(t, sent.done, call.dialed.Add(negotiationLimit)))
			})
		}
		t.Run("a silent caller: the greeting and the prompt at 3 seconds", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			stream := call.record(call.connected.Add(negotiationLimit + 5*time.Second))
			stream.waitFor(t, len(opening)+len(asked), call.connected.Add(negotiationLimit+progressLimit))
			call.send(t, []byte("ann\r"))
			stream.expectStream(t, join(opening, asked, helloTo("ann")))
			stream.expectAskedAt(t, len(opening), call.dialed.Add(negotiationLimit), stream.arrivedAt(t, 0).Add(negotiationLimit+margin))
		})
		t.Run("one answer, then silence: the greeting and the prompt at 3 seconds", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			stream := call.record(call.connected.Add(negotiationLimit + 5*time.Second))
			call.send(t, request(doVerb, echo))
			stream.waitFor(t, len(opening)+len(asked), call.connected.Add(negotiationLimit+progressLimit))
			call.send(t, []byte("ann\r"))
			stream.expectStream(t, join(opening, asked, echoed("ann")))
			stream.expectAskedAt(t, len(opening), call.dialed.Add(negotiationLimit), stream.arrivedAt(t, 0).Add(negotiationLimit+margin))
		})
		t.Run("the second answer at 2 seconds: the greeting and the prompt then, not at 3", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			stream := call.record(call.connected.Add(negotiationLimit + 5*time.Second))
			call.send(t, request(doVerb, echo))
			wait(t, call.connected.Add(2*time.Second))
			sent := call.send(t, request(doVerb, sga))
			stream.waitFor(t, len(opening)+len(asked), sent.done.Add(progressLimit))
			call.send(t, []byte("ann\r"))
			stream.expectStream(t, join(opening, asked, echoed("ann")))
			// The nearest fault misses the answers, and its greeting at negotiation's 3 seconds
			// is only a second after this one: the window keeps margin.
			stream.expectAskedAt(t, len(opening), sent.began, sent.done.Add(margin))
		})
		t.Run("the answers a byte at a time, 50 ms apart: the greeting and the prompt after the last", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			stream := call.record(call.connected.Add(5 * time.Second))
			var lastSent sending
			for index := range answers {
				wait(t, time.Now().Add(50*time.Millisecond))
				lastSent = call.send(t, answers[index:index+1])
			}
			stream.waitFor(t, len(opening)+len(asked), lastSent.done.Add(progressLimit))
			call.send(t, []byte("ann\r"))
			stream.expectStream(t, join(opening, asked, echoed("ann")))
			// The nearest fault misses the answers, so the greeting waits for negotiation's 3
			// seconds from the dial.
			stream.expectAskedAt(t, len(opening), lastSent.began,
				windowEnd(t, lastSent.done, call.dialed.Add(negotiationLimit)))
		})
	})
	t.Run("When the caller ends the name with CR or LF, the engine shall write `Hello `, the name and CR LF.", func(t *testing.T) {
		t.Parallel()
		rows := []nameRow{
			{name: "refused ECHO, alice CR: Hello alice, no echo", answer: refused, typed: []byte("alice\r"), after: helloTo("alice")},
			{name: "refused ECHO, alice LF", answer: refused, typed: []byte("alice\n"), after: helloTo("alice")},
			{name: "refused ECHO, alice CR LF: one Hello", answer: refused, typed: []byte("alice\r\n"), after: helloTo("alice")},
			{name: "refused ECHO, alice CR NUL: one Hello", answer: refused, typed: []byte{'a', 'l', 'i', 'c', 'e', '\r', nul}, after: helloTo("alice")},
			{name: "ECHO agreed, alice CR: the echo, then Hello alice", answer: answers, typed: []byte("alice\r"), after: echoed("alice")},
			{name: "ECHO agreed, alice LF: the echo ends CR LF too", answer: answers, typed: []byte("alice\n"), after: echoed("alice")},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				runNameRow(t, row)
			})
		}
		t.Run("refused ECHO, the name a byte at a time, 20 ms apart", func(t *testing.T) {
			t.Parallel()
			call, stream, _ := answeredCall(t, refused, nil, 5*time.Second)
			for _, value := range []byte("bob\r") {
				wait(t, time.Now().Add(20*time.Millisecond))
				call.send(t, []byte{value})
			}
			stream.expectStream(t, join(opening, asked, helloTo("bob")))
		})
		t.Run("the name typed in the same write as the last answer", func(t *testing.T) {
			t.Parallel()
			_, stream, _ := answeredCall(t, answers, []byte("alice\r"), 5*time.Second)
			stream.expectStream(t, join(opening, asked, echoed("alice")))
		})
		t.Run("the name typed before the prompt, during the 3 seconds after the one answer", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			stream := call.record(call.connected.Add(negotiationLimit + 5*time.Second))
			call.readOpeningFrom(t, stream)
			call.send(t, request(doVerb, echo))
			wait(t, time.Now().Add(100*time.Millisecond))
			// Negotiation reads this as data and discards it; what comes after its end is the name.
			call.send(t, []byte("early"))
			wait(t, call.connected.Add(negotiationLimit+margin))
			call.send(t, []byte("late\r"))
			stream.expectStream(t, join(opening, asked, echoed("late")))
		})
	})
	t.Run("If the caller sends anything after the name ends, then the engine shall discard it without reply.", func(t *testing.T) {
		t.Parallel()
		rows := []nameRow{
			{name: "bob CR more CR in one write: one Hello", answer: refused, typed: []byte("bob\rmore\r"), after: helloTo("bob")},
			{name: "bob CR, then DO 24 and WILL 31 in the same write: no reply", answer: answers, typed: join([]byte("bob\r"), request(doVerb, telnetTypeOption), request(will, windowSizeOption)), after: echoed("bob")},
			{name: "bob LF, then BS and text: the name stays bob", answer: answers, typed: []byte("bob\n\x08\x08x\r"), after: echoed("bob")},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				runNameRow(t, row)
			})
		}
		t.Run("text and requests sent once Hello arrived: nothing more, and the engine takes them", func(t *testing.T) {
			t.Parallel()
			call, stream, _ := answeredCall(t, answers, []byte("bob\r"), 5*time.Second)
			stream.expectStream(t, join(opening, asked, echoed("bob")))
			call.send(t, join(request(doVerb, telnetTypeOption), request(will, windowSizeOption), []byte("text\r")))
			wait(t, time.Now().Add(200*time.Millisecond))
			call.send(t, make([]byte, 1024))
		})
	})
	t.Run("When `Hello <name>` is written to a Telnet caller, the engine shall shut down its sending side of the connection.", func(t *testing.T) {
		t.Parallel()
		for name, typed := range map[string]string{"CR": "bob\r", "LF": "bob\n"} {
			t.Run("a name ended by "+name+": end of stream at once after Hello, and the engine still takes what the caller sends", func(t *testing.T) {
				t.Parallel()
				call, stream, _ := answeredCall(t, refused, []byte(typed), 5*time.Second)
				stream.expectStream(t, join(opening, asked, helloTo("bob")))
				helloEnd := stream.arrivedAt(t, len(stream.received)-1)
				expectWithin(t, "end of stream", stream.ended, helloEnd, helloEnd.Add(margin))
				// A connection closed whole would answer these with a reset; one whose sending side
				// alone is shut takes them.
				call.send(t, make([]byte, 1024))
				wait(t, time.Now().Add(200*time.Millisecond))
				call.send(t, make([]byte, 1024))
			})
		}
	})
	t.Run("If the caller has not ended the name 60 seconds after the engine wrote `What is your name? `, then the engine shall close the connection without writing more.", func(t *testing.T) {
		t.Parallel()
		rows := []struct {
			name   string
			answer []byte
			typing func(call caller, start time.Time)
			after  []byte
		}{
			{name: "a caller silent after DO DO", answer: answers},
			{name: "a caller that refused ECHO typing a every 10 seconds, never ending: typing does not move the 60 seconds", answer: refused, typing: func(call caller, start time.Time) {
				for index := 1; index < 6; index++ {
					wait(t, start.Add(time.Duration(index)*10*time.Second))
					_, _ = call.connection.Write([]byte("a"))
				}
			}},
			{name: "a caller pressing CR alone every 10 seconds", answer: answers, typing: func(call caller, start time.Time) {
				for index := 1; index < 6; index++ {
					wait(t, start.Add(time.Duration(index)*10*time.Second))
					_, _ = call.connection.Write([]byte("\r"))
				}
			}},
		}
		for _, row := range rows {
			t.Run(row.name+": closed at 60 seconds, nothing after the prompt", func(t *testing.T) {
				t.Parallel()
				call, stream, sent := answeredCall(t, row.answer, nil, nameLimit+10*time.Second)
				stream.waitFor(t, len(opening)+len(asked), sent.done.Add(progressLimit))
				if row.typing != nil {
					go row.typing(call, sent.done)
				}
				stream.expectStream(t, join(opening, asked))
				promptEnd := stream.arrivedAt(t, len(opening)+len(asked)-1)
				expectWithin(t, "the close", stream.ended, sent.began.Add(nameLimit), promptEnd.Add(nameLimit+margin))
			})
		}
		t.Run("a caller with ECHO agreed typing ab, then silent: the echo of ab, then closed at 60 seconds", func(t *testing.T) {
			t.Parallel()
			_, stream, sent := answeredCall(t, answers, []byte("ab"), nameLimit+10*time.Second)
			stream.expectStream(t, join(opening, asked, []byte("ab")))
			promptEnd := stream.arrivedAt(t, len(opening)+len(asked)-1)
			expectWithin(t, "the close", stream.ended, sent.began.Add(nameLimit), promptEnd.Add(nameLimit+margin))
		})
	})
	t.Run("When the caller sends a character from space to tilde (0x20 to 0x7E) and the name holds fewer than 30, the engine shall add it to the name.", func(t *testing.T) {
		t.Parallel()
		var printable []byte
		for character := byte(0x20); character <= 0x7E; character++ {
			printable = append(printable, character)
		}
		for start := 0; start < len(printable); start += nameMost {
			part := string(printable[start:min(start+nameMost, len(printable))])
			t.Run(fmt.Sprintf("the printable characters from %#02x, %d of them", printable[start], len(part)), func(t *testing.T) {
				t.Parallel()
				runNameRow(t, nameRow{answer: answers, typed: []byte(part + "\r"), after: echoed(part)})
			})
		}
		rows := []nameRow{
			{name: "a name of one space", answer: answers, typed: []byte(" \r"), after: echoed(" ")},
			{name: "leading and trailing spaces kept", answer: refused, typed: []byte("  a b  \r"), after: helloTo("  a b  ")},
			{name: "exactly 30 characters, the edge just inside the limit", answer: answers, typed: []byte(strings.Repeat("x", nameMost-1) + "y\r"), after: echoed(strings.Repeat("x", nameMost-1) + "y")},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				runNameRow(t, row)
			})
		}
	})
	t.Run("Apart from BS, DEL, CR and LF, the engine shall drop every other byte the caller sends after negotiation or, over SSH, after `shell`, and every character past the 30th.", func(t *testing.T) {
		t.Parallel()
		var others []byte
		for code := range 255 {
			value := byte(code)
			isPrintable := value >= 0x20 && value <= 0x7E
			if !isPrintable && value != backspace && value != del && value != '\r' && value != '\n' {
				others = append(others, value)
			}
		}
		thirty := strings.Repeat("x", nameMost)
		rows := []nameRow{
			{name: "31 characters: the first 30", answer: answers, typed: []byte(thirty + "y\r"), after: echoed(thirty)},
			{name: "40 characters, BS, then z: the first 29 and z", answer: answers, typed: []byte(thirty + "0123456789\x08z\r"),
				after: join([]byte(thirty), []byte{backspace, ' ', backspace}, []byte("z\r\n"), helloTo(thirty[:nameMost-1]+"z"))},
			{name: "every byte from 0x00 to 0xFE that is not printable, BS, DEL, CR or LF, between a and b: dropped, never echoed", answer: answers, typed: join([]byte("a"), others, []byte("b\r")), after: echoed("ab")},
			{name: "the same with ECHO refused", answer: refused, typed: join([]byte("a"), others, []byte("b\r")), after: helloTo("ab")},
			{name: "ESC sequences: ESC dropped, the rest kept as typed", answer: answers, typed: []byte("a\x1b[2J\x1b[31mb\r"), after: echoed("a[2J[31mb")},
			{name: "0x9B, BEL, NUL and TAB: dropped", answer: answers, typed: []byte{'a', 0x9B, 0x07, nul, '\t', 'b', '\r'}, after: echoed("ab")},
			{name: "a doubled IAC, the data byte 255: dropped, never echoed", answer: answers, typed: []byte{'a', iac, iac, 'b', '\r'}, after: echoed("ab")},
			{name: "data bytes sent during negotiation do not reach the name", answer: join([]byte("junk"), answers), typed: []byte("ok\r"), after: echoed("ok")},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				runNameRow(t, row)
			})
		}
	})
	t.Run("After negotiation ends and until a Telnet caller's name ends, the engine shall answer each option request as it did during negotiation, and discard every other Telnet command without reply.", func(t *testing.T) {
		t.Parallel()
		rows := []nameRow{
			{name: "ab, DO 24, c CR: WONT 24 in its place among the echo", answer: answers, typed: join([]byte("ab"), request(doVerb, telnetTypeOption), []byte("c\r")),
				after: join([]byte("ab"), request(wont, telnetTypeOption), []byte("c\r\n"), helloTo("abc"))},
			{name: "WILL 31 mid-name: DONT 31", answer: answers, typed: join([]byte("a"), request(will, windowSizeOption), []byte("b\r")),
				after: join([]byte("a"), request(dont, windowSizeOption), []byte("b\r\n"), helloTo("ab"))},
			{name: "WONT 24 and DONT 24 mid-name: no reply", answer: answers, typed: join([]byte("a"), request(wont, telnetTypeOption), request(dont, telnetTypeOption), []byte("b\r")), after: echoed("ab")},
			{name: "DO 0 and DO 255 mid-name: WONT each", answer: refused, typed: join([]byte("a"), request(doVerb, 0), request(doVerb, 255), []byte("b\r")),
				after: join(request(wont, 0), request(wont, 255), helloTo("ab"))},
			{name: "DO ECHO and DO SGA again, already agreed: no reply", answer: answers, typed: join([]byte("a"), request(doVerb, echo), request(doVerb, sga), []byte("b\r")), after: echoed("ab")},
			{name: "IAC NOP, IAC AYT and a subnegotiation holding IAC IAC SE mid-name: discarded, the name unbroken", answer: answers,
				typed: join([]byte("a"), []byte{iac, nop, iac, ayt}, []byte{iac, subnegotiationBegin, telnetTypeOption, 'q', iac, iac, subnegotiationEnd, 'r', iac, subnegotiationEnd}, []byte("b\r")), after: echoed("ab")},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				runNameRow(t, row)
			})
		}
		t.Run("a request split across negotiation's end: its last byte after the 3 seconds, answered once", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			stream := call.record(call.connected.Add(negotiationLimit + 5*time.Second))
			call.send(t, join(request(doVerb, echo), []byte{iac, doVerb}))
			stream.waitFor(t, len(opening)+len(asked), call.connected.Add(negotiationLimit+progressLimit))
			call.send(t, []byte{telnetTypeOption, 'k', '\r'})
			stream.expectStream(t, join(opening, asked, request(wont, telnetTypeOption), echoed("k")))
		})
		t.Run("a request sent as the 3 seconds pass: answered once, whichever side of the end it falls", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			stream := call.record(call.connected.Add(negotiationLimit + 5*time.Second))
			call.send(t, request(doVerb, echo))
			wait(t, call.connected.Add(negotiationLimit-5*time.Millisecond))
			call.send(t, request(doVerb, telnetTypeOption))
			wait(t, call.connected.Add(negotiationLimit+margin))
			call.send(t, []byte("k\r"))
			// Before the end, its reply comes before the greeting; after it, among the name.
			got := stream.waitFor(t, 1<<20, time.Now().Add(2*margin))
			before := join(opening, request(wont, telnetTypeOption), asked, echoed("k"))
			after := join(opening, asked, request(wont, telnetTypeOption), echoed("k"))
			if !bytes.Equal(got, before) && !bytes.Equal(got, after) {
				t.Fatalf("the stream was\n% x\nwant one WONT 24 before or after the greeting", got)
			}
		})
		t.Run("a caller that floods and reads only after the 3 seconds: every reply whole and once, the greeting and the prompt after a reply still waiting at the 3 seconds, then the name", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			wait(t, call.connected.Add(time.Second))
			floodNumbered(t, call, []byte("k\r"))
			wait(t, call.connected.Add(negotiationLimit+margin))
			stream := call.recordBulk(call.connected.Add(40 * time.Second))
			<-stream.done
			got := stream.received
			if !bytes.HasPrefix(got, opening) || !bytes.HasSuffix(got, helloTo("k")) {
				t.Fatalf("the stream did not run from the opening to Hello k: %v", stream.end)
			}
			askedAt := bytes.Index(got, asked)
			if askedAt < 0 || (askedAt-len(opening))%3 != 0 {
				t.Fatalf("the greeting and the prompt are not whole between whole replies")
			}
			// Some requests are answered before the greeting, by negotiation, the rest after it by
			// the Line; together they are every request sent, each once, in order.
			replies := join(got[len(opening):askedAt], got[askedAt+len(asked):len(got)-len(helloTo("k"))])
			answered := expectNumberedReplies(t, replies)
			t.Logf("%d replies before the greeting, %d after", (askedAt-len(opening))/3, answered-(askedAt-len(opening))/3)
		})
	})
	t.Run("While a Telnet caller has agreed to ECHO, the engine shall echo each character it adds to the name, write BS, space, BS for each it removes, and write CR LF when the name ends.", func(t *testing.T) {
		t.Parallel()
		rows := []nameRow{
			{name: "abc CR", answer: answers, typed: []byte("abc\r"), after: echoed("abc")},
			{name: "abx BS c CR", answer: answers, typed: []byte("abx\x08c\r"), after: join([]byte("abx\x08 \x08c\r\n"), helloTo("abc"))},
			{name: "abx DEL c CR", answer: answers, typed: []byte("abx\x7fc\r"), after: join([]byte("abx\x08 \x08c\r\n"), helloTo("abc"))},
			{name: "a caller that refused turns ECHO on mid-name: WILL ECHO, then the echo", answer: refused,
				typed: join([]byte("a"), request(doVerb, echo), []byte("b\r")), after: join(request(will, echo), []byte("b\r\n"), helloTo("ab"))},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				runNameRow(t, row)
			})
		}
		t.Run("a late yes: DO ECHO after the 3 seconds, no reply, the echo from the next character", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			stream := call.record(call.connected.Add(negotiationLimit + 5*time.Second))
			stream.waitFor(t, len(opening)+len(asked), call.connected.Add(negotiationLimit+progressLimit))
			call.send(t, join([]byte("a"), request(doVerb, echo), []byte("b\r")))
			stream.expectStream(t, join(opening, asked, []byte("b\r\n"), helloTo("ab")))
		})
	})
	t.Run("While a Telnet caller has not agreed to ECHO, the engine shall echo nothing.", func(t *testing.T) {
		t.Parallel()
		rows := []nameRow{
			{name: "refused: abc BS d CR", answer: refused, typed: []byte("abc\x08d\r"), after: helloTo("abd")},
			{name: "agreed, then DONT ECHO after ab: WONT ECHO, then no echo", answer: answers,
				typed: join([]byte("ab"), request(dont, echo), []byte("c\x08d\r")), after: join([]byte("ab"), request(wont, echo), helloTo("abd"))},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				runNameRow(t, row)
			})
		}
		t.Run("a caller silent through negotiation", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			stream := call.record(call.connected.Add(negotiationLimit + 5*time.Second))
			stream.waitFor(t, len(opening)+len(asked), call.connected.Add(negotiationLimit+progressLimit))
			call.send(t, []byte("abc\x08d\r"))
			stream.expectStream(t, join(opening, asked, helloTo("abd")))
		})
	})
	t.Run("When the caller sends BS or DEL while the name holds a character, the engine shall remove the last character.", func(t *testing.T) {
		t.Parallel()
		thirty := strings.Repeat("x", nameMost)
		rows := []nameRow{
			{name: "abc BS", answer: refused, typed: []byte("abc\x08\r"), after: helloTo("ab")},
			{name: "abc DEL DEL", answer: refused, typed: []byte("abc\x7f\x7f\r"), after: helloTo("a")},
			{name: "30 characters, BS, y", answer: refused, typed: []byte(thirty + "\x08y\r"), after: helloTo(thirty[:nameMost-1] + "y")},
			{name: "BS among dropped bytes", answer: refused, typed: []byte("ab\x01\x08\x02c\r"), after: helloTo("ac")},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				runNameRow(t, row)
			})
		}
	})
	t.Run("If the caller sends BS, DEL, CR or LF while the name is empty, then the engine shall write nothing and keep waiting.", func(t *testing.T) {
		t.Parallel()
		for name, key := range map[string]byte{"BS": backspace, "DEL": del, "CR": '\r', "LF": '\n'} {
			t.Run(name+" alone, ECHO agreed: nothing written, then a CR: the echo and Hello a", func(t *testing.T) {
				t.Parallel()
				call, stream, sent := answeredCall(t, answers, nil, 5*time.Second)
				stream.waitFor(t, len(opening)+len(asked), sent.done.Add(progressLimit))
				call.send(t, []byte{key})
				wait(t, time.Now().Add(quietFor))
				call.send(t, []byte("a\r"))
				stream.expectStream(t, join(opening, asked, echoed("a")))
			})
		}
		runNameRow(t, nameRow{answer: answers, typed: []byte("a\x08\x08\ra\r"), after: join([]byte("a\x08 \x08"), echoed("a"))})
	})
	t.Run("If 70 seconds pass since it accepted a connection, then the engine shall close that connection.", func(t *testing.T) {
		t.Parallel()
		ceilingRows(t)
	})
	t.Run("Accept shall keep the caller's urgent data in line, so that a Synch, IAC with DM sent as urgent data, reaches negotiation whole and, after negotiation, the caller's next character after it is read as data.", func(t *testing.T) {
		t.Parallel()
		t.Run("ab, IAC, DM as urgent data, c CR, after negotiation: Hello abc", func(t *testing.T) {
			t.Parallel()
			call, stream, sent := answeredCall(t, refused, nil, 5*time.Second)
			stream.waitFor(t, len(opening)+len(asked), sent.done.Add(progressLimit))
			call.send(t, []byte{'a', 'b', iac})
			if err := sendUrgent(call.connection, dataMark); err != nil {
				t.Fatalf("sending urgent data: %v", err)
			}
			call.send(t, []byte("c\r"))
			stream.expectStream(t, join(opening, asked, helloTo("abc")))
		})
		t.Run("a Synch during negotiation, before the answers: the answers read whole", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			stream := call.record(call.connected.Add(5 * time.Second))
			stream.waitFor(t, len(opening), call.connected.Add(progressLimit))
			call.send(t, []byte{iac})
			if err := sendUrgent(call.connection, dataMark); err != nil {
				t.Fatalf("sending urgent data: %v", err)
			}
			sent := call.send(t, answers)
			stream.waitFor(t, len(opening)+len(asked), sent.done.Add(progressLimit))
			call.send(t, []byte("ab\r"))
			stream.expectStream(t, join(opening, asked, echoed("ab")))
			// The nearest fault misses the answers, so the greeting waits for negotiation's 3
			// seconds from the dial.
			stream.expectAskedAt(t, len(opening), sent.began,
				windowEnd(t, sent.done, call.dialed.Add(negotiationLimit)))
		})
	})
	t.Run("When Run returns session.Answered, the listener package shall call the KindConnection's Close once, under the connection's context, and then close the connection.", func(t *testing.T) {
		t.Parallel()
		t.Run("callers that close once Hello arrives: their places are free at once", func(t *testing.T) {
			t.Parallel()
			address := startEngine(t, 1)[0]
			var closed time.Time
			var lastSent sending
			for range connectionCap {
				call := dial(t, address)
				stream := call.record(call.connected.Add(progressLimit))
				lastSent = call.send(t, join(answers, []byte("n\r")))
				stream.expectStream(t, join(opening, asked, echoed("n")))
				_ = call.connection.Close()
				closed = time.Now()
			}
			// The nearest fault frees a place only when the last caller's closing wait's 3
			// seconds end, and that wait began no sooner than its write.
			expectServedBy(t, address, windowEnd(t, closed, lastSent.began.Add(closingWaitLimit)))
		})
		t.Run("a caller that stays: closed 3 seconds after the shutdown, not before, its bytes read meanwhile", func(t *testing.T) {
			t.Parallel()
			call, stream, sent := answeredCall(t, answers, []byte("n\r"), 5*time.Second)
			stream.expectStream(t, join(opening, asked, echoed("n")))
			shutAt := stream.ended
			// Bytes sent during the closing wait are read, so the close comes as no reset until it.
			// The window opens 3 seconds after the name's CR went, a moment provably before the
			// engine's shutdown: the caller's own sight of the shutdown can lag it on a loaded
			// runner (ubuntu-24.04-arm, 2026-10-25, 74 ms early by that sight).
			closedAt := call.awaitReset(t, shutAt.Add(closingWaitLimit+2*margin))
			expectWithin(t, "the close", closedAt, sent.began.Add(closingWaitLimit), shutAt.Add(closingWaitLimit+margin))
		})
		t.Run("Hello after 68 seconds: closed at the ceiling, not 3 seconds after the shutdown", func(t *testing.T) {
			t.Parallel()
			clampRows(t)
		})
	})
	t.Run("When Open returns an error or a nil KindConnection, or Run returns anything but session.Answered, the listener package shall close the connection without writing to it and without calling Close.", func(t *testing.T) {
		t.Parallel()
		t.Run("a caller that closes during negotiation: nothing after the opening", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			stream := call.record(call.connected.Add(5 * time.Second))
			call.send(t, request(doVerb, echo))
			_ = call.connection.CloseWrite()
			stream.expectStream(t, opening)
		})
		t.Run("a caller that closes mid-name: nothing after its close, and its place free", func(t *testing.T) {
			t.Parallel()
			address := startEngine(t, 1)[0]
			for range connectionCap {
				call := dial(t, address)
				stream := call.record(call.connected.Add(5 * time.Second))
				call.send(t, join(refused, []byte("ab")))
				stream.waitFor(t, len(opening)+len(asked), time.Now().Add(progressLimit))
				_ = call.connection.CloseWrite()
				stream.expectStream(t, join(opening, asked))
			}
			// The nearest fault misses the close and holds the place for the name's 60 seconds.
			expectServedBy(t, address, time.Now().Add(wideMargin))
		})
		t.Run("a caller that resets mid-name: its place free", func(t *testing.T) {
			t.Parallel()
			address := startEngine(t, 1)[0]
			for range connectionCap {
				call := dial(t, address)
				call.send(t, join(refused, []byte("ab")))
				call.readOpening(t, time.Now().Add(progressLimit))
				_ = call.connection.SetLinger(0)
				_ = call.connection.Close()
			}
			// The nearest fault misses the close and holds the place for the name's 60 seconds.
			expectServedBy(t, address, time.Now().Add(wideMargin))
		})
		t.Run("a caller that half-closes mid-name: closed at once, with no closing wait", func(t *testing.T) {
			t.Parallel()
			call, stream, _ := answeredCall(t, refused, []byte("ab"), 5*time.Second)
			stream.waitFor(t, len(opening)+len(asked), time.Now().Add(progressLimit))
			closedAt := time.Now()
			_ = call.connection.CloseWrite()
			stream.expectStream(t, join(opening, asked))
			expectWithin(t, "the engine's end", stream.ended, closedAt, closedAt.Add(margin))
		})
		t.Run("NoName at 60 seconds: closed then, with no closing wait", func(t *testing.T) {
			t.Parallel()
			call, stream, _ := answeredCall(t, answers, nil, nameLimit+negotiationLimit+5*time.Second)
			stream.waitFor(t, len(opening)+len(asked), time.Now().Add(progressLimit))
			promptAt := stream.byteAt(t, len(opening)+len(asked)-1)
			// Whatever the caller sends after the 60 seconds meets a closed connection, not a
			// closing wait that would take it.
			closedAt := call.awaitReset(t, promptAt.Add(nameLimit+2*margin))
			expectWithin(t, "the close", closedAt, call.connected.Add(nameLimit), promptAt.Add(nameLimit+margin))
		})
		t.Run("an Open that runs the real Accept and returns a nil KindConnection: closed at once after the opening, no greeting", func(t *testing.T) {
			t.Parallel()
			nilOpen := func(ctx context.Context, connection *net.TCPConn) (listener.KindConnection, error) {
				if _, err := telnet.Accept(ctx, connection); err != nil {
					return nil, err
				}
				return nil, nil
			}
			call := dial(t, startKind(t, 1, nilOpen)[0])
			stream := call.record(call.connected.Add(5 * time.Second))
			sent := call.send(t, answers)
			stream.expectStream(t, opening)
			expectWithin(t, "the engine's end", stream.ended, sent.began, sent.done.Add(margin))
		})
	})
	t.Run("When the connection's context ends, the listener package shall close the connection at once.", func(t *testing.T) {
		t.Parallel()
		t.Run("Stop with a silent caller and one in Close's wait: both closed at once", func(t *testing.T) {
			t.Parallel()
			engine, addresses := startListener(t, 1, openTelnet)
			closing := dial(t, addresses[0])
			closingStream := closing.record(closing.connected.Add(10 * time.Second))
			closingSent := closing.send(t, join(answers, []byte("n\r")))
			// End of stream is the shutdown: the closing caller is now in Close's wait.
			closingStream.expectStream(t, join(opening, asked, echoed("n")))
			// The silent caller comes second, so that nothing it does can hold back the closing
			// caller's call and start the closing wait later than its write.
			silent := dial(t, addresses[0])
			silentStream := silent.record(silent.connected.Add(10 * time.Second))
			silentStream.waitFor(t, len(opening), time.Now().Add(progressLimit))
			stoppedAt := time.Now()
			// The nearest fault leaves a call open until its closing wait's 3 seconds end, and
			// that wait began no sooner than the closing caller's write.
			closingEnd := windowEnd(t, stoppedAt, closingSent.began.Add(closingWaitLimit))
			go engine.Stop()
			closedAt := closing.awaitReset(t, stoppedAt.Add(2*wideMargin))
			expectWithin(t, "the closing caller's close", closedAt, stoppedAt, closingEnd)
			silentStream.expectStream(t, opening)
			expectWithin(t, "the silent caller's end", silentStream.ended, stoppedAt, stoppedAt.Add(wideMargin))
		})
	})
}

// quietFor is how long a row waits to show nothing comes.
const quietFor = 300 * time.Millisecond

// readOpeningFrom waits for the opening on a recorded stream.
func (call caller) readOpeningFrom(t *testing.T, stream *recording) {
	t.Helper()
	got := stream.waitFor(t, len(opening), call.connected.Add(progressLimit))
	if !bytes.HasPrefix(got, opening) {
		t.Fatalf("the stream did not start with the opening: % x", got)
	}
}

// floodRequests is more than any runner's buffers hold: Linux took up to 7 MB of a flood before
// its writes waited, on an Ubuntu 24.04 machine, 2026-10-23.
const floodRequests = 8 << 20

// floodOptions are the option codes a flood asks for in turn: 4 to 255, never ECHO or SGA.
var floodOptions = func() []byte {
	var codes []byte
	for code := range 256 {
		if code >= 4 {
			codes = append(codes, byte(code))
		}
	}
	return codes
}()

// floodOption is the option a flood's request at index asks for.
func floodOption(index int) byte {
	return floodOptions[index%len(floodOptions)]
}

// numbered is length bytes of a flood's stream from offset: DO for options 4 to 255 in turn,
// never ECHO or SGA, so every request is refused with WONT and the reply names which request it
// answers. It is made a part at a time, so a long flood holds little memory.
func numbered(offset, length int) []byte {
	part := make([]byte, length)
	for position := range part {
		index, place := (offset+position)/3, (offset+position)%3
		part[position] = []byte{iac, doVerb, floodOption(index)}[place]
	}
	return part
}

// floodNumbered sends the numbered stream and never reads, until a write stops going through,
// then finishes a request the last write may have cut short and sends the bytes after, on a
// goroutine that waits for room. A write cut short may have sent more than it reports, as
// Windows does, so the rows read where the stream stopped from the replies themselves.
func floodNumbered(t *testing.T, call caller, after []byte) {
	t.Helper()
	for offset := 0; offset < 3*floodRequests; {
		_ = call.connection.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
		written, err := call.connection.Write(numbered(offset, 3072))
		offset += written
		if errors.Is(err, os.ErrDeadlineExceeded) {
			rest := numbered(offset, (3-offset%3)%3)
			go func() {
				_ = call.connection.SetWriteDeadline(time.Now().Add(60 * time.Second))
				_, _ = call.connection.Write(join(rest, after))
			}()
			return
		}
		if err != nil {
			t.Fatalf("flooding: %v", err)
		}
	}
	t.Fatalf("flooding: the writes never waited")
}

// expectNumberedReplies checks replies are WONT to the numbered stream's requests from the first,
// each once, in order, and returns how many.
func expectNumberedReplies(t *testing.T, replies []byte) int {
	t.Helper()
	for index := 0; index < len(replies)/3; index++ {
		if !bytes.Equal(replies[3*index:3*index+3], request(wont, floodOption(index))) {
			t.Fatalf("reply %d is % x, want WONT to request %d", index, replies[3*index:3*index+3], index)
		}
	}
	if len(replies)%3 != 0 {
		t.Fatalf("the replies end with a part of one: % x", replies[len(replies)/3*3:])
	}
	return len(replies) / 3
}

// bulkRecording is everything the engine sends a caller that receives megabytes, with when each
// chunk arrived rather than each byte, read on its own goroutine until end of stream.
type bulkRecording struct {
	received   []byte
	chunkEnds  []int
	chunkTimes []time.Time
	end        error
	done       chan struct{}
}

// recordBulk starts reading the caller's connection in large chunks; it gives up at the deadline.
func (call caller) recordBulk(deadline time.Time) *bulkRecording {
	stream := &bulkRecording{done: make(chan struct{})}
	_ = call.connection.SetReadDeadline(deadline)
	go func() {
		defer close(stream.done)
		chunk := make([]byte, 64<<10)
		for {
			got, err := call.connection.Read(chunk)
			if got > 0 {
				stream.received = append(stream.received, chunk[:got]...)
				stream.chunkEnds = append(stream.chunkEnds, len(stream.received))
				stream.chunkTimes = append(stream.chunkTimes, time.Now())
			}
			if err != nil {
				stream.end = err
				return
			}
		}
	}()
	return stream
}

// arrivedAt is when the byte at offset arrived; the stream must have ended.
func (stream *bulkRecording) arrivedAt(offset int) time.Time {
	<-stream.done
	for index, end := range stream.chunkEnds {
		if offset < end {
			return stream.chunkTimes[index]
		}
	}
	return time.Time{}
}

// dialSmall dials with a receive buffer of 4096 bytes set before the connection opens, closed
// when the test ends.
func dialSmall(t *testing.T, address string) caller {
	t.Helper()
	dialed := time.Now()
	opened, err := (&net.Dialer{Control: smallWindow}).DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatalf("dialing the engine: %v", err)
	}
	connection, isTCP := opened.(*net.TCPConn)
	if !isTCP {
		t.Fatalf("the caller's connection is a %T", opened)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return caller{connection: connection, dialed: dialed, connected: time.Now()}
}

// engineCloseAt is when the engine closed the caller's connection, as the caller can tell: the
// first reset its writes meet off Linux, the OS's table of sockets on Linux, where the engine's
// FIN can wait behind a closed window.
func engineCloseAt(t *testing.T, call caller, address string, deadline time.Time) time.Time {
	t.Helper()
	if runtime.GOOS == "linux" {
		closedAt, _, _ := engineClosed(t, address, call.connection.LocalAddr().String(), deadline)
		return closedAt
	}
	return call.awaitReset(t, deadline)
}

// ceilingCallers is how many callers the ceiling's row runs at once, each against its own engine.
// A caller that floods and never reads leaves negotiation waiting in a write, so the greeting is
// never written and only the ceiling ends the call. On 2026-10-23 and 24, on Windows, 20 of 20 and
// 30 of 30 callers reached the ceiling. On an Ubuntu 24.04 machine, in the whole suite under the
// race detector, 20 of 20 did, twice; in two earlier runs, one of them killed for want of
// memory, 1 of 30 and none of 30 did, their greetings getting through and the name's 60 seconds
// ending the call. So the row asks for one at the ceiling on Windows only; the clamp's row shows
// the ceiling on Linux.
const ceilingCallers = 20

// ceilingRows floods from 1 second and never reads, each caller against its own engine: each
// call is closed either at the ceiling or, where the greeting got through, at the name's 60
// seconds after it; on Windows at least one reaches the ceiling.
func ceilingRows(t *testing.T) {
	t.Helper()
	var mutex sync.Mutex
	atCeiling := 0
	var calling sync.WaitGroup
	for index := range ceilingCallers {
		calling.Go(func() {
			ended := ceilingCall(t, index)
			mutex.Lock()
			defer mutex.Unlock()
			if ended == "ceiling" {
				atCeiling++
			}
		})
	}
	calling.Wait()
	if !t.Failed() && runtime.GOOS == "windows" && atCeiling == 0 {
		t.Fatalf("of %d callers that flood and never read, none was closed at the ceiling: each got its greeting through", ceilingCallers)
	}
	t.Logf("%d of %d callers reached the ceiling", atCeiling, ceilingCallers)
}

// ceilingCall is one caller of the ceiling's row. It reports how its call ended.
func ceilingCall(t *testing.T, index int) string {
	t.Helper()
	address := startEngine(t, 1)[0]
	call := dialSmall(t, address)
	wait(t, call.connected.Add(time.Second))
	call.flood(t)
	if time.Now().After(call.dialed.Add(negotiationLimit - 100*time.Millisecond)) {
		t.Errorf("test fault: caller %d's flood took until %v after the dial", index, time.Since(call.dialed))
		return ""
	}
	deadline := call.connected.Add(ceilingLimit + margin)
	closedAt := engineCloseAt(t, call, address, deadline)
	ceiling := call.dialed.Add(ceilingLimit)
	if !closedAt.Before(ceiling.Add(-early)) {
		expectWithin(t, fmt.Sprintf("caller %d's close", index), closedAt, ceiling, deadline)
		return "ceiling"
	}
	// The greeting got through: the prompt was written once negotiation's last write went out,
	// 3 seconds or later, a moment a caller that never reads cannot see (4.6 seconds on a loaded
	// runner, ubuntu-24.04-arm, 2026-10-26), and the name's 60 seconds after it end the call, by
	// the ceiling at the latest. The rows that time the name's 60 seconds are the single callers'.
	expectWithin(t, fmt.Sprintf("caller %d's close, its greeting through", index), closedAt,
		call.dialed.Add(negotiationLimit+nameLimit), ceiling)
	return "name"
}

// clampCallers is how many callers the clamp's row runs at once: on 2026-10-23, 4 of 4 had their
// Hello after 68 seconds on Windows and on Ubuntu 24.04.
const clampCallers = 6

// clampRows makes Hello come after 68 seconds, so the closing wait would end past the ceiling: a
// caller floods and does not read, so the greeting waits; it reads from 10 seconds, so the prompt
// is written then and the name's 60 seconds run past 68; and it ends a name at 68.5 seconds. Its
// close comes at the ceiling. Where a call's greeting got through before 10 seconds the name's 60
// seconds end it earlier, so the row checks every close comes by the ceiling, and on Windows that
// one Hello came after 68 seconds.
func clampRows(t *testing.T) {
	t.Helper()
	var mutex sync.Mutex
	clamped := 0
	var calling sync.WaitGroup
	for index := range clampCallers {
		calling.Go(func() {
			if clampCall(t, index) {
				mutex.Lock()
				clamped++
				mutex.Unlock()
			}
		})
	}
	calling.Wait()
	if !t.Failed() && runtime.GOOS == "windows" && clamped == 0 {
		t.Fatalf("of %d callers none had its Hello after 68 seconds", clampCallers)
	}
	t.Logf("%d of %d callers had their Hello after 68 seconds", clamped, clampCallers)
}

func clampCall(t *testing.T, index int) bool {
	t.Helper()
	address := startEngine(t, 1)[0]
	call := dialSmall(t, address)
	closeAt := watchClose(t, call, address, call.connected.Add(ceilingLimit+closingWaitLimit+margin))
	wait(t, call.connected.Add(time.Second))
	call.flood(t)
	wait(t, call.connected.Add(10*time.Second))
	stream := call.recordBulk(call.connected.Add(ceilingLimit + 5*time.Second))
	wait(t, call.connected.Add(68500*time.Millisecond))
	_ = call.connection.SetWriteDeadline(time.Now().Add(time.Second))
	_, _ = call.connection.Write([]byte("a\r"))
	ceiling := call.dialed.Add(ceilingLimit)
	<-stream.done
	hello := bytes.Index(stream.received, helloTo("a"))
	var helloAt time.Time
	if hello >= 0 {
		helloAt = stream.arrivedAt(hello)
	}
	if hello < 0 || helloAt.Before(call.dialed.Add(68*time.Second)) {
		// No Hello after 68 seconds: the call ended by the name's 60 seconds or the ceiling,
		// either way by the ceiling.
		if closedAt := closeAt(); closedAt.After(call.connected.Add(ceilingLimit + margin)) {
			t.Errorf("caller %d's call ended %v after the ceiling", index, closedAt.Sub(ceiling))
		}
		return false
	}
	expectWithin(t, fmt.Sprintf("caller %d's close, Hello at %v", index, helloAt.Sub(call.dialed)), closeAt(), ceiling, call.connected.Add(ceilingLimit+margin))
	return true
}

// watchClose starts watching for the engine's close of a caller's connection and returns a call
// that gives its moment. On Linux it watches the OS's table of sockets from the start, so a close
// that came before the row looks is seen too; elsewhere the caller's writes meet the reset, which
// stays to be met however late it is looked for.
func watchClose(t *testing.T, call caller, address string, deadline time.Time) func() time.Time {
	t.Helper()
	if runtime.GOOS != "linux" {
		return func() time.Time { return call.awaitReset(t, deadline) }
	}
	closed := make(chan time.Time, 1)
	local := call.connection.LocalAddr().String()
	go func() {
		closedAt, _, _ := engineClosed(t, address, local, deadline)
		closed <- closedAt
	}()
	return func() time.Time {
		timer := time.NewTimer(time.Until(deadline.Add(margin)))
		defer timer.Stop()
		select {
		case closedAt := <-closed:
			return closedAt
		case <-timer.C:
			t.Errorf("the engine's close was not seen by %v", deadline)
			return deadline.Add(margin)
		}
	}
}
