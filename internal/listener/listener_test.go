// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests of one caller's call through the Listener on real loopback sockets, from accept to
// close: the opening requests, the refusals, what negotiation discards, the close, the cap of
// 100, and serving every caller while others are silent or slow. Each call is followed to its
// end: the greeting and the prompt, a name, Hello and the name, and end of stream.
package listener_test

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// finish waits for the greeting and the prompt after the bytes before them, types a name, and
// checks the whole stream to its end: the echo when ECHO was agreed, then Hello and the name.
// It returns when the greeting's first byte arrived.
func finish(t *testing.T, call caller, stream *recording, before []byte, echoes bool) time.Time {
	t.Helper()
	stream.waitFor(t, len(before)+len(asked), time.Now().Add(negotiationLimit+progressLimit))
	call.send(t, []byte("n\r"))
	after := helloTo("n")
	if echoes {
		after = echoed("n")
	}
	stream.expectStream(t, join(before, asked, after))
	return stream.arrivedAt(t, len(before))
}

func TestCall(t *testing.T) {
	t.Parallel()
	t.Run("When it accepts a Telnet caller, the engine shall send IAC WILL ECHO, IAC WILL SGA, IAC WILL BINARY, IAC DO BINARY, IAC DO TTYPE, IAC DO NAWS, IAC DO NEW-ENVIRON and IAC DO TSPEED, in that order, and no other option request.", func(t *testing.T) {
		t.Parallel()
		t.Run("a caller that answers all eight", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			call.readOpening(t, call.connected.Add(progressLimit))
			stream := call.record(call.send(t, answers).done.Add(testrun.Patient(5 * time.Second)))
			finish(t, call, stream, nil, true)
		})
		t.Run("a silent caller", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			stream := call.record(call.connected.Add(negotiationLimit + testrun.Patient(5*time.Second)))
			finish(t, call, stream, opening, false)
		})
		t.Run("the opening comes at once, before the caller sends anything", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			// The nearest fault waits for the caller's first byte, which never comes.
			call.readOpening(t, call.connected.Add(testrun.Patient(wideMargin)))
		})
	})
	t.Run("If the caller sends WILL for a Telnet option other than SGA, BINARY, TTYPE, NAWS, NEW-ENVIRON and TSPEED, or DO for one other than ECHO, SGA and BINARY, then the engine shall refuse it, WILL with DONT and DO with WONT.", func(t *testing.T) {
		t.Parallel()
		t.Run("DO and WILL for other options, then the answers", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			stream := call.record(call.connected.Add(testrun.Patient(5 * time.Second)))
			call.send(t, join(request(doVerb, 2), request(doVerb, telnetTypeOption), request(doVerb, 255),
				request(will, echo), request(will, 25), answers))
			finish(t, call, stream, join(opening, request(wont, 2), request(wont, telnetTypeOption), request(wont, 255),
				request(dont, echo), request(dont, 25)), true)
		})
	})
	t.Run("The engine shall send at most one reply to each option request.", func(t *testing.T) {
		t.Parallel()
		rows := []struct {
			name    string
			sent    []byte
			replies []byte
		}{
			{name: "DO 24 five times: five WONT 24", sent: join(repeated(request(doVerb, telnetTypeOption), 5), answers), replies: repeated(request(wont, telnetTypeOption), 5)},
			{name: "DO ECHO three times, then the other seven: no reply", sent: join(repeated(request(doVerb, echo), 3), answers[3:])},
			{name: "DONT ECHO, DO ECHO, then the other seven: one WILL ECHO", sent: join(request(dont, echo), request(doVerb, echo), answers[3:]), replies: request(will, echo)},
			{name: "WILL TTYPE three times among the answers: no reply, and the SEND once, which is no reply", sent: join(repeated(request(will, telnetTypeOption), 3), answers[:12], answers[15:]), replies: terminalTypeSend},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				call := dial(t, startEngine(t, 1)[0])
				stream := call.record(call.connected.Add(testrun.Patient(5 * time.Second)))
				call.send(t, row.sent)
				finish(t, call, stream, join(opening, row.replies), true)
			})
		}
	})
	t.Run("If, during negotiation, the caller sends anything that is not an option request, AYT, AO or IP, then the engine shall discard it without reply.", func(t *testing.T) {
		t.Parallel()
		var everyDataByte []byte
		for code := range 255 {
			everyDataByte = append(everyDataByte, byte(code))
		}
		t.Run("text, every data byte, commands and a subnegotiation, then the answers", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			stream := call.record(call.connected.Add(testrun.Patient(5 * time.Second)))
			call.send(t, join([]byte("hello\r\n"), everyDataByte, []byte{iac, iac, iac, nop, iac, dataMark, iac, 247, iac, 248, iac, 249},
				[]byte{iac, subnegotiationBegin, telnetTypeOption, 1, iac, subnegotiationEnd}, []byte{doVerb, echo, doVerb, sga}))
			sent := call.send(t, answers)
			// Nothing negotiation read reaches the name: the name is only what is typed after.
			greetingAt := finish(t, call, stream, opening, true)
			// The nearest fault misses the answers, so the greeting waits for negotiation's 3
			// seconds from the dial.
			expectWithin(t, "the greeting", greetingAt, sent.began,
				windowEnd(t, sent.done, call.dialed.Add(negotiationLimit)))
		})
		t.Run("a subnegotiation that never ends, answers inside it", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			stream := call.record(call.connected.Add(negotiationLimit + testrun.Patient(5*time.Second)))
			call.send(t, join([]byte{iac, subnegotiationBegin, telnetTypeOption}, answers))
			for next := time.Now(); next.Before(call.dialed.Add(negotiationLimit - 300*time.Millisecond)); next = next.Add(200 * time.Millisecond) {
				wait(t, next)
				call.send(t, join([]byte("data"), request(doVerb, telnetTypeOption)))
			}
			// The subnegotiation is still open after negotiation, so the caller ends it before its
			// name; the answers inside it were never answers, so nothing is echoed.
			stream.waitFor(t, len(opening)+len(asked), call.connected.Add(negotiationLimit+progressLimit))
			call.send(t, []byte{iac, subnegotiationEnd, 'n', '\r'})
			stream.expectStream(t, join(opening, asked, helloTo("n")))
			expectWithin(t, "the greeting", stream.arrivedAt(t, len(opening)), call.dialed.Add(negotiationLimit), stream.arrivedAt(t, 0).Add(negotiationLimit+margin))
		})
	})
	t.Run("When a Telnet caller closes the connection, or 3 seconds after the engine shut down its sending side, whichever comes first, the engine shall close the connection.", func(t *testing.T) {
		t.Parallel()
		t.Run("callers that close at once: their places are free at once", func(t *testing.T) {
			t.Parallel()
			address := startEngine(t, 1)[0]
			released, closed := helloAndClose(t, address)
			// The nearest fault frees a place only when a closing wait's 3 seconds end, and none
			// began before the names were sent.
			expectServedBy(t, address, windowEnd(t, closed, released.Add(closingWaitLimit)))
		})
		t.Run("callers that stay: closed 3 seconds after the shutdown, not before", func(t *testing.T) {
			t.Parallel()
			address := startEngine(t, 1)[0]
			// The hundred are set up first, each answered and waiting at the prompt with its place
			// held, and then type their names together. No place can come back before 3 seconds
			// after the first of those writes began, however long a runner took to set them up
			// (2.2 seconds under twice the usual load, 2026-10-25).
			callers, streams := fillAtPrompt(t, address)
			expectRefused(t, address)
			released := sendNames(t, callers)
			// A second short of the 3 seconds, so that a probe the engine accepts late on a loaded
			// runner still meets a full cap; the single caller's row holds the close to 3.
			wait(t, released.Add(closingWaitLimit-time.Second))
			expectRefusedUntil(t, address, released.Add(closingWaitLimit))
			var lastEnd time.Time
			for _, stream := range streams {
				stream.expectStream(t, join(opening, asked, echoed("n")))
				if stream.ended.After(lastEnd) {
					lastEnd = stream.ended
				}
			}
			expectServedBy(t, address, lastEnd.Add(closingWaitLimit+margin))
		})
	})
	t.Run("While 100 connections are open, the engine shall close each new connection at once, without writing to it.", func(t *testing.T) {
		t.Parallel()
		t.Run("a hundred silent callers are served, the hundred and first is closed at once", func(t *testing.T) {
			t.Parallel()
			address := startEngine(t, 1)[0]
			fillSilently(t, []string{address})
			expectRefused(t, address)
			expectRefused(t, address)
		})
		t.Run("fifty on each of two sockets: the next on either is closed at once", func(t *testing.T) {
			t.Parallel()
			addresses := startEngine(t, 2)
			fillSilently(t, addresses)
			expectRefused(t, addresses[0])
			expectRefused(t, addresses[1])
		})
		t.Run("refused callers take no place, and a caller that leaves frees one", func(t *testing.T) {
			t.Parallel()
			address := startEngine(t, 1)[0]
			callers := fillSilently(t, []string{address})
			for range 3 {
				expectRefused(t, address)
			}
			// The last caller dialed leaves, so the nearest fault, one that misses its close and
			// frees the place only when its negotiation's 3 seconds end, is timed from a moment
			// just before the window, however long a runner took to dial the hundred.
			leaving := callers[len(callers)-1]
			_ = leaving.connection.Close()
			expectServedBy(t, address, windowEnd(t, time.Now(), leaving.dialed.Add(negotiationLimit)))
			expectRefused(t, address)
		})
		for _, sockets := range []int{1, 2} {
			t.Run(fmt.Sprintf("two hundred callers at once on %d sockets: exactly a hundred served", sockets), func(t *testing.T) {
				t.Parallel()
				addresses := startEngine(t, sockets)
				var mutex sync.Mutex
				outcomes := map[string]int{}
				var calling sync.WaitGroup
				for index := range 2 * connectionCap {
					calling.Go(func() {
						outcome := callOnce(t, addresses[index%sockets])
						mutex.Lock()
						outcomes[outcome]++
						mutex.Unlock()
					})
				}
				calling.Wait()
				if outcomes["served"] != connectionCap || outcomes["refused"] != connectionCap {
					t.Fatalf("of two hundred callers at once: %v", outcomes)
				}
			})
		}
	})
	t.Run("While one caller is silent or slow, the engine shall serve every other caller without waiting on that one.", func(t *testing.T) {
		t.Parallel()
		// otherDialed is when the silent or slow caller this one must not wait on was dialed.
		normalCall := func(t *testing.T, address string, otherDialed time.Time) {
			t.Helper()
			call := dial(t, address)
			stream := call.record(call.connected.Add(testrun.Patient(5 * time.Second)))
			opened := call.connected
			answered := call.send(t, answers)
			greetingAt := finish(t, call, stream, opening, true)
			// The nearest fault negotiates one caller at a time, so this one's opening waits out
			// the other's 3 seconds of negotiation, which began at its dial.
			expectWithin(t, "the opening", stream.arrivedAt(t, 0), opened,
				windowEnd(t, opened, otherDialed.Add(negotiationLimit)))
			// The nearest fault misses the answers, so the greeting waits for negotiation's 3
			// seconds from the dial; one that serves a caller at a time waits for the other's whole
			// call, later still.
			expectWithin(t, "the greeting", greetingAt, answered.began,
				windowEnd(t, answered.done, call.dialed.Add(negotiationLimit)))
		}
		t.Run("a silent caller", func(t *testing.T) {
			t.Parallel()
			address := startEngine(t, 1)[0]
			normalCall(t, address, dial(t, address).dialed)
		})
		t.Run("a caller that floods and never reads", func(t *testing.T) {
			t.Parallel()
			address := startEngine(t, 1)[0]
			flooder := dial(t, address)
			flooder.flood(t)
			normalCall(t, address, flooder.dialed)
		})
		t.Run("a caller that sends a byte every 200 ms", func(t *testing.T) {
			t.Parallel()
			address := startEngine(t, 1)[0]
			slow := dial(t, address)
			done := make(chan struct{})
			go func() {
				defer close(done)
				for index := range 10 {
					wait(t, slow.connected.Add(time.Duration(index)*200*time.Millisecond))
					_, _ = slow.connection.Write([]byte("x"))
				}
			}()
			wait(t, slow.connected.Add(500*time.Millisecond))
			normalCall(t, address, slow.dialed)
			<-done
		})
		t.Run("ninety-nine silent callers", func(t *testing.T) {
			t.Parallel()
			address := startEngine(t, 1)[0]
			var lastDialed time.Time
			for range connectionCap - 1 {
				lastDialed = dial(t, address).dialed
			}
			normalCall(t, address, lastDialed)
		})
		t.Run("a silent caller on one socket, a caller on the other", func(t *testing.T) {
			t.Parallel()
			addresses := startEngine(t, 2)
			normalCall(t, addresses[1], dial(t, addresses[0]).dialed)
			normalCall(t, addresses[0], dial(t, addresses[1]).dialed)
		})
	})
}

// callOnce is one of many callers dialing at once: it reports "served", "refused", or what went
// wrong, since it runs off the test's goroutine. Its row counts the two; the rows of the hundred
// and first caller hold the refusal to "at once", so its wait is a progress one.
func callOnce(t *testing.T, address string) string {
	t.Helper()
	opened, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", address)
	if err != nil {
		return "dial failed: " + err.Error()
	}
	t.Cleanup(func() { _ = opened.Close() })
	_ = opened.SetReadDeadline(time.Now().Add(progressLimit))
	received := make([]byte, len(opening))
	got, err := io.ReadFull(opened, received)
	switch {
	case err == nil && string(received) == string(opening):
		return "served"
	case got == 0 && (errors.Is(err, io.EOF) || isReset(err)):
		return "refused"
	default:
		return fmt.Sprintf("neither: % x, %v", received[:got], err)
	}
}
