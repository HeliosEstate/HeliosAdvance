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
)

// finish waits for the greeting and the prompt after the bytes before them, types a name, and
// checks the whole stream to its end: the echo when ECHO was agreed, then Hello and the name.
// It returns when the greeting's first byte arrived.
func finish(t *testing.T, call caller, stream *recording, before []byte, echoes bool) time.Time {
	t.Helper()
	stream.waitFor(t, len(before)+len(asked), time.Now().Add(negotiationLimit+2*margin))
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
	t.Run("When it accepts a caller, the engine shall send WILL ECHO and WILL SGA, and no other option request.", func(t *testing.T) {
		t.Parallel()
		t.Run("a caller that answers DO DO", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			call.readOpening(t, call.connected.Add(margin))
			stream := call.record(call.send(t, answers).Add(5 * time.Second))
			finish(t, call, stream, nil, true)
		})
		t.Run("a silent caller", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			stream := call.record(call.connected.Add(negotiationLimit + 5*time.Second))
			finish(t, call, stream, opening, false)
		})
		t.Run("the opening comes at once, before the caller sends anything", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			call.readOpening(t, call.connected.Add(margin))
		})
	})
	t.Run("If, during negotiation, the caller asks for a Telnet option other than ECHO and SGA, then the engine shall refuse it.", func(t *testing.T) {
		t.Parallel()
		t.Run("DO and WILL for other options, then the answers", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			stream := call.record(call.connected.Add(5 * time.Second))
			call.send(t, join(request(doVerb, 0), request(doVerb, telnetTypeOption), request(doVerb, 255),
				request(will, telnetTypeOption), request(will, windowSizeOption), answers))
			finish(t, call, stream, join(opening, request(wont, 0), request(wont, telnetTypeOption), request(wont, 255),
				request(dont, telnetTypeOption), request(dont, windowSizeOption)), true)
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
			{name: "DO ECHO three times, then DO SGA: no reply", sent: join(repeated(request(doVerb, echo), 3), request(doVerb, sga))},
			{name: "DONT ECHO, DO ECHO, DO SGA: one WILL ECHO", sent: join(request(dont, echo), request(doVerb, echo), request(doVerb, sga)), replies: request(will, echo)},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				call := dial(t, startEngine(t, 1)[0])
				stream := call.record(call.connected.Add(5 * time.Second))
				call.send(t, row.sent)
				finish(t, call, stream, join(opening, row.replies), true)
			})
		}
	})
	t.Run("If, during negotiation, the caller sends anything that is not an option request, then the engine shall discard it without reply.", func(t *testing.T) {
		t.Parallel()
		var everyDataByte []byte
		for code := range 255 {
			everyDataByte = append(everyDataByte, byte(code))
		}
		t.Run("text, every data byte, commands and a subnegotiation, then the answers", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			stream := call.record(call.connected.Add(5 * time.Second))
			call.send(t, join([]byte("hello\r\n"), everyDataByte, []byte{iac, iac, iac, nop, iac, ayt},
				[]byte{iac, subnegotiationBegin, telnetTypeOption, 1, iac, subnegotiationEnd}, []byte{doVerb, echo, doVerb, sga}))
			sent := call.send(t, answers)
			// Nothing negotiation read reaches the name: the name is only what is typed after.
			greetingAt := finish(t, call, stream, opening, true)
			expectWithin(t, "the greeting", greetingAt, sent, sent.Add(margin))
		})
		t.Run("a subnegotiation that never ends, answers inside it", func(t *testing.T) {
			t.Parallel()
			call := dial(t, startEngine(t, 1)[0])
			stream := call.record(call.connected.Add(negotiationLimit + 5*time.Second))
			call.send(t, join([]byte{iac, subnegotiationBegin, telnetTypeOption}, answers))
			for next := time.Now(); next.Before(call.dialed.Add(negotiationLimit - 300*time.Millisecond)); next = next.Add(200 * time.Millisecond) {
				wait(t, next)
				call.send(t, join([]byte("data"), request(doVerb, telnetTypeOption)))
			}
			// The subnegotiation is still open after negotiation, so the caller ends it before its
			// name; the answers inside it were never answers, so nothing is echoed.
			stream.waitFor(t, len(opening)+len(asked), call.connected.Add(negotiationLimit+2*margin))
			call.send(t, []byte{iac, subnegotiationEnd, 'n', '\r'})
			stream.expectStream(t, join(opening, asked, helloTo("n")))
			expectWithin(t, "the greeting", stream.arrivedAt(t, len(opening)), call.dialed.Add(negotiationLimit), stream.arrivedAt(t, 0).Add(negotiationLimit+margin))
		})
	})
	t.Run("When the caller closes the connection, or 3 seconds after the engine shut down its sending side, whichever comes first, the engine shall close the connection.", func(t *testing.T) {
		t.Parallel()
		t.Run("callers that close at once: their places are free at once", func(t *testing.T) {
			t.Parallel()
			address := startEngine(t, 1)[0]
			var closed time.Time
			for range connectionCap {
				call := dial(t, address)
				stream := call.record(call.connected.Add(2 * margin))
				call.send(t, join(answers, []byte("n\r")))
				stream.expectStream(t, join(opening, asked, echoed("n")))
				_ = call.connection.Close()
				closed = time.Now()
			}
			expectServedBy(t, address, closed.Add(margin))
		})
		t.Run("callers that stay: closed 3 seconds after the shutdown, not before", func(t *testing.T) {
			t.Parallel()
			address := startEngine(t, 1)[0]
			// The hundred are set up at once, so the window before the first closes does not
			// depend on how fast a runner dials a hundred times.
			var mutex sync.Mutex
			var firstAnswer, lastEnd time.Time
			var calling sync.WaitGroup
			for range connectionCap {
				calling.Go(func() {
					answeredAt, ended, problem := answerAndStay(t, address)
					mutex.Lock()
					defer mutex.Unlock()
					if problem != "" {
						t.Error(problem)
						return
					}
					if firstAnswer.IsZero() || answeredAt.Before(firstAnswer) {
						firstAnswer = answeredAt
					}
					if ended.After(lastEnd) {
						lastEnd = ended
					}
				})
			}
			calling.Wait()
			if t.Failed() {
				t.FailNow()
			}
			if time.Now().After(firstAnswer.Add(closingWaitLimit - 500*time.Millisecond)) {
				t.Fatalf("test fault: a hundred callers took %v to set up", time.Since(firstAnswer))
			}
			expectRefused(t, address)
			wait(t, firstAnswer.Add(closingWaitLimit-150*time.Millisecond))
			expectRefused(t, address)
			expectServedBy(t, address, lastEnd.Add(closingWaitLimit+margin))
		})
	})
	t.Run("While 100 connections are open, the engine shall close each new connection at once, without writing to it.", func(t *testing.T) {
		t.Parallel()
		t.Run("a hundred silent callers are served, the hundred and first is closed at once", func(t *testing.T) {
			t.Parallel()
			address := startEngine(t, 1)[0]
			for range connectionCap {
				call := dial(t, address)
				call.readOpening(t, call.connected.Add(margin))
			}
			expectRefused(t, address)
			expectRefused(t, address)
		})
		t.Run("fifty on each of two sockets: the next on either is closed at once", func(t *testing.T) {
			t.Parallel()
			addresses := startEngine(t, 2)
			for index := range connectionCap {
				call := dial(t, addresses[index%2])
				call.readOpening(t, call.connected.Add(margin))
			}
			expectRefused(t, addresses[0])
			expectRefused(t, addresses[1])
		})
		t.Run("refused callers take no place, and a caller that leaves frees one", func(t *testing.T) {
			t.Parallel()
			address := startEngine(t, 1)[0]
			callers := make([]caller, connectionCap)
			for index := range callers {
				callers[index] = dial(t, address)
				callers[index].readOpening(t, callers[index].connected.Add(margin))
			}
			for range 3 {
				expectRefused(t, address)
			}
			_ = callers[0].connection.Close()
			expectServedBy(t, address, time.Now().Add(margin))
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
		normalCall := func(t *testing.T, address string) {
			t.Helper()
			call := dial(t, address)
			stream := call.record(call.connected.Add(5 * time.Second))
			opened := call.connected
			answeredAt := call.send(t, answers)
			greetingAt := finish(t, call, stream, opening, true)
			expectWithin(t, "the opening", stream.arrivedAt(t, 0), opened, opened.Add(margin))
			expectWithin(t, "the greeting", greetingAt, answeredAt, answeredAt.Add(margin))
		}
		t.Run("a silent caller", func(t *testing.T) {
			t.Parallel()
			address := startEngine(t, 1)[0]
			dial(t, address)
			normalCall(t, address)
		})
		t.Run("a caller that floods and never reads", func(t *testing.T) {
			t.Parallel()
			address := startEngine(t, 1)[0]
			dial(t, address).flood(t)
			normalCall(t, address)
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
			normalCall(t, address)
			<-done
		})
		t.Run("ninety-nine silent callers", func(t *testing.T) {
			t.Parallel()
			address := startEngine(t, 1)[0]
			for range connectionCap - 1 {
				dial(t, address)
			}
			normalCall(t, address)
		})
		t.Run("a silent caller on one socket, a caller on the other", func(t *testing.T) {
			t.Parallel()
			addresses := startEngine(t, 2)
			dial(t, addresses[0])
			normalCall(t, addresses[1])
			dial(t, addresses[1])
			normalCall(t, addresses[0])
		})
	})
}

// answerAndStay is one of many callers at once: it answers and types a name in one write, reads
// the whole call to end of stream, and keeps its end open. It reports when it answered and when
// the stream ended, or what went wrong, since it runs off the test's goroutine.
func answerAndStay(t *testing.T, address string) (answeredAt, ended time.Time, problem string) {
	t.Helper()
	opened, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", address)
	if err != nil {
		return answeredAt, ended, "dial failed: " + err.Error()
	}
	t.Cleanup(func() { _ = opened.Close() })
	_ = opened.SetDeadline(time.Now().Add(2 * margin))
	if _, err := opened.Write(join(answers, []byte("n\r"))); err != nil {
		return answeredAt, ended, "the caller's write failed: " + err.Error()
	}
	answeredAt = time.Now()
	var received []byte
	chunk := make([]byte, 256)
	for {
		got, err := opened.Read(chunk)
		received = append(received, chunk[:got]...)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return answeredAt, ended, fmt.Sprintf("the stream did not end in order: %v, after % x", err, received)
		}
	}
	ended = time.Now()
	if want := join(opening, asked, echoed("n")); string(received) != string(want) {
		return answeredAt, ended, fmt.Sprintf("the stream was % x, want % x", received, want)
	}
	return answeredAt, ended, ""
}

// callOnce is one of many callers dialing at once: it reports "served", "refused", or what went
// wrong, since it runs off the test's goroutine.
func callOnce(t *testing.T, address string) string {
	t.Helper()
	opened, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", address)
	if err != nil {
		return "dial failed: " + err.Error()
	}
	t.Cleanup(func() { _ = opened.Close() })
	_ = opened.SetReadDeadline(time.Now().Add(2 * margin))
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
