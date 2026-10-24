// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests of Open and the Line over real loopback sockets, driven by the scripted caller: how
// negotiation hands over to the Line, what the Line owes and holds when it starts, how it queues
// and writes the caller's bytes, how it reads the caller's characters and answers their option
// requests, and each way a call on it ends.
package telnet_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/telnet"
)

// The Line's limits, as the contract's lines state them.
const sendBufferBytes = 1024

// quiet is how long a row watches for bytes that must not come.
const quiet = 300 * time.Millisecond

// opened is what one Open call returned, and when.
type opened struct {
	line     *telnet.Line
	outcome  telnet.Outcome
	err      error
	returned time.Time
}

// opening is an Open call running on the server end.
type openCall struct {
	called time.Time
	done   <-chan opened
}

// openOn calls Open on its own goroutine, as the Listener does, and returns at once.
func openOn(ctx context.Context, connection telnet.Conn) openCall {
	done := make(chan opened, 1)
	called := time.Now()
	go func() {
		line, outcome, err := telnet.Open(ctx, connection)
		done <- opened{line: line, outcome: outcome, err: err, returned: time.Now()}
	}()
	return openCall{called: called, done: done}
}

// result waits for Open to return, failing the test if it has not by the deadline.
func (call openCall) result(t *testing.T, deadline time.Time) opened {
	t.Helper()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case got := <-call.done:
		return got
	case <-timer.C:
		t.Fatalf("Open had not returned %v after it was called", time.Since(call.called))
		return opened{}
	}
}

// answeredLine opens a Line whose caller answers DO DO with the bytes after, in one write, and
// reads the opening: negotiation ends Answered.
func answeredLine(t *testing.T, after []byte) (connected, *telnet.Line) {
	t.Helper()
	return lineAfter(t, answers, after)
}

// lineAfter opens a Line whose caller sends the answers and the bytes after them in one write.
func lineAfter(t *testing.T, answer, after []byte) (connected, *telnet.Line) {
	t.Helper()
	pair := connect(t)
	call := openOn(t.Context(), pair.server)
	readExactly(t, pair.client, len(opening), time.Now().Add(margin))
	write(t, pair.client, join(answer, after))
	got := call.result(t, time.Now().Add(margin))
	if got.err != nil || got.outcome != telnet.Answered {
		t.Fatalf("setting up: Open returned (%v, %v), want Answered", got.outcome, got.err)
	}
	replies, _ := (&reading{}).readAll(answer)
	if len(replies) > 0 {
		readExactly(t, pair.client, len(replies), time.Now().Add(margin))
	}
	return pair, got.line
}

// expectQuiet checks the caller receives nothing for a while.
func expectQuiet(t *testing.T, client net.Conn) {
	t.Helper()
	_ = client.SetReadDeadline(time.Now().Add(quiet))
	buffer := make([]byte, 64)
	got, err := client.Read(buffer)
	if got > 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the caller received % x and %v where nothing was due", buffer[:got], err)
	}
}

// expectReceived checks the caller receives exactly these bytes next.
func expectReceived(t *testing.T, client net.Conn, want []byte) {
	t.Helper()
	got := readExactly(t, client, len(want), time.Now().Add(margin))
	if !bytes.Equal(got, want) {
		t.Fatalf("the caller received\n% x\nwant\n% x", got, want)
	}
}

// recv calls RecvChar with a deadline a margin away.
func recv(t *testing.T, line *telnet.Line) (byte, error) {
	t.Helper()
	return line.RecvChar(t.Context(), time.Now().Add(2*margin))
}

// expectData reads the given data bytes with RecvChar, one call each.
func expectData(t *testing.T, line *telnet.Line, want []byte) {
	t.Helper()
	for index, wanted := range want {
		got, err := recv(t, line)
		if err != nil || got != wanted {
			t.Fatalf("RecvChar %d returned %#02x and %v, want %#02x", index, got, err, wanted)
		}
	}
}

// sendAll queues bytes with SendChar, each call returning no error. Its context ends in 5
// seconds, so a SendChar that writes where it should only queue, to a caller not reading, fails
// the row rather than waiting for good.
func sendAll(t *testing.T, line *telnet.Line, data []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for index, value := range data {
		if err := line.SendChar(ctx, value); err != nil {
			t.Fatalf("SendChar %d of %#02x returned %v", index, value, err)
		}
	}
}

// flush calls Flush and fails the test on an error.
func flush(t *testing.T, line *telnet.Line) {
	t.Helper()
	if err := line.Flush(t.Context()); err != nil {
		t.Fatalf("Flush returned %v", err)
	}
}

// cancelled is a context already ended.
func cancelled(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	return ctx
}

// lineReadsAs is the test's reading of what a Line reading these bytes after DO DO returns as data
// and replies.
func lineReadsAs(input []byte) ([]byte, []byte) {
	during := &reading{}
	during.readAll(answers)
	after := carryOn(during)
	var data, replies []byte
	for _, value := range input {
		reply, isData := after.strip(value)
		replies = append(replies, reply...)
		if isData {
			data = append(data, value)
		}
	}
	return data, replies
}

// splitRead is the real server end, with one read returning bytes and an error together: the
// first read whose bytes end with the marker returns the bytes before it with the error, end of
// file unless another is given, as a read meeting the caller's close or a passed deadline might.
// Only a wrapper can make the two meet in one call.
type splitRead struct {
	*net.TCPConn
	marker byte
	err    error
	done   bool
}

func (connection *splitRead) Read(buffer []byte) (int, error) {
	got, err := connection.TCPConn.Read(buffer)
	if err == nil && got > 0 && !connection.done && buffer[got-1] == connection.marker {
		connection.done = true
		if connection.err != nil {
			return got - 1, connection.err
		}
		return got - 1, io.EOF
	}
	return got, err
}

func TestOpen(t *testing.T) {
	t.Parallel()
	t.Run("Open shall negotiate as Negotiate does, and return the Outcome, or an error matching Negotiate's through errors.Is.", func(t *testing.T) {
		t.Parallel()
		t.Run("every option request, then the answers: the replies Negotiate writes, and Answered", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := openOn(t.Context(), pair.server)
			write(t, pair.client, sweep())
			want := join(opening, expectedReplies(sweep()))
			expectReceived(t, pair.client, want)
			got := call.result(t, time.Now().Add(margin))
			if got.err != nil || got.outcome != telnet.Answered || got.line == nil {
				t.Fatalf("Open returned (%v, %v, %v), want a Line and Answered", got.line, got.outcome, got.err)
			}
		})
		t.Run("a silent caller: TimedOut at 3 seconds, with a Line", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := openOn(t.Context(), pair.server)
			expectReceived(t, pair.client, opening)
			got := call.result(t, call.called.Add(negotiationLimit+margin))
			if got.err != nil || got.outcome != telnet.TimedOut || got.line == nil {
				t.Fatalf("Open returned (%v, %v, %v), want a Line and TimedOut", got.line, got.outcome, got.err)
			}
			expectWithin(t, "Open's return", got.returned, call.called.Add(negotiationLimit), call.called.Add(negotiationLimit+margin))
		})
		t.Run("a caller that closes before it answers: ErrCallerClosed", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := openOn(t.Context(), pair.server)
			write(t, pair.client, request(doVerb, echo))
			_ = pair.client.CloseWrite()
			got := call.result(t, time.Now().Add(margin))
			if !errors.Is(got.err, telnet.ErrCallerClosed) {
				t.Fatalf("Open returned %v, want ErrCallerClosed", got.err)
			}
		})
		t.Run("a caller that resets: ErrConnectionFailed", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := openOn(t.Context(), pair.server)
			expectReceived(t, pair.client, opening)
			reset(t, pair.client)
			got := call.result(t, time.Now().Add(margin))
			if !errors.Is(got.err, telnet.ErrConnectionFailed) {
				t.Fatalf("Open returned %v, want ErrConnectionFailed", got.err)
			}
		})
		t.Run("the context cancelled while negotiation waits: ErrDeadlineEnded and context.Canceled", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			ctx, cancel := context.WithCancel(t.Context())
			call := openOn(ctx, pair.server)
			expectReceived(t, pair.client, opening)
			cancel()
			cancelledAt := time.Now()
			got := call.result(t, cancelledAt.Add(margin))
			if !errors.Is(got.err, telnet.ErrDeadlineEnded) || !errors.Is(got.err, context.Canceled) {
				t.Fatalf("Open returned %v, want ErrDeadlineEnded and context.Canceled", got.err)
			}
		})
		t.Run("the context's deadline at 1 second: ErrDeadlineEnded and context.DeadlineExceeded", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := time.Now().Add(time.Second)
			call := openOn(withDeadline(t, deadline), pair.server)
			got := call.result(t, deadline.Add(margin))
			if !errors.Is(got.err, telnet.ErrDeadlineEnded) || !errors.Is(got.err, context.DeadlineExceeded) {
				t.Fatalf("Open returned %v, want ErrDeadlineEnded and context.DeadlineExceeded", got.err)
			}
			expectWithin(t, "Open's return", got.returned, deadline, deadline.Add(margin))
		})
		t.Run("the context ended before the call: ErrDeadlineEnded, nothing written", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			got := openOn(cancelled(t), pair.server).result(t, time.Now().Add(margin))
			if !errors.Is(got.err, telnet.ErrDeadlineEnded) || !errors.Is(got.err, context.Canceled) {
				t.Fatalf("Open returned %v, want ErrDeadlineEnded", got.err)
			}
			expectNothingWritten(t, pair)
		})
	})
	t.Run("When Open returns ErrCallerClosed, the error shall also match io.EOF.", func(t *testing.T) {
		t.Parallel()
		for name, sent := range map[string][]byte{"silent": nil, "one answer": request(doVerb, echo), "text": []byte("hello")} {
			t.Run("a caller that closes, "+name, func(t *testing.T) {
				t.Parallel()
				pair := connect(t)
				call := openOn(t.Context(), pair.server)
				if sent != nil {
					write(t, pair.client, sent)
				}
				_ = pair.client.CloseWrite()
				got := call.result(t, time.Now().Add(margin))
				if !errors.Is(got.err, telnet.ErrCallerClosed) || !errors.Is(got.err, io.EOF) {
					t.Fatalf("Open returned %v, want ErrCallerClosed matching io.EOF", got.err)
				}
			})
		}
	})
	t.Run("When negotiation ends with an outcome, Open shall return a Line that writes first, in order, the replies of a read that returned bytes with a passed deadline, which Negotiate did not write.", func(t *testing.T) {
		t.Parallel()
		t.Run("DO 24 and DO 31 read with a passed deadline: TimedOut, then WONT 24 and WONT 31 before the bytes queued after", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := openOn(t.Context(), &splitRead{TCPConn: pair.server, marker: 'z', err: os.ErrDeadlineExceeded})
			expectReceived(t, pair.client, opening)
			write(t, pair.client, join(request(doVerb, echo), request(doVerb, telnetTypeOption), request(doVerb, windowSizeOption), []byte("z")))
			got := call.result(t, time.Now().Add(margin))
			if got.err != nil || got.outcome != telnet.TimedOut {
				t.Fatalf("Open returned (%v, %v), want TimedOut", got.outcome, got.err)
			}
			expectQuiet(t, pair.client)
			sendAll(t, got.line, []byte("q"))
			flush(t, got.line)
			expectReceived(t, pair.client, join(request(wont, telnetTypeOption), request(wont, windowSizeOption), []byte("q")))
			expectQuiet(t, pair.client)
		})
		t.Run("the same replies go out first when the Line first waits for the caller", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := openOn(t.Context(), &splitRead{TCPConn: pair.server, marker: 'z', err: os.ErrDeadlineExceeded})
			expectReceived(t, pair.client, opening)
			write(t, pair.client, join(request(doVerb, telnetTypeOption), []byte("z")))
			got := call.result(t, time.Now().Add(margin))
			done := make(chan byte, 1)
			go func() {
				value, err := got.line.RecvChar(t.Context(), time.Now().Add(5*time.Second))
				if err != nil {
					t.Errorf("RecvChar returned %v", err)
				}
				done <- value
			}()
			expectReceived(t, pair.client, request(wont, telnetTypeOption))
			write(t, pair.client, []byte("k"))
			if value := <-done; value != 'k' {
				t.Fatalf("RecvChar returned %#02x, want k", value)
			}
		})
		t.Run("the replies of a read that met the caller's close are not owed: Open returns ErrCallerClosed", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := openOn(t.Context(), &splitRead{TCPConn: pair.server, marker: 'z'})
			expectReceived(t, pair.client, opening)
			write(t, pair.client, join(request(doVerb, telnetTypeOption), []byte("z")))
			got := call.result(t, time.Now().Add(margin))
			if !errors.Is(got.err, telnet.ErrCallerClosed) || got.line != nil {
				t.Fatalf("Open returned (%v, %v), want a nil Line and ErrCallerClosed", got.line, got.err)
			}
			expectNothingWritten(t, pair)
		})
	})
	t.Run("When negotiation ends with an outcome after Receive returned true, Open shall return a Line whose receive buffer holds, unread and in order, every byte negotiation's last read returned after the byte at which Receive returned true, and no other byte.", func(t *testing.T) {
		t.Parallel()
		t.Run("text before the answers, alice after them, then the caller's close: alice, then end of file", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := openOn(t.Context(), pair.server)
			expectReceived(t, pair.client, opening)
			write(t, pair.client, join([]byte("xy"), answers, []byte("alice")))
			got := call.result(t, time.Now().Add(margin))
			if got.err != nil || got.outcome != telnet.Answered {
				t.Fatalf("Open returned (%v, %v), want Answered", got.outcome, got.err)
			}
			_ = pair.client.CloseWrite()
			expectData(t, got.line, []byte("alice"))
			if value, err := recv(t, got.line); !errors.Is(err, io.EOF) {
				t.Fatalf("after alice RecvChar returned %#02x and %v, want end of file", value, err)
			}
		})
		t.Run("a request after the answers in the same read is answered by the Line, in place", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, join([]byte("a"), request(doVerb, telnetTypeOption), []byte("b")))
			expectData(t, line, []byte("ab"))
			flush(t, line)
			expectReceived(t, pair.client, request(wont, telnetTypeOption))
		})
		t.Run("the 255 data byte after the answers, split as IAC IAC: one data byte 255", func(t *testing.T) {
			t.Parallel()
			_, line := answeredLine(t, []byte{iac, iac, 'q'})
			expectData(t, line, []byte{iac, 'q'})
		})
	})
	t.Run("When negotiation ends TimedOut before Receive returned true, Open shall return a Line whose receive buffer is empty.", func(t *testing.T) {
		t.Parallel()
		t.Run("text and one answer during negotiation, then silence: the Line returns only what comes after", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := openOn(t.Context(), pair.server)
			expectReceived(t, pair.client, opening)
			write(t, pair.client, join([]byte("early"), request(doVerb, echo), []byte("text")))
			got := call.result(t, call.called.Add(negotiationLimit+margin))
			if got.err != nil || got.outcome != telnet.TimedOut {
				t.Fatalf("Open returned (%v, %v), want TimedOut", got.outcome, got.err)
			}
			write(t, pair.client, []byte("late"))
			expectData(t, got.line, []byte("late"))
		})
		t.Run("a request split at the 3 seconds: the Line reads its last byte as the end of it", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := openOn(t.Context(), pair.server)
			expectReceived(t, pair.client, opening)
			write(t, pair.client, []byte{iac, doVerb})
			got := call.result(t, call.called.Add(negotiationLimit+margin))
			if got.err != nil || got.outcome != telnet.TimedOut {
				t.Fatalf("Open returned (%v, %v), want TimedOut", got.outcome, got.err)
			}
			write(t, pair.client, []byte{telnetTypeOption, 'k'})
			expectData(t, got.line, []byte("k"))
			flush(t, got.line)
			expectReceived(t, pair.client, request(wont, telnetTypeOption))
		})
	})
	t.Run("When it returns an error, Open shall return a nil Line.", func(t *testing.T) {
		t.Parallel()
		t.Run("the context ended before the call", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			if got := openOn(cancelled(t), pair.server).result(t, time.Now().Add(margin)); !errors.Is(got.err, telnet.ErrDeadlineEnded) || got.line != nil {
				t.Fatalf("Open returned (%v, %v), want a nil Line and ErrDeadlineEnded", got.line, got.err)
			}
		})
		t.Run("the caller closes", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := openOn(t.Context(), pair.server)
			_ = pair.client.CloseWrite()
			if got := call.result(t, time.Now().Add(margin)); !errors.Is(got.err, telnet.ErrCallerClosed) || got.line != nil {
				t.Fatalf("Open returned (%v, %v), want a nil Line and ErrCallerClosed", got.line, got.err)
			}
		})
		t.Run("the caller resets", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := openOn(t.Context(), pair.server)
			expectReceived(t, pair.client, opening)
			reset(t, pair.client)
			if got := call.result(t, time.Now().Add(margin)); !errors.Is(got.err, telnet.ErrConnectionFailed) || got.line != nil {
				t.Fatalf("Open returned (%v, %v), want a nil Line and ErrConnectionFailed", got.line, got.err)
			}
		})
	})
}

func TestLine(t *testing.T) {
	t.Parallel()
	t.Run("SendChar shall queue a byte other than 255 as itself, and the data byte 255 as IAC IAC.", func(t *testing.T) {
		t.Parallel()
		t.Run("every byte value, then Flush", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			values := make([]byte, 256)
			for code := range values {
				values[code] = byte(code)
			}
			sendAll(t, line, values)
			flush(t, line)
			expectReceived(t, pair.client, join(values[:255], []byte{iac, iac}))
		})
		t.Run("255 three times between text", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			sendAll(t, line, []byte{'a', iac, iac, 'b', iac})
			flush(t, line)
			expectReceived(t, pair.client, []byte{'a', iac, iac, iac, iac, 'b', iac, iac})
		})
	})
	t.Run("If the context has ended when SendChar is called, then SendChar shall queue nothing and return the context's error, wrapped.", func(t *testing.T) {
		t.Parallel()
		for name, ctx := range map[string]func(t *testing.T) context.Context{
			"cancelled": cancelled,
			"its deadline passed": func(t *testing.T) context.Context {
				t.Helper()
				return withDeadline(t, time.Now().Add(-time.Second))
			},
		} {
			t.Run(name+": x is not queued, y after it is", func(t *testing.T) {
				t.Parallel()
				pair, line := answeredLine(t, nil)
				err := line.SendChar(ctx(t), 'x')
				if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("SendChar returned %v, want the context's error", err)
				}
				sendAll(t, line, []byte("y"))
				flush(t, line)
				expectReceived(t, pair.client, []byte("y"))
				expectQuiet(t, pair.client)
			})
		}
	})
	t.Run("When the send buffer has room for the byte, or for both bytes of IAC IAC, SendChar shall queue it without writing and return no error.", func(t *testing.T) {
		t.Parallel()
		t.Run("one byte: nothing written until Flush", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			sendAll(t, line, []byte("a"))
			expectQuiet(t, pair.client)
			flush(t, line)
			expectReceived(t, pair.client, []byte("a"))
		})
		t.Run("1024 bytes, the buffer full: nothing written until Flush", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			sendAll(t, line, repeated([]byte("n"), sendBufferBytes))
			expectQuiet(t, pair.client)
			flush(t, line)
			expectReceived(t, pair.client, repeated([]byte("n"), sendBufferBytes))
		})
		t.Run("1022 bytes then 255: IAC IAC fits, nothing written until Flush", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			sendAll(t, line, join(repeated([]byte("n"), sendBufferBytes-2), []byte{iac}))
			expectQuiet(t, pair.client)
			flush(t, line)
			expectReceived(t, pair.client, join(repeated([]byte("n"), sendBufferBytes-2), []byte{iac, iac}))
		})
	})
	t.Run("When the send buffer has no room for the byte, or for both bytes of IAC IAC, SendChar shall first write it out as Flush does, with Flush's results, and queue nothing unless that write emptied it.", func(t *testing.T) {
		t.Parallel()
		t.Run("the 1025th byte: the 1024 written, the 1025th queued", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			sendAll(t, line, repeated([]byte("n"), sendBufferBytes))
			sendAll(t, line, []byte("z"))
			expectReceived(t, pair.client, repeated([]byte("n"), sendBufferBytes))
			expectQuiet(t, pair.client)
			flush(t, line)
			expectReceived(t, pair.client, []byte("z"))
		})
		t.Run("255 with 1023 queued: the 1023 written, IAC IAC queued", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			sendAll(t, line, repeated([]byte("n"), sendBufferBytes-1))
			sendAll(t, line, []byte{iac})
			expectReceived(t, pair.client, repeated([]byte("n"), sendBufferBytes-1))
			expectQuiet(t, pair.client)
			flush(t, line)
			expectReceived(t, pair.client, []byte{iac, iac})
		})
		t.Run("a full buffer that cannot be written before the context's deadline: its error, and the byte not queued", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			fill(t, pair.server)
			queued := repeated([]byte("q"), sendBufferBytes)
			sendAll(t, line, queued)
			deadline := time.Now().Add(300 * time.Millisecond)
			if err := line.SendChar(withDeadline(t, deadline), 'r'); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("SendChar returned %v, want the context's deadline", err)
			}
			expectWithin(t, "SendChar's return", time.Now(), deadline, deadline.Add(margin))
			// r is never written: neither queued then, nor written by anything after the failure.
			expectNothingMore(t, pair, line, queued)
		})
	})
	t.Run("Flush shall write the send buffer's bytes in order, and leave it empty once they are written.", func(t *testing.T) {
		t.Parallel()
		t.Run("abc, Flush, Flush: abc once", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			sendAll(t, line, []byte("abc"))
			flush(t, line)
			flush(t, line)
			expectReceived(t, pair.client, []byte("abc"))
			expectQuiet(t, pair.client)
		})
		t.Run("Flush with nothing queued writes nothing", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			flush(t, line)
			expectQuiet(t, pair.client)
		})
	})
	t.Run("If the context has ended when Flush is called, or ends while it waits, then Flush shall write nothing more and return the context's error, wrapped.", func(t *testing.T) {
		t.Parallel()
		t.Run("cancelled before the call: nothing written, abc kept for the next Flush", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			sendAll(t, line, []byte("abc"))
			if err := line.Flush(cancelled(t)); !errors.Is(err, context.Canceled) {
				t.Fatalf("Flush returned %v, want context.Canceled", err)
			}
			expectQuiet(t, pair.client)
			flush(t, line)
			expectReceived(t, pair.client, []byte("abc"))
		})
		t.Run("cancelled while it waits on a caller that does not read: returns at once with context.Canceled", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			fill(t, pair.server)
			queued := []byte("queued")
			sendAll(t, line, queued)
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- line.Flush(ctx) }()
			expectStillWaiting(t, done)
			cancel()
			cancelledAt := time.Now()
			err := <-done
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Flush returned %v, want context.Canceled", err)
			}
			expectWithin(t, "Flush's return", time.Now(), cancelledAt, cancelledAt.Add(margin))
			expectNothingMore(t, pair, line, queued)
		})
		t.Run("its deadline passes while it waits: context.DeadlineExceeded at the deadline", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			fill(t, pair.server)
			queued := []byte("queued")
			sendAll(t, line, queued)
			deadline := time.Now().Add(500 * time.Millisecond)
			err := line.Flush(endsLate(t, deadline))
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Flush returned %v, want context.DeadlineExceeded", err)
			}
			expectWithin(t, "Flush's return", time.Now(), deadline, deadline.Add(margin))
			expectNothingMore(t, pair, line, queued)
		})
	})
	t.Run("If a write fails otherwise, then Flush shall return ErrConnectionFailed.", func(t *testing.T) {
		t.Parallel()
		t.Run("the caller resets: ErrConnectionFailed", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			reset(t, pair.client)
			var err error
			for range 50 {
				sendAll(t, line, repeated([]byte("x"), 100))
				if err = line.Flush(t.Context()); err != nil {
					break
				}
				wait(t.Context(), time.Now().Add(10*time.Millisecond))
			}
			if !errors.Is(err, telnet.ErrConnectionFailed) {
				t.Fatalf("Flush returned %v, want ErrConnectionFailed", err)
			}
		})
	})
	t.Run("After a write has failed, whatever it wrote, every later SendChar, Flush and RecvChar on the Line shall write nothing and return ErrConnectionFailed.", func(t *testing.T) {
		t.Parallel()
		t.Run("a Flush cut short by its context's deadline", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, []byte("waiting"))
			fill(t, pair.server)
			queued := repeated([]byte("abcdefghij"), 300)
			ctx := withDeadline(t, time.Now().Add(300*time.Millisecond))
			var sent []byte
			for _, value := range queued {
				if line.SendChar(ctx, value) != nil {
					break
				}
				sent = append(sent, value)
			}
			if err := line.Flush(ctx); err == nil {
				t.Fatalf("Flush returned no error on a caller that does not read")
			}
			// RecvChar fails too, though the caller's bytes are waiting.
			expectNothingMore(t, pair, line, sent)
		})
		t.Run("a RecvChar whose write of the queued bytes its deadline cuts short", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			fill(t, pair.server)
			queued := []byte("queued")
			sendAll(t, line, queued)
			if _, err := line.RecvChar(t.Context(), time.Now().Add(300*time.Millisecond)); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("RecvChar returned %v, want os.ErrDeadlineExceeded", err)
			}
			write(t, pair.client, []byte("k"))
			expectNothingMore(t, pair, line, queued)
		})
		t.Run("a Flush the caller's reset fails", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			reset(t, pair.client)
			var err error
			for range 50 {
				sendAll(t, line, repeated([]byte("x"), 100))
				if err = line.Flush(t.Context()); err != nil {
					break
				}
				wait(t.Context(), time.Now().Add(10*time.Millisecond))
			}
			if !errors.Is(err, telnet.ErrConnectionFailed) {
				t.Fatalf("Flush returned %v, want ErrConnectionFailed", err)
			}
			for name, call := range map[string]func() error{
				"SendChar": func() error { return line.SendChar(t.Context(), 'x') },
				"Flush":    func() error { return line.Flush(t.Context()) },
				"RecvChar": func() error { _, err := line.RecvChar(t.Context(), time.Now().Add(margin)); return err },
			} {
				if err := call(); !errors.Is(err, telnet.ErrConnectionFailed) {
					t.Fatalf("%s after the failed write returned %v, want ErrConnectionFailed", name, err)
				}
			}
		})
		t.Run("a Flush whose context had ended before it wrote is no failed write: the bytes go with the next", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			sendAll(t, line, []byte("abc"))
			_ = line.Flush(cancelled(t))
			flush(t, line)
			expectReceived(t, pair.client, []byte("abc"))
		})
	})
	t.Run("RecvChar shall return the caller's data bytes in the order sent, and no byte of a Telnet command.", func(t *testing.T) {
		t.Parallel()
		input := join([]byte("ab"), request(doVerb, telnetTypeOption), []byte{iac, nop}, []byte("c"),
			[]byte{iac, subnegotiationBegin, telnetTypeOption, 'x', iac, iac, subnegotiationEnd, 'y', iac, subnegotiationEnd},
			[]byte{iac, iac}, request(will, windowSizeOption), []byte("d"))
		want, _ := lineReadsAs(input)
		t.Run("text among commands, in one write", func(t *testing.T) {
			t.Parallel()
			_, line := answeredLine(t, input)
			expectData(t, line, want)
		})
		t.Run("the same, a byte at a time", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			go func() {
				for _, value := range input {
					_, _ = pair.client.Write([]byte{value})
					wait(t.Context(), time.Now().Add(2*time.Millisecond))
				}
			}()
			expectData(t, line, want)
		})
		t.Run("every byte 0 to 254 as data", func(t *testing.T) {
			t.Parallel()
			values := make([]byte, 255)
			for code := range values {
				values[code] = byte(code)
			}
			_, line := answeredLine(t, values)
			expectData(t, line, values)
		})
	})
	t.Run("RecvChar shall read no byte after the data byte it returns.", func(t *testing.T) {
		t.Parallel()
		t.Run("a, then DO 24, then b: no reply until RecvChar reads past a", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, join([]byte("a"), request(doVerb, telnetTypeOption), []byte("b")))
			expectData(t, line, []byte("a"))
			flush(t, line)
			expectQuiet(t, pair.client)
			expectData(t, line, []byte("b"))
			flush(t, line)
			expectReceived(t, pair.client, request(wont, telnetTypeOption))
		})
		t.Run("a, then DONT ECHO: Echoes stays true until RecvChar reads past a", func(t *testing.T) {
			t.Parallel()
			_, line := answeredLine(t, join([]byte("a"), request(dont, echo), []byte("b")))
			expectData(t, line, []byte("a"))
			if !line.Echoes() {
				t.Fatalf("Echoes is false before RecvChar read DONT ECHO")
			}
			expectData(t, line, []byte("b"))
			if line.Echoes() {
				t.Fatalf("Echoes is true after RecvChar read DONT ECHO")
			}
		})
	})
	t.Run("RecvChar shall queue Strip's replies as they are, unescaped, in order.", func(t *testing.T) {
		t.Parallel()
		t.Run("DO 255, WILL 31, DONT ECHO, DO ECHO, then x: their replies in order, 255 not doubled", func(t *testing.T) {
			t.Parallel()
			input := join(request(doVerb, 255), request(will, windowSizeOption), request(dont, echo), request(doVerb, echo), []byte("x"))
			_, wantReplies := lineReadsAs(input)
			pair, line := answeredLine(t, input)
			expectData(t, line, []byte("x"))
			flush(t, line)
			expectReceived(t, pair.client, wantReplies)
			expectQuiet(t, pair.client)
		})
		t.Run("replies queued after bytes SendChar queued, and before those queued after", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, join(request(doVerb, telnetTypeOption), []byte("x")))
			sendAll(t, line, []byte("before"))
			expectData(t, line, []byte("x"))
			sendAll(t, line, []byte("after"))
			flush(t, line)
			expectReceived(t, pair.client, join([]byte("before"), request(wont, telnetTypeOption), []byte("after")))
		})
	})
	t.Run("Before it hands Strip a byte, RecvChar shall have room for one reply, 3 bytes, writing the send buffer out as Flush does, under deadline, when it has not.", func(t *testing.T) {
		t.Parallel()
		for _, held := range []int{sendBufferBytes - 2, sendBufferBytes - 3, sendBufferBytes} {
			t.Run(fmt.Sprintf("%d bytes queued, DO 24 and x in the receive buffer: the queued bytes, then WONT 24", held), func(t *testing.T) {
				t.Parallel()
				// DO 24 and x came with the answers, so RecvChar finds them without waiting for
				// the caller and writes nothing unless it needs room.
				pair, line := answeredLine(t, join(request(doVerb, telnetTypeOption), []byte("x")))
				sendAll(t, line, repeated([]byte("n"), held))
				expectData(t, line, []byte("x"))
				flush(t, line)
				expectReceived(t, pair.client, join(repeated([]byte("n"), held), request(wont, telnetTypeOption)))
				expectQuiet(t, pair.client)
			})
		}
		t.Run("a thousand DO 24 at once: every reply, whole and in order", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, join(repeated(request(doVerb, telnetTypeOption), 1000), []byte("x")))
			received := make(chan []byte, 1)
			go func() { received <- readExactly(t, pair.client, 3000, time.Now().Add(5*time.Second)) }()
			expectData(t, line, []byte("x"))
			flush(t, line)
			if got := <-received; !bytes.Equal(got, repeated(request(wont, telnetTypeOption), 1000)) {
				t.Fatalf("the replies to a thousand DO 24 were not a thousand WONT 24")
			}
		})
	})
	t.Run("Before it waits for the caller, RecvChar shall write the send buffer out as Flush does, under deadline.", func(t *testing.T) {
		t.Parallel()
		t.Run("abc queued, the caller silent: abc arrives while RecvChar waits", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			sendAll(t, line, []byte("abc"))
			done := make(chan byte, 1)
			go func() {
				value, err := line.RecvChar(t.Context(), time.Now().Add(5*time.Second))
				if err != nil {
					t.Errorf("RecvChar returned %v", err)
				}
				done <- value
			}()
			expectReceived(t, pair.client, []byte("abc"))
			write(t, pair.client, []byte("k"))
			if value := <-done; value != 'k' {
				t.Fatalf("RecvChar returned %#02x, want k", value)
			}
		})
		t.Run("a reply queued by RecvChar itself goes out before it waits", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, request(doVerb, telnetTypeOption))
			done := make(chan byte, 1)
			go func() {
				value, err := line.RecvChar(t.Context(), time.Now().Add(5*time.Second))
				if err != nil {
					t.Errorf("RecvChar returned %v", err)
				}
				done <- value
			}()
			expectReceived(t, pair.client, request(wont, telnetTypeOption))
			write(t, pair.client, []byte("k"))
			<-done
		})
		t.Run("the caller not reading: RecvChar waits on that write and returns os.ErrDeadlineExceeded at its deadline", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			fill(t, pair.server)
			sendAll(t, line, []byte("queued"))
			deadline := time.Now().Add(500 * time.Millisecond)
			if _, err := line.RecvChar(t.Context(), deadline); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("RecvChar returned %v, want os.ErrDeadlineExceeded", err)
			}
			expectWithin(t, "RecvChar's return", time.Now(), deadline, deadline.Add(margin))
		})
	})
	t.Run("Once deadline has passed, RecvChar shall return os.ErrDeadlineExceeded, even with bytes in the receive buffer.", func(t *testing.T) {
		t.Parallel()
		t.Run("abc waiting, a deadline already past: os.ErrDeadlineExceeded, then b and c", func(t *testing.T) {
			t.Parallel()
			_, line := answeredLine(t, []byte("abc"))
			expectData(t, line, []byte("a"))
			if value, err := line.RecvChar(t.Context(), time.Now().Add(-time.Millisecond)); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("RecvChar returned %#02x and %v, want os.ErrDeadlineExceeded", value, err)
			}
			expectData(t, line, []byte("bc"))
		})
		t.Run("a silent caller: os.ErrDeadlineExceeded at the deadline", func(t *testing.T) {
			t.Parallel()
			_, line := answeredLine(t, nil)
			deadline := time.Now().Add(500 * time.Millisecond)
			if _, err := line.RecvChar(t.Context(), deadline); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("RecvChar returned %v, want os.ErrDeadlineExceeded", err)
			}
			expectWithin(t, "RecvChar's return", time.Now(), deadline, deadline.Add(margin))
		})
	})
	t.Run("If the caller closes its side while no data byte is waiting, then RecvChar shall return io.EOF.", func(t *testing.T) {
		t.Parallel()
		rows := map[string][]byte{"nothing sent": nil, "ab sent first": []byte("ab"), "DO 24 sent first": request(doVerb, telnetTypeOption)}
		for name, sent := range rows {
			t.Run(name+": the data, then io.EOF", func(t *testing.T) {
				t.Parallel()
				pair, line := answeredLine(t, sent)
				_ = pair.client.CloseWrite()
				data, _ := lineReadsAs(sent)
				expectData(t, line, data)
				if value, err := recv(t, line); !errors.Is(err, io.EOF) {
					t.Fatalf("RecvChar returned %#02x and %v, want io.EOF", value, err)
				}
			})
		}
	})
	t.Run("If the context has ended when RecvChar is called, or ends while it waits, then RecvChar shall return the context's error, wrapped, and no byte.", func(t *testing.T) {
		t.Parallel()
		t.Run("cancelled before the call, with a byte waiting: context.Canceled, the byte kept", func(t *testing.T) {
			t.Parallel()
			_, line := answeredLine(t, []byte("a"))
			if value, err := line.RecvChar(cancelled(t), time.Now().Add(margin)); !errors.Is(err, context.Canceled) || value != 0 {
				t.Fatalf("RecvChar returned %#02x and %v, want no byte and context.Canceled", value, err)
			}
			expectData(t, line, []byte("a"))
		})
		t.Run("cancelled while it waits: context.Canceled at once", func(t *testing.T) {
			t.Parallel()
			_, line := answeredLine(t, nil)
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() {
				_, err := line.RecvChar(ctx, time.Now().Add(10*time.Second))
				done <- err
			}()
			expectStillWaiting(t, done)
			cancel()
			cancelledAt := time.Now()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("RecvChar returned %v, want context.Canceled", err)
			}
			expectWithin(t, "RecvChar's return", time.Now(), cancelledAt, cancelledAt.Add(margin))
		})
		t.Run("the context's deadline before RecvChar's own: context.DeadlineExceeded at the context's", func(t *testing.T) {
			t.Parallel()
			_, line := answeredLine(t, nil)
			deadline := time.Now().Add(500 * time.Millisecond)
			if _, err := line.RecvChar(endsLate(t, deadline), deadline.Add(5*time.Second)); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("RecvChar returned %v, want context.DeadlineExceeded", err)
			}
			expectWithin(t, "RecvChar's return", time.Now(), deadline, deadline.Add(margin))
		})
		t.Run("the context's deadline and RecvChar's at the same moment: the context wins", func(t *testing.T) {
			t.Parallel()
			_, line := answeredLine(t, nil)
			deadline := time.Now().Add(500 * time.Millisecond)
			if _, err := line.RecvChar(endsLate(t, deadline), deadline); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("RecvChar returned %v, want context.DeadlineExceeded", err)
			}
		})
	})
	t.Run("If a read or a write fails otherwise, then RecvChar shall return ErrConnectionFailed.", func(t *testing.T) {
		t.Parallel()
		t.Run("the caller resets while RecvChar waits", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			done := make(chan error, 1)
			go func() {
				_, err := line.RecvChar(t.Context(), time.Now().Add(5*time.Second))
				done <- err
			}()
			expectStillWaiting(t, done)
			reset(t, pair.client)
			if err := <-done; !errors.Is(err, telnet.ErrConnectionFailed) {
				t.Fatalf("RecvChar returned %v, want ErrConnectionFailed", err)
			}
		})
		t.Run("the caller resets, then RecvChar writes a queued reply", func(t *testing.T) {
			t.Parallel()
			pair, line := answeredLine(t, nil)
			reset(t, pair.client)
			var err error
			for range 50 {
				sendAll(t, line, repeated([]byte("x"), 100))
				if _, err = line.RecvChar(t.Context(), time.Now().Add(100*time.Millisecond)); !errors.Is(err, os.ErrDeadlineExceeded) {
					break
				}
			}
			if !errors.Is(err, telnet.ErrConnectionFailed) {
				t.Fatalf("RecvChar returned %v, want ErrConnectionFailed", err)
			}
		})
	})
	t.Run("RecvChar shall keep the bytes a read returns before it looks at that read's error.", func(t *testing.T) {
		t.Parallel()
		t.Run("ab and end of file from one read: a, b, then io.EOF", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := openOn(t.Context(), &splitRead{TCPConn: pair.server, marker: 'z'})
			expectReceived(t, pair.client, opening)
			write(t, pair.client, answers)
			got := call.result(t, time.Now().Add(margin))
			if got.err != nil {
				t.Fatalf("Open returned %v", got.err)
			}
			write(t, pair.client, []byte("abz"))
			expectData(t, got.line, []byte("ab"))
			if value, err := recv(t, got.line); !errors.Is(err, io.EOF) {
				t.Fatalf("RecvChar returned %#02x and %v, want io.EOF", value, err)
			}
		})
	})
	t.Run("While the caller has agreed to ECHO, Echoes shall return true.", func(t *testing.T) {
		t.Parallel()
		t.Run("after DO DO", func(t *testing.T) {
			t.Parallel()
			if _, line := answeredLine(t, nil); !line.Echoes() {
				t.Fatalf("Echoes is false after DO ECHO")
			}
		})
		t.Run("after DONT ECHO, then DO ECHO read by RecvChar", func(t *testing.T) {
			t.Parallel()
			_, line := lineAfter(t, join(request(dont, echo), request(doVerb, sga)), join(request(doVerb, echo), []byte("x")))
			expectData(t, line, []byte("x"))
			if !line.Echoes() {
				t.Fatalf("Echoes is false after a late DO ECHO")
			}
		})
		t.Run("a late yes, DO ECHO after the 3 seconds", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := openOn(t.Context(), pair.server)
			got := call.result(t, call.called.Add(negotiationLimit+margin))
			write(t, pair.client, join(request(doVerb, echo), []byte("x")))
			expectData(t, got.line, []byte("x"))
			if !got.line.Echoes() {
				t.Fatalf("Echoes is false after a late DO ECHO")
			}
		})
	})
	t.Run("While the caller has not agreed to ECHO, Echoes shall return false.", func(t *testing.T) {
		t.Parallel()
		t.Run("after DONT ECHO, DO SGA", func(t *testing.T) {
			t.Parallel()
			if _, line := lineAfter(t, join(request(dont, echo), request(doVerb, sga)), nil); line.Echoes() {
				t.Fatalf("Echoes is true after DONT ECHO")
			}
		})
		t.Run("a caller silent through negotiation", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			got := openOn(t.Context(), pair.server).result(t, time.Now().Add(negotiationLimit+margin))
			if got.err != nil || got.outcome != telnet.TimedOut || got.line == nil {
				t.Fatalf("Open returned (%v, %v, %v), want a Line and TimedOut", got.line, got.outcome, got.err)
			}
			if got.line.Echoes() {
				t.Fatalf("Echoes is true for a caller that never answered")
			}
		})
		t.Run("after DO DO, then DONT ECHO read by RecvChar", func(t *testing.T) {
			t.Parallel()
			_, line := answeredLine(t, join(request(dont, echo), []byte("x")))
			expectData(t, line, []byte("x"))
			if line.Echoes() {
				t.Fatalf("Echoes is true after DONT ECHO")
			}
		})
	})
	t.Run("If the Line was not made by Open, or is nil, then Echoes shall return false.", func(t *testing.T) {
		t.Parallel()
		t.Run("a nil Line", func(t *testing.T) {
			t.Parallel()
			var line *telnet.Line
			if line.Echoes() {
				t.Fatalf("a nil Line echoes")
			}
			probeEchoes(t)
		})
		t.Run("a zero Line", func(t *testing.T) {
			t.Parallel()
			if (&telnet.Line{}).Echoes() {
				t.Fatalf("a zero Line echoes")
			}
			probeEchoes(t)
		})
	})
}

// probeEchoes ends a row whose own Echoes rightly returns false: a Line Open made for a caller
// that answered DO DO echoes, so code that always says false fails the row.
func probeEchoes(t *testing.T) {
	t.Helper()
	if _, line := answeredLine(t, nil); !line.Echoes() {
		t.Fatalf("a Line after DO DO does not echo")
	}
}

// filler is the byte the test writes past the Line to fill what the caller can hold.
const filler byte = 's'

// fill writes filler bytes straight to the server end, past the Line, the caller not reading,
// until a write has to wait: the Line's next write then waits too. How many filler bytes reach
// the caller is not known, since a write cut short may have sent all of it.
func fill(t *testing.T, server *net.TCPConn) {
	t.Helper()
	// Windows takes large writes into its own buffers, so the first chunks are large; Linux still
	// takes a small write once a large one waits, so the chunks shrink until one byte waits too.
	for _, size := range []int{256 << 10, 4 << 10, 64, 1} {
		chunk := repeated([]byte{filler}, size)
		waited := false
		for range 4096 {
			_ = server.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
			if _, err := server.Write(chunk); err != nil {
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("filling: %v", err)
				}
				waited = true
				break
			}
		}
		if !waited {
			t.Fatalf("filling: writes of %d bytes never waited", size)
		}
	}
	_ = server.SetWriteDeadline(time.Time{})
}

// expectNothingMore checks that every later call on a Line whose write failed writes nothing and
// returns ErrConnectionFailed, and that the caller, reading at last, gets filler and then at most
// the bytes queued before the failure, in order: never a byte queued after it.
func expectNothingMore(t *testing.T, pair connected, line *telnet.Line, queuedBefore []byte) {
	t.Helper()
	received := make(chan []byte, 1)
	go func() {
		stream, err := readToEnd(pair.client, time.Now().Add(60*time.Second))
		if !errors.Is(err, io.EOF) {
			t.Errorf("the caller's stream did not end in order: %v", err)
		}
		received <- stream
	}()
	if err := line.SendChar(t.Context(), 'x'); !errors.Is(err, telnet.ErrConnectionFailed) {
		t.Fatalf("SendChar after the failed write returned %v, want ErrConnectionFailed", err)
	}
	if err := line.Flush(t.Context()); !errors.Is(err, telnet.ErrConnectionFailed) {
		t.Fatalf("Flush after the failed write returned %v, want ErrConnectionFailed", err)
	}
	if _, err := line.RecvChar(t.Context(), time.Now().Add(margin)); !errors.Is(err, telnet.ErrConnectionFailed) {
		t.Fatalf("RecvChar after the failed write returned %v, want ErrConnectionFailed", err)
	}
	_ = pair.server.CloseWrite()
	got := bytes.TrimLeft(<-received, string(filler))
	if len(got) > len(queuedBefore) || !bytes.Equal(got, queuedBefore[:len(got)]) {
		t.Fatalf("after the filler the caller received %d bytes, not a part of the %d queued before the failure, in order", len(got), len(queuedBefore))
	}
}

// expectStillWaiting checks a call has not returned yet.
func expectStillWaiting(t *testing.T, done <-chan error) {
	t.Helper()
	timer := time.NewTimer(quiet)
	defer timer.Stop()
	select {
	case err := <-done:
		t.Fatalf("the call returned %v while it should still wait", err)
	case <-timer.C:
	}
}
