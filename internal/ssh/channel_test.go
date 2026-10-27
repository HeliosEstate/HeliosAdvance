// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The Channel, SSH's character calls and its own close, called through their exported names on a
// Channel Accept made over a loopback connection, with QA's own client on the other end.
package ssh_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/ssh"
)

// sendBufferSize is the contract's send buffer, as its line states it.
const sendBufferSize = 1024

var errDeadline = os.ErrDeadlineExceeded

// openCall is a Channel Accept made and the caller on its other end.
type openCall struct {
	client  *rawClient
	channel *ssh.Channel
}

// acceptCall reaches the shell, with a terminal when terminal is set, before is sent first as
// channel data, and window is what the caller lets the engine send.
func acceptCall(t *testing.T, terminal bool, before string, window uint32) openCall {
	t.Helper()
	address, results, _ := acceptPair(t, t.Context(), readKey(t))
	client := dialRaw(t, address)
	client.handshake(curveExchange(t, "curve25519-sha256"), true)
	client.signIn("anyone")
	out := message(messageChannelOpen).text("session").uint32Value(0).uint32Value(window).uint32Value(clientMaxPacket)
	client.sendPacket(out.data)
	reply, err := client.next(time.Now().Add(5 * time.Second))
	if err != nil || reply[0] != messageChannelConfirmation {
		t.Fatalf("the session channel: %v, %v", reply, err)
	}
	parser := &reader{t: t, data: reply[1:]}
	parser.uint32Value()
	client.engineChannel = parser.uint32Value()
	client.windowToServer = parser.uint32Value()
	if before != "" {
		client.sendData(before)
	}
	client.toShell(terminal)
	return openCall{client: client, channel: expectChannel(t, waitAccept(t, results, 5*time.Second))}
}

// sendText queues text with SendChar. Its context ends in 5 seconds, so a SendChar that writes
// where it should only queue, to a caller that lets little through, fails the row rather than
// waiting for good.
func sendText(t *testing.T, channel *ssh.Channel, text []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for _, character := range text {
		if err := channel.SendChar(ctx, character); err != nil {
			t.Fatalf("SendChar of %q: %v", character, err)
		}
	}
}

func flush(t *testing.T, channel *ssh.Channel) {
	t.Helper()
	if err := channel.Flush(t.Context()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
}

// expectQuietCaller waits quietFor and fails the row if any channel data came.
func (client *rawClient) expectQuiet() {
	client.t.Helper()
	before := len(client.received)
	payload, err := client.next(time.Now().Add(quietFor))
	if err == nil || len(client.received) != before {
		client.t.Fatalf("the caller received %q and message %v, want nothing yet", client.received[before:], payload)
	}
}

func cancelled(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	return ctx
}

func TestChannel(t *testing.T) {
	t.Parallel()

	t.Run("SendChar shall queue each byte as itself.", func(t *testing.T) {
		t.Parallel()
		t.Run("every byte from 0 to 255, flushed: those 256 bytes as channel data, 255 not doubled", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			every := make([]byte, 256)
			for index := range every {
				every[index] = byte(index)
			}
			sendText(t, call.channel, every)
			flush(t, call.channel)
			call.client.readData(256, time.Now().Add(5*time.Second))
			call.client.expectQuiet()
			if !bytes.Equal(call.client.received, every) {
				t.Fatalf("the caller received %q, want every byte once", call.client.received)
			}
		})
	})

	t.Run("If the context has ended when SendChar is called, then SendChar shall queue nothing and return the context's error, wrapped.", func(t *testing.T) {
		t.Parallel()
		ctxDeadline, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
		t.Cleanup(cancel)
		for _, row := range []struct {
			name string
			ctx  context.Context
			want error
		}{
			{"a cancelled context", cancelled(t), context.Canceled},
			{"a context whose deadline passed", ctxDeadline, context.DeadlineExceeded},
		} {
			t.Run(row.name+": its error, and z sent after it arrives alone", func(t *testing.T) {
				t.Parallel()
				call := acceptCall(t, false, "", clientWindow)
				if err := call.channel.SendChar(row.ctx, 'a'); !errors.Is(err, row.want) {
					t.Fatalf("SendChar gave %v, want %v", err, row.want)
				}
				sendText(t, call.channel, []byte("z"))
				flush(t, call.channel)
				call.client.readData(1, time.Now().Add(5*time.Second))
				call.client.expectQuiet()
				if string(call.client.received) != "z" {
					t.Fatalf("the caller received %q, want z alone", call.client.received)
				}
			})
		}
	})

	t.Run("When the send buffer has room for the byte, SendChar shall queue it without writing and return no error.", func(t *testing.T) {
		t.Parallel()
		t.Run("1024 bytes, the buffer's whole, edge included: nothing written until the Flush, then all of them", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			text := bytes.Repeat([]byte("abcdefgh"), sendBufferSize/8)
			sendText(t, call.channel, text)
			call.client.expectQuiet()
			flush(t, call.channel)
			call.client.readData(sendBufferSize, time.Now().Add(5*time.Second))
			if !bytes.Equal(call.client.received, text) {
				t.Fatalf("the caller received %d bytes, not the 1024 in order", len(call.client.received))
			}
		})
	})

	t.Run("When the send buffer has no room, SendChar shall first write it out as Flush does, with Flush's results, and queue nothing unless that write emptied it.", func(t *testing.T) {
		t.Parallel()
		t.Run("the 1025th byte: the first 1024 written, the 1025th held until the Flush", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			text := bytes.Repeat([]byte("abcdefgh"), sendBufferSize/8)
			sendText(t, call.channel, append(bytes.Clone(text), 'z'))
			call.client.readData(sendBufferSize, time.Now().Add(5*time.Second))
			call.client.expectQuiet()
			flush(t, call.channel)
			call.client.readData(sendBufferSize+1, time.Now().Add(5*time.Second))
			if !bytes.Equal(call.client.received, append(text, 'z')) {
				t.Fatalf("the caller received %d bytes, not the 1025 in order", len(call.client.received))
			}
		})
		t.Run("the 1025th byte while the caller lets nothing more through and the context ends: the context's error, and every later call io.EOF", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", 16)
			text := bytes.Repeat([]byte("abcdefgh"), sendBufferSize/8)
			sendText(t, call.channel, text)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			t.Cleanup(cancel)
			if err := call.channel.SendChar(ctx, 'z'); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("the 1025th SendChar gave %v, want the context's deadline", err)
			}
			expectFailedAfter(t, call, text)
		})
	})

	t.Run("Flush shall write the send buffer's bytes in order as channel data, and leave it empty once they are written.", func(t *testing.T) {
		t.Parallel()
		t.Run("abc, then d: abcd as channel data, nothing twice", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			sendText(t, call.channel, []byte("abc"))
			flush(t, call.channel)
			flush(t, call.channel)
			sendText(t, call.channel, []byte("d"))
			flush(t, call.channel)
			call.client.readData(4, time.Now().Add(5*time.Second))
			call.client.expectQuiet()
			if string(call.client.received) != "abcd" {
				t.Fatalf("the caller received %q, want abcd", call.client.received)
			}
		})
	})

	t.Run("If the context has ended when Flush is called, or ends while it waits, then Flush shall write nothing more and return the context's error, wrapped.", func(t *testing.T) {
		t.Parallel()
		t.Run("a cancelled context at the call: context.Canceled, nothing written", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			sendText(t, call.channel, []byte("abc"))
			if err := call.channel.Flush(cancelled(t)); !errors.Is(err, context.Canceled) {
				t.Fatalf("Flush gave %v, want context.Canceled", err)
			}
			call.client.expectQuiet()
		})
		t.Run("cancelled while the write waits on a caller that lets 16 bytes through: context.Canceled at once, then every call io.EOF", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", 16)
			text := bytes.Repeat([]byte("abcdefgh"), 12)
			sendText(t, call.channel, text)
			ctx, cancel := context.WithCancel(t.Context())
			flushed := make(chan error, 1)
			go func() { flushed <- call.channel.Flush(ctx) }()
			call.client.readData(16, time.Now().Add(5*time.Second))
			cancelledAt := time.Now()
			cancel()
			select {
			case err := <-flushed:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("Flush gave %v, want context.Canceled", err)
				}
				expectWithin(t, "Flush's return", time.Now(), cancelledAt, cancelledAt.Add(margin))
			case <-time.After(margin + time.Second):
				t.Fatalf("Flush had not returned %v after the cancel", margin+time.Second)
			}
			expectFailedAfter(t, call, text)
		})
	})

	t.Run("If a write fails otherwise, then Flush shall return io.EOF.", func(t *testing.T) {
		t.Parallel()
		t.Run("the caller resets: a Flush soon after gives io.EOF, and none any other error", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			_ = call.client.connection.SetLinger(0)
			_ = call.client.connection.Close()
			until := time.Now().Add(5 * time.Second)
			for {
				sendText(t, call.channel, []byte("x"))
				err := call.channel.Flush(t.Context())
				if err != nil {
					expectEnd(t, "Flush after the reset", err)
					return
				}
				if time.Now().After(until) {
					t.Fatalf("Flush gave no error for 5 seconds after the reset, want io.EOF")
				}
			}
		})
	})

	t.Run("After a write has failed, every later SendChar, Flush and RecvChar on the Channel shall write nothing and return io.EOF, unless the context has ended.", func(t *testing.T) {
		t.Parallel()
		t.Run("after a write the context cut short: each call io.EOF, and nothing of theirs arrives", func(t *testing.T) {
			t.Parallel()
			call := cutWrite(t)
			expectFailedAfter(t, call.openCall, call.cut)
		})
		t.Run("after a write the context cut short, each call under a cancelled context: context.Canceled, then io.EOF under a live one", func(t *testing.T) {
			t.Parallel()
			call := cutWrite(t)
			ended := cancelled(t)
			if err := call.channel.SendChar(ended, 'Q'); !errors.Is(err, context.Canceled) {
				t.Fatalf("SendChar under a cancelled context gave %v, want context.Canceled", err)
			}
			if err := call.channel.Flush(ended); !errors.Is(err, context.Canceled) {
				t.Fatalf("Flush under a cancelled context gave %v, want context.Canceled", err)
			}
			if _, err := call.channel.RecvChar(ended, time.Now().Add(time.Second)); !errors.Is(err, context.Canceled) {
				t.Fatalf("RecvChar under a cancelled context gave %v, want context.Canceled", err)
			}
			expectFailedAfter(t, call.openCall, call.cut)
		})
	})

	t.Run("RecvChar shall return the caller's channel data bytes in the order sent, those sent before the call included, and no byte of extended data.", func(t *testing.T) {
		t.Parallel()
		t.Run("a before the shell, b and extended XY before the call, c while it waits: a, b, c", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "a", clientWindow)
			call.client.sendData("b")
			call.client.sendExtended("XY")
			expectReceived(t, call.channel, "ab")
			call.client.sendExtended("Q")
			call.client.sendData("c")
			expectReceived(t, call.channel, "c")
			expectNothingMore(t, call.channel)
		})
		t.Run("3 MiB of extended data, more than the engine's window, then abc: a, b, c", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			// Extended data counts against the window like any other, and only the engine's
			// discarding gives that room back: if the discarding stopped, the caller would stall.
			chunk := strings.Repeat("Q", 16*1024)
			deadline := time.Now().Add(15 * time.Second)
			for sent := 0; sent < 3*1024*1024; sent += len(chunk) {
				// next would wait on past a window adjust for another message, so the adjusts
				// are read here.
				for call.client.windowToServer < wireLength(len(chunk)) {
					payload, err := call.client.nextIgnoring(deadline)
					if err != nil {
						t.Fatalf("after %d bytes of extended data the engine gave no room back: %v", sent, err)
					}
					if payload[0] == messageWindowAdjust {
						parser := &reader{t: t, data: payload[1:]}
						parser.uint32Value()
						call.client.windowToServer += parser.uint32Value()
					}
				}
				call.client.sendExtended(chunk)
				call.client.windowToServer -= wireLength(len(chunk))
			}
			call.client.sendData("abc")
			expectReceived(t, call.channel, "abc")
		})
	})

	t.Run("Before it waits for the caller, RecvChar shall write the send buffer out as Flush does, under deadline.", func(t *testing.T) {
		t.Parallel()
		t.Run("x queued, then RecvChar: x reaches the caller, whose y then comes back", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			sendText(t, call.channel, []byte("x"))
			received := make(chan byte, 1)
			go func() {
				got, err := call.channel.RecvChar(t.Context(), time.Now().Add(5*time.Second))
				if err != nil {
					t.Errorf("RecvChar gave %v", err)
				}
				received <- got
			}()
			call.client.readData(1, time.Now().Add(5*time.Second))
			call.client.sendData("y")
			if got := <-received; got != 'y' || string(call.client.received) != "x" {
				t.Fatalf("RecvChar gave %q and the caller received %q, want y and x", got, call.client.received)
			}
		})
	})

	t.Run("Once deadline has passed, RecvChar shall return os.ErrDeadlineExceeded, even with bytes waiting, unless an earlier write on the Channel has failed, or no byte is waiting and the caller's data has ended; then it shall return io.EOF.", func(t *testing.T) {
		t.Parallel()
		t.Run("ab waiting, a read, then a deadline already past: os.ErrDeadlineExceeded, and b is still there", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "ab", clientWindow)
			expectReceived(t, call.channel, "a")
			if got, err := call.channel.RecvChar(t.Context(), time.Now().Add(-time.Second)); !errors.Is(err, errDeadline) {
				t.Fatalf("RecvChar gave %q, %v, want os.ErrDeadlineExceeded", got, err)
			}
			expectReceived(t, call.channel, "b")
		})
		t.Run("nothing waiting: os.ErrDeadlineExceeded at the deadline", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			deadline := time.Now().Add(time.Second)
			_, err := call.channel.RecvChar(t.Context(), deadline)
			returned := time.Now()
			if !errors.Is(err, errDeadline) {
				t.Fatalf("RecvChar gave %v, want os.ErrDeadlineExceeded", err)
			}
			expectWithin(t, "RecvChar's return", returned, deadline, deadline.Add(margin))
		})
		t.Run("end of file, io.EOF, then a call whose deadline has passed: io.EOF again, the stored end winning", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			call.client.sendPacket(message(messageChannelEOF).uint32Value(call.client.engineChannel).data)
			if got, err := call.channel.RecvChar(t.Context(), time.Now().Add(5*time.Second)); !errors.Is(err, io.EOF) {
				t.Fatalf("RecvChar gave %q, %v, want io.EOF", got, err)
			}
			if got, err := call.channel.RecvChar(t.Context(), time.Now().Add(-time.Second)); !errors.Is(err, io.EOF) {
				t.Fatalf("the next RecvChar, its deadline past, gave %q, %v, want io.EOF", got, err)
			}
		})
		t.Run("a reset seen by RecvChar, then a call whose deadline has passed: io.EOF, the ended data winning", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			_ = call.client.connection.SetLinger(0)
			_ = call.client.connection.Close()
			_, err := call.channel.RecvChar(t.Context(), time.Now().Add(5*time.Second))
			expectEnd(t, "RecvChar after the reset", err)
			_, err = call.channel.RecvChar(t.Context(), time.Now().Add(-time.Second))
			expectEnd(t, "the next RecvChar, its deadline past,", err)
		})
		t.Run("a write the context cut short, then a call whose deadline has passed: io.EOF, the failed write winning", func(t *testing.T) {
			t.Parallel()
			call := cutWrite(t)
			_, err := call.channel.RecvChar(t.Context(), time.Now().Add(-time.Second))
			expectEnd(t, "RecvChar, its deadline past,", err)
		})
		t.Run("ab and end of file before the shell, then a call whose deadline has passed: os.ErrDeadlineExceeded, the bytes waiting, then a, b and io.EOF", func(t *testing.T) {
			t.Parallel()
			client, results := endBeforeShell(t, false, "ab")
			client.toShell(false)
			channel := expectChannel(t, waitAccept(t, results, 5*time.Second))
			// Time for any read the shell's wait began to finish: with a and b waiting, a stored
			// end must not win over the deadline.
			waitUntil(t, time.Now().Add(quietFor))
			if got, err := channel.RecvChar(t.Context(), time.Now().Add(-time.Second)); !errors.Is(err, errDeadline) {
				t.Fatalf("RecvChar, its deadline past, gave %q, %v, want os.ErrDeadlineExceeded", got, err)
			}
			expectReceived(t, channel, "ab")
			if got, err := channel.RecvChar(t.Context(), time.Now().Add(5*time.Second)); !errors.Is(err, io.EOF) {
				t.Fatalf("after a and b RecvChar gave %q, %v, want io.EOF", got, err)
			}
		})
	})

	t.Run("If the caller's data ends, however it ends, while no byte is waiting, then RecvChar shall return io.EOF.", func(t *testing.T) {
		t.Parallel()
		t.Run("the caller resets while RecvChar waits: io.EOF", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			received := make(chan error, 1)
			go func() {
				_, err := call.channel.RecvChar(t.Context(), time.Now().Add(5*time.Second))
				received <- err
			}()
			waitUntil(t, time.Now().Add(quietFor))
			_ = call.client.connection.SetLinger(0)
			_ = call.client.connection.Close()
			expectEnd(t, "RecvChar", <-received)
		})
		for _, row := range []struct {
			name string
			end  func(client *rawClient)
		}{
			{"end of file", func(client *rawClient) {
				client.sendPacket(message(messageChannelEOF).uint32Value(client.engineChannel).data)
			}},
			{"the channel's close", func(client *rawClient) {
				client.sendPacket(message(messageChannelClose).uint32Value(client.engineChannel).data)
			}},
			{connectionCloseRow, func(client *rawClient) { _ = client.connection.CloseWrite() }},
			{disconnectRow, func(client *rawClient) { client.sendPacket(disconnectMessage()) }},
		} {
			t.Run("ab, then "+row.name+": a, b, then io.EOF", func(t *testing.T) {
				t.Parallel()
				call := acceptCall(t, false, "", clientWindow)
				call.client.sendData("ab")
				row.end(call.client)
				expectReceived(t, call.channel, "ab")
				_, err := call.channel.RecvChar(t.Context(), time.Now().Add(5*time.Second))
				expectEnd(t, "RecvChar after a and b", err)
			})
		}
	})

	t.Run("If the write it makes before it waits fails, other than by its deadline or the context, then RecvChar shall return io.EOF.", func(t *testing.T) {
		t.Parallel()
		for _, row := range []struct {
			name string
			end  func(client *rawClient)
		}{
			{"a reset", func(client *rawClient) {
				_ = client.connection.SetLinger(0)
				_ = client.connection.Close()
			}},
			{connectionCloseRow, func(client *rawClient) { _ = client.connection.Close() }},
			{disconnectRow, func(client *rawClient) { client.sendPacket(disconnectMessage()) }},
		} {
			t.Run("with a terminal, x read and its echo queued, then "+row.name+": io.EOF, then Flush, SendChar and RecvChar io.EOF", func(t *testing.T) {
				t.Parallel()
				call := echoMeetsEnd(t, row.end)
				// The echo either failed in RecvChar's write or fails in Flush's: io.EOF both ways,
				// and every call after it io.EOF.
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				expectEnd(t, "Flush", call.channel.Flush(ctx))
				expectEnd(t, "SendChar", call.channel.SendChar(ctx, 'y'))
				_, err := call.channel.RecvChar(ctx, time.Now().Add(time.Second))
				expectEnd(t, "the next RecvChar", err)
			})
		}
		t.Run("96 bytes queued to a caller that lets 16 through, the write cut by RecvChar's deadline: os.ErrDeadlineExceeded at the deadline, then every call io.EOF", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", 16)
			text := bytes.Repeat([]byte("abcdefgh"), 12)
			sendText(t, call.channel, text)
			deadline := time.Now().Add(time.Second)
			_, err := call.channel.RecvChar(t.Context(), deadline)
			returned := time.Now()
			if !errors.Is(err, errDeadline) {
				t.Fatalf("RecvChar gave %v, want os.ErrDeadlineExceeded", err)
			}
			expectWithin(t, "RecvChar's return", returned, deadline, deadline.Add(margin))
			expectFailedAfter(t, call, text)
		})
	})

	t.Run("If the context has ended when RecvChar is called, or ends while it waits, then RecvChar shall return the context's error, wrapped, and no byte.", func(t *testing.T) {
		t.Parallel()
		t.Run("a cancelled context with a waiting: context.Canceled, and a is still there", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "a", clientWindow)
			if got, err := call.channel.RecvChar(cancelled(t), time.Now().Add(5*time.Second)); !errors.Is(err, context.Canceled) {
				t.Fatalf("RecvChar gave %q, %v, want context.Canceled", got, err)
			}
			expectReceived(t, call.channel, "a")
		})
		t.Run("the context's deadline passing while it waits: context.DeadlineExceeded at the deadline", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			deadline := time.Now().Add(time.Second)
			ctx, cancel := context.WithDeadline(t.Context(), deadline)
			t.Cleanup(cancel)
			_, err := call.channel.RecvChar(ctx, time.Now().Add(5*time.Second))
			returned := time.Now()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("RecvChar gave %v, want context.DeadlineExceeded", err)
			}
			expectWithin(t, "RecvChar's return", returned, deadline, deadline.Add(margin))
		})
		t.Run("cancelled while it waits: context.Canceled at once", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			ctx, cancel := context.WithCancel(t.Context())
			received := make(chan error, 1)
			go func() {
				_, err := call.channel.RecvChar(ctx, time.Now().Add(5*time.Second))
				received <- err
			}()
			waitUntil(t, time.Now().Add(quietFor))
			cancelledAt := time.Now()
			cancel()
			select {
			case err := <-received:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("RecvChar gave %v, want context.Canceled", err)
				}
				expectWithin(t, "RecvChar's return", time.Now(), cancelledAt, cancelledAt.Add(margin))
			case <-time.After(margin + time.Second):
				t.Fatalf("RecvChar had not returned %v after the cancel", margin+time.Second)
			}
		})
	})

	t.Run("While the caller asked for a terminal before the shell, Echoes shall return true.", func(t *testing.T) {
		t.Parallel()
		t.Run("pty-req, then shell: true, and still true after a pty-req after the shell", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, true, "", clientWindow)
			if !call.channel.Echoes() {
				t.Fatalf("Echoes was false after a pty-req")
			}
			if reply := call.client.request("pty-req", true, ptyRequest("vt100", []byte{0})); reply[0] != messageChannelFailure {
				t.Fatalf("a pty-req after the shell: message %d, want FAILURE", reply[0])
			}
			if !call.channel.Echoes() {
				t.Fatalf("Echoes changed during the call")
			}
		})
	})

	t.Run("While the caller did not ask for a terminal before the shell, Echoes shall return false.", func(t *testing.T) {
		t.Parallel()
		t.Run("shell alone, then a pty-req after it, refused: false, where a Channel with a terminal says true", func(t *testing.T) {
			t.Parallel()
			if !acceptCall(t, true, "", clientWindow).channel.Echoes() {
				t.Fatalf("Echoes was false after a pty-req")
			}
			call := acceptCall(t, false, "", clientWindow)
			if reply := call.client.request("pty-req", true, ptyRequest("vt100", []byte{0})); reply[0] != messageChannelFailure {
				t.Fatalf("a pty-req after the shell: message %d, want FAILURE", reply[0])
			}
			if call.channel.Echoes() {
				t.Fatalf("Echoes was true with no terminal asked for before the shell")
			}
		})
	})

	t.Run("If the Channel was not made by Accept, or is nil, then Echoes shall return false.", func(t *testing.T) {
		t.Parallel()
		t.Run("nil and a Channel not made by Accept: false, where Accept's with a terminal says true", func(t *testing.T) {
			t.Parallel()
			if !acceptCall(t, true, "", clientWindow).channel.Echoes() {
				t.Fatalf("Echoes was false after a pty-req")
			}
			var none *ssh.Channel
			if none.Echoes() || (&ssh.Channel{}).Echoes() {
				t.Fatalf("Echoes was true on a Channel Accept did not make")
			}
		})
	})

	t.Run("Close shall send exit status 0, then end of file, then close the channel.", func(t *testing.T) {
		t.Parallel()
		t.Run("hi queued: hi, then exit-status 0 asking no reply, end of file, the close, and nothing more", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			sendText(t, call.channel, []byte("hi"))
			closed := make(chan error, 1)
			go func() { closed <- call.channel.Close(t.Context()) }()
			expectClosingMessages(t, call.client, "hi")
			_ = call.client.connection.CloseWrite()
			if err := <-closed; err != nil {
				t.Fatalf("Close gave %v", err)
			}
		})
	})

	t.Run("Close shall wait until the caller closes the connection or ClosingWaitSeconds pass, no later than the context's deadline.", func(t *testing.T) {
		t.Parallel()
		t.Run("a caller that stays: Close returns 3 seconds after", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			called := time.Now()
			closed := make(chan error, 1)
			go func() { closed <- call.channel.Close(t.Context()) }()
			expectClosingMessages(t, call.client, "")
			received := time.Now()
			select {
			case err := <-closed:
				returned := time.Now()
				if err != nil {
					t.Fatalf("Close gave %v, want no error", err)
				}
				expectWithin(t, "Close's return", returned, called.Add(closingWait), received.Add(closingWait+margin))
			case <-time.After(closingWait + margin + time.Second):
				t.Fatalf("Close had not returned %v after the close", closingWait+margin+time.Second)
			}
		})
		t.Run("a context deadline 1 second away: Close returns at it, with context.DeadlineExceeded", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			deadline := time.Now().Add(time.Second)
			ctx, cancel := context.WithDeadline(t.Context(), deadline)
			t.Cleanup(cancel)
			err := call.channel.Close(ctx)
			returned := time.Now()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Close gave %v, want context.DeadlineExceeded", err)
			}
			expectWithin(t, "Close's return", returned, deadline, deadline.Add(margin))
		})
	})

	t.Run("When the caller closes the connection, or ClosingWaitSeconds pass, Close shall return no error.", func(t *testing.T) {
		t.Parallel()
		t.Run("the caller closes once the channel's close arrives: Close returns at once, no error", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			closed := make(chan error, 1)
			go func() { closed <- call.channel.Close(t.Context()) }()
			expectClosingMessages(t, call.client, "")
			_ = call.client.connection.CloseWrite()
			callerClosed := time.Now()
			select {
			case err := <-closed:
				if err != nil {
					t.Fatalf("Close gave %v, want no error", err)
				}
				expectWithin(t, "Close's return", time.Now(), callerClosed, callerClosed.Add(margin))
			case <-time.After(margin + time.Second):
				t.Fatalf("Close had not returned %v after the caller closed", margin+time.Second)
			}
		})
	})

	t.Run("If the context has ended when Close is called, then Close shall return the context's error, wrapped, without touching the connection.", func(t *testing.T) {
		t.Parallel()
		t.Run("a cancelled context: context.Canceled, nothing sent, and the Channel still carries z", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			if err := call.channel.Close(cancelled(t)); !errors.Is(err, context.Canceled) {
				t.Fatalf("Close gave %v, want context.Canceled", err)
			}
			call.client.expectQuiet()
			sendText(t, call.channel, []byte("z"))
			flush(t, call.channel)
			call.client.readData(1, time.Now().Add(5*time.Second))
		})
	})

	t.Run("If the context ends while Close waits, then Close shall return the context's error, wrapped.", func(t *testing.T) {
		t.Parallel()
		t.Run("cancelled during the wait: context.Canceled at once", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			ctx, cancel := context.WithCancel(t.Context())
			closed := make(chan error, 1)
			go func() { closed <- call.channel.Close(ctx) }()
			expectClosingMessages(t, call.client, "")
			cancelledAt := time.Now()
			cancel()
			select {
			case err := <-closed:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("Close gave %v, want context.Canceled", err)
				}
				expectWithin(t, "Close's return", time.Now(), cancelledAt, cancelledAt.Add(margin))
			case <-time.After(margin + time.Second):
				t.Fatalf("Close had not returned %v after the cancel", margin+time.Second)
			}
		})
	})

	t.Run("If sending any of them fails, then Close shall return io.EOF at once.", func(t *testing.T) {
		t.Parallel()
		t.Run("the caller reset, seen by RecvChar first: io.EOF at once", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			_ = call.client.connection.SetLinger(0)
			_ = call.client.connection.Close()
			_, err := call.channel.RecvChar(t.Context(), time.Now().Add(5*time.Second))
			expectEnd(t, "RecvChar after the reset", err)
			called := time.Now()
			expectEnd(t, "Close", call.channel.Close(t.Context()))
			expectWithin(t, "Close's return", time.Now(), called, called.Add(margin))
		})
	})

	t.Run("If the Channel was not made by Accept, or is nil, then Close shall return ErrConnectionFailed without touching the connection.", func(t *testing.T) {
		t.Parallel()
		t.Run("nil and a Channel not made by Accept: ErrConnectionFailed, where Accept's closes with no error", func(t *testing.T) {
			t.Parallel()
			call := acceptCall(t, false, "", clientWindow)
			var none *ssh.Channel
			if err := none.Close(t.Context()); !errors.Is(err, ssh.ErrConnectionFailed) {
				t.Fatalf("Close on nil gave %v", err)
			}
			if err := (&ssh.Channel{}).Close(t.Context()); !errors.Is(err, ssh.ErrConnectionFailed) {
				t.Fatalf("Close on a Channel Accept did not make gave %v", err)
			}
			closed := make(chan error, 1)
			go func() { closed <- call.channel.Close(t.Context()) }()
			expectClosingMessages(t, call.client, "")
			_ = call.client.connection.CloseWrite()
			if err := <-closed; err != nil {
				t.Fatalf("Close of Accept's Channel gave %v", err)
			}
		})
	})
}

// expectClosingMessages reads queued data, then exactly exit-status 0 with no reply asked, end
// of file and the close, in that order.
func expectClosingMessages(t *testing.T, client *rawClient, queued string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	if queued != "" {
		client.readData(len(queued), deadline)
		if string(client.received) != queued {
			t.Fatalf("the caller received %q, want %q first", client.received, queued)
		}
	}
	want := [][]byte{
		message(messageChannelRequest).uint32Value(0).text("exit-status").boolean(false).uint32Value(0).data,
		message(messageChannelEOF).uint32Value(0).data,
		message(messageChannelClose).uint32Value(0).data,
	}
	for index, each := range want {
		payload, err := client.next(deadline)
		if err != nil || !bytes.Equal(payload, each) {
			t.Fatalf("closing message %d was %v, %v, want %v", index+1, payload, err, each)
		}
	}
}

// echoMeetsEnd reaches where the write-fails line starts: with a terminal, x read and its echo
// queued, the caller's end, then a RecvChar whose write of the echo meets it, giving io.EOF.
func echoMeetsEnd(t *testing.T, end func(client *rawClient)) openCall {
	t.Helper()
	call := acceptCall(t, true, "", clientWindow)
	call.client.sendData("x")
	expectReceived(t, call.channel, "x")
	sendText(t, call.channel, []byte("x"))
	end(call.client)
	// The end reaches the engine before the call, so the queued echo meets a connection that has
	// ended.
	waitUntil(t, time.Now().Add(quietFor))
	_, err := call.channel.RecvChar(t.Context(), time.Now().Add(5*time.Second))
	expectEnd(t, "RecvChar with the echo queued", err)
	return call
}

// expectEnd is io.EOF alone: every end of the caller's data or the connection, however it came,
// and never the wrong call's ErrConnectionFailed.
func expectEnd(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, io.EOF) || errors.Is(err, ssh.ErrConnectionFailed) {
		t.Fatalf("%s gave %v, want io.EOF alone", what, err)
	}
}

// cutCall is an open call whose write the context cut short, and what that write held.
type cutCall struct {
	openCall
	cut []byte
}

// cutWrite queues 96 bytes to a caller that lets 16 through, then cuts Flush's write with a
// context that ends in a second.
func cutWrite(t *testing.T) cutCall {
	t.Helper()
	call := acceptCall(t, false, "", 16)
	text := bytes.Repeat([]byte("abcdefgh"), 12)
	sendText(t, call.channel, text)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := call.channel.Flush(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Flush gave %v, want the context's deadline", err)
	}
	return cutCall{openCall: call, cut: text}
}

// expectFailedAfter checks every call fails once a write did, and that nothing they could write
// arrives: what comes once the caller opens its window is a prefix of what the cut write held.
func expectFailedAfter(t *testing.T, call openCall, cut []byte) {
	t.Helper()
	// Bounded, so a call that writes where it must fail waits 5 seconds at most, not for good.
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	expectEnd(t, "SendChar after the failed write", call.channel.SendChar(ctx, 'Q'))
	expectEnd(t, "Flush after the failed write", call.channel.Flush(ctx))
	_, err := call.channel.RecvChar(ctx, time.Now().Add(time.Second))
	expectEnd(t, "RecvChar after the failed write", err)
	call.client.sendPacket(message(messageWindowAdjust).uint32Value(call.client.engineChannel).uint32Value(clientWindow).data)
	for {
		if _, err := call.client.next(time.Now().Add(quietFor)); err != nil {
			break
		}
	}
	if !bytes.HasPrefix(cut, call.client.received) {
		t.Fatalf("the caller received %q, which is not a prefix of the cut write", call.client.received)
	}
}
