// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests of the session's Run and Text I/O's Conn through the real stack the Listener builds: a
// Telnet Line from Accept over a real loopback socket, with the scripted caller at the other end.
// They live with the Listener's tests because only this package may use all three units.
package listener_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/session"
	"github.com/heliosestate/heliosadvance/internal/telnet"
	"github.com/heliosestate/heliosadvance/internal/textio"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// stackPair is one loopback connection with a Line opened on its server end.
type stackPair struct {
	client *net.TCPConn
	server *net.TCPConn
	line   *telnet.Line
}

// openStack connects, makes a Line on the server end with Accept, and has the caller answer with
// the given answers and the bytes after them, in one write. It reads the opening and any replies.
func openStack(t *testing.T, answer, after []byte) stackPair {
	t.Helper()
	listening, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on loopback: %v", err)
	}
	defer func() { _ = listening.Close() }()
	clientEnd, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", listening.Addr().String())
	if err != nil {
		t.Fatalf("dialing loopback: %v", err)
	}
	serverEnd, err := listening.Accept()
	if err != nil {
		t.Fatalf("accepting on loopback: %v", err)
	}
	client, clientIsTCP := clientEnd.(*net.TCPConn)
	server, serverIsTCP := serverEnd.(*net.TCPConn)
	if !clientIsTCP || !serverIsTCP {
		t.Fatalf("loopback connection is not TCP")
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	type openResult struct {
		line *telnet.Line
		err  error
	}
	done := make(chan openResult, 1)
	go func() {
		line, err := telnet.Accept(t.Context(), server)
		done <- openResult{line: line, err: err}
	}()
	pair := stackPair{client: client, server: server}
	pair.expectReceived(t, opening)
	_ = client.SetWriteDeadline(time.Now().Add(testrun.Patient(testrun.HangBound)))
	if _, err := client.Write(join(answer, after)); err != nil {
		t.Fatalf("the caller's write failed: %v", err)
	}
	result := <-done
	if result.err != nil {
		t.Fatalf("setting up: Open returned %v", result.err)
	}
	pair.line = result.line
	// The answers the rows use, all eight with ECHO agreed or refused, draw no reply.
	return pair
}

func (pair stackPair) send(t *testing.T, data []byte) {
	t.Helper()
	_ = pair.client.SetWriteDeadline(time.Now().Add(testrun.Patient(testrun.HangBound)))
	if _, err := pair.client.Write(data); err != nil {
		t.Fatalf("the caller's write failed: %v", err)
	}
}

// expectReceived checks the caller receives exactly these bytes next.
func (pair stackPair) expectReceived(t *testing.T, want []byte) {
	t.Helper()
	_ = pair.client.SetReadDeadline(time.Now().Add(testrun.Patient(2 * margin)))
	got := make([]byte, len(want))
	count, err := io.ReadFull(pair.client, got)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("the caller received % x and %v, want % x", got[:count], err, want)
	}
}

// expectQuiet checks the caller receives nothing for a while.
func (pair stackPair) expectQuiet(t *testing.T) {
	t.Helper()
	_ = pair.client.SetReadDeadline(time.Now().Add(quietFor))
	buffer := make([]byte, 64)
	got, err := pair.client.Read(buffer)
	if got > 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the caller received % x and %v where nothing was due", buffer[:got], err)
	}
}

// resetCaller closes the caller's end abortively.
func (pair stackPair) resetCaller(t *testing.T) {
	t.Helper()
	_ = pair.client.SetLinger(0)
	_ = pair.client.Close()
}

// ended is a context already cancelled.
func ended(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	return ctx
}

// stallCaller writes filler straight to the server end, past the Line, the caller not reading,
// until even a one-byte write waits, so the Line's next write waits too. Windows takes large
// writes into its own buffers and Linux still takes a small one once a large one waits, so the
// writes shrink.
func (pair stackPair) stallCaller(t *testing.T) {
	t.Helper()
	for _, size := range []int{256 << 10, 4 << 10, 64, 1} {
		chunk := repeated([]byte("s"), size)
		waited := false
		for range 4096 {
			_ = pair.server.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
			if _, err := pair.server.Write(chunk); err != nil {
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
	_ = pair.server.SetWriteDeadline(time.Time{})
}

// drain reads everything the caller is owed until the server shuts its sending side.
func (pair stackPair) drain(t *testing.T) []byte {
	t.Helper()
	received := make(chan []byte, 1)
	go func() {
		_ = pair.client.SetReadDeadline(time.Now().Add(testrun.Patient(60 * time.Second)))
		var all []byte
		chunk := make([]byte, 64<<10)
		for {
			got, err := pair.client.Read(chunk)
			all = append(all, chunk[:got]...)
			if err != nil {
				received <- all
				return
			}
		}
	}()
	if err := pair.line.Flush(t.Context()); err != nil {
		t.Fatalf("draining: Flush returned %v", err)
	}
	_ = pair.server.CloseWrite()
	return <-received
}

// runResult is what one Run returned, and when.
type runResult struct {
	ending   session.Ending
	err      error
	returned time.Time
}

// runOn calls Run on its own goroutine over a Conn on the pair's Line.
func runOn(ctx context.Context, pair stackPair) <-chan runResult {
	done := make(chan runResult, 1)
	go func() {
		ending, err := session.Run(ctx, textio.New(pair.line))
		done <- runResult{ending: ending, err: err, returned: time.Now()}
	}()
	return done
}

// recording is a Chars that passes every call through to the real Line and counts the SendChar
// calls made after one has failed: the one thing about SendString no caller can see.
type recordingChars struct {
	line           *telnet.Line
	failed         bool
	afterFailure   int
	flushesAfter   int
	failingResults []error
}

func (chars *recordingChars) SendChar(ctx context.Context, character byte) error {
	if chars.failed {
		chars.afterFailure++
	}
	err := chars.line.SendChar(ctx, character)
	if err != nil {
		chars.failed = true
		chars.failingResults = append(chars.failingResults, err)
	}
	return err
}

func (chars *recordingChars) RecvChar(ctx context.Context, deadline time.Time) (byte, error) {
	return chars.line.RecvChar(ctx, deadline)
}

func (chars *recordingChars) Flush(ctx context.Context) error {
	if chars.failed {
		chars.flushesAfter++
	}
	err := chars.line.Flush(ctx)
	if err != nil {
		chars.failed = true
		chars.failingResults = append(chars.failingResults, err)
	}
	return err
}

func (chars *recordingChars) Echoes() bool {
	return chars.line.Echoes()
}

func TestSessionRun(t *testing.T) {
	t.Parallel()
	t.Run("When it is called, Run shall write Greeting and then Prompt before it reads.", func(t *testing.T) {
		t.Parallel()
		t.Run("a name typed ahead, ECHO agreed: the greeting and the prompt come before its echo", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, answers, []byte("bob\r"))
			done := runOn(t.Context(), pair)
			pair.expectReceived(t, join(asked, echoed("bob")))
			if got := <-done; got.err != nil || got.ending != session.Answered {
				t.Fatalf("Run returned (%v, %v), want Answered", got.ending, got.err)
			}
		})
	})
	t.Run("Run shall read the name with RecvString, with a deadline of NameSeconds after Prompt was written, which typing does not move, and a limit of NameMostCharacters.", func(t *testing.T) {
		t.Parallel()
		t.Run("a silent caller: NoName 60 seconds after the prompt", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, answers, nil)
			called := time.Now()
			done := runOn(t.Context(), pair)
			pair.expectReceived(t, asked)
			promptAt := time.Now()
			got := <-done
			if got.err != nil || got.ending != session.NoName {
				t.Fatalf("Run returned (%v, %v), want NoName", got.ending, got.err)
			}
			expectWithin(t, "Run's return", got.returned, called.Add(nameLimit), promptAt.Add(nameLimit+margin))
		})
		t.Run("typing every 10 seconds, never ending: still NoName at 60 seconds", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, refused, nil)
			called := time.Now()
			done := runOn(t.Context(), pair)
			pair.expectReceived(t, asked)
			promptAt := time.Now()
			go func() {
				for index := 1; index < 6; index++ {
					wait(t, promptAt.Add(time.Duration(index)*10*time.Second))
					_, _ = pair.client.Write([]byte("a"))
				}
			}()
			got := <-done
			if got.err != nil || got.ending != session.NoName {
				t.Fatalf("Run returned (%v, %v), want NoName", got.ending, got.err)
			}
			expectWithin(t, "Run's return", got.returned, called.Add(nameLimit), promptAt.Add(nameLimit+margin))
		})
		t.Run("31 characters: the first 30", func(t *testing.T) {
			t.Parallel()
			thirty := strings.Repeat("x", nameMost)
			pair := openStack(t, refused, []byte(thirty+"y\r"))
			done := runOn(t.Context(), pair)
			pair.expectReceived(t, join(asked, helloTo(thirty)))
			<-done
		})
	})
	t.Run("Run shall count toward the name what the caller sent after negotiation and before Prompt was written, as RecvString reads it.", func(t *testing.T) {
		t.Parallel()
		t.Run("bob typed in the same write as the answers, ended after the prompt", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, refused, []byte("bob"))
			done := runOn(t.Context(), pair)
			pair.expectReceived(t, asked)
			pair.send(t, []byte("by\r"))
			pair.expectReceived(t, helloTo("bobby"))
			<-done
		})
	})
	t.Run("When RecvString returns a name, Run shall write Reply, the name and CR LF, and return Answered.", func(t *testing.T) {
		t.Parallel()
		for name, typed := range map[string]string{"CR": "ann\r", "LF": "ann\n"} {
			t.Run("ann ended by "+name, func(t *testing.T) {
				t.Parallel()
				pair := openStack(t, refused, nil)
				done := runOn(t.Context(), pair)
				pair.expectReceived(t, asked)
				pair.send(t, []byte(typed))
				pair.expectReceived(t, helloTo("ann"))
				if got := <-done; got.err != nil || got.ending != session.Answered {
					t.Fatalf("Run returned (%v, %v), want Answered", got.ending, got.err)
				}
				pair.expectQuiet(t)
			})
		}
	})
	t.Run("When RecvString returns os.ErrDeadlineExceeded, Run shall write nothing more and return NoName.", func(t *testing.T) {
		t.Parallel()
		t.Run("ab typed with ECHO agreed, never ended: the echo goes, nothing more, NoName", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, answers, nil)
			done := runOn(t.Context(), pair)
			pair.expectReceived(t, asked)
			pair.send(t, []byte("ab"))
			pair.expectReceived(t, []byte("ab"))
			got := <-done
			if got.err != nil || got.ending != session.NoName {
				t.Fatalf("Run returned (%v, %v), want NoName", got.ending, got.err)
			}
			if received := pair.drain(t); len(received) != 0 {
				t.Fatalf("after NoName the caller received % x", received)
			}
		})
	})
	t.Run("If the context has ended when Run is called, then Run shall return ErrCallEnded without writing.", func(t *testing.T) {
		t.Parallel()
		t.Run("a cancelled context: ErrCallEnded, and nothing queued or written", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, answers, []byte("bob\r"))
			got := <-runOn(ended(t), pair)
			if !errors.Is(got.err, session.ErrCallEnded) || !errors.Is(got.err, context.Canceled) {
				t.Fatalf("Run returned %v, want ErrCallEnded wrapping context.Canceled", got.err)
			}
			if received := pair.drain(t); len(received) != 0 {
				t.Fatalf("the caller received % x", received)
			}
		})
		t.Run("a context whose deadline passed: ErrCallEnded wrapping context.DeadlineExceeded", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, answers, nil)
			ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
			defer cancel()
			got := <-runOn(ctx, pair)
			if !errors.Is(got.err, session.ErrCallEnded) || !errors.Is(got.err, context.DeadlineExceeded) {
				t.Fatalf("Run returned %v, want ErrCallEnded wrapping context.DeadlineExceeded", got.err)
			}
			if received := pair.drain(t); len(received) != 0 {
				t.Fatalf("the caller received % x", received)
			}
		})
	})
	t.Run("When a call returns the context's error, Run shall return ErrCallEnded wrapping it; io.EOF, ErrCallerClosed; any other error, ErrConnectionFailed wrapping it.", func(t *testing.T) {
		t.Parallel()
		t.Run("cancelled while it waits for the name: ErrCallEnded wrapping context.Canceled", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, answers, nil)
			ctx, cancel := context.WithCancel(t.Context())
			done := runOn(ctx, pair)
			pair.expectReceived(t, asked)
			cancel()
			if got := <-done; !errors.Is(got.err, session.ErrCallEnded) || !errors.Is(got.err, context.Canceled) {
				t.Fatalf("Run returned %v, want ErrCallEnded wrapping context.Canceled", got.err)
			}
		})
		t.Run("the context's deadline while it waits for the name: ErrCallEnded wrapping context.DeadlineExceeded", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, answers, nil)
			// A second was met in the greeting's write on a slow machine, before the wait for the
			// name the row is about.
			deadline := testrun.CaseDeadline()
			ctx, cancel := context.WithDeadline(t.Context(), deadline)
			defer cancel()
			done := runOn(ctx, pair)
			pair.expectReceived(t, asked)
			testrun.ExpectCaseReached(t, deadline, margin)
			if got := <-done; !errors.Is(got.err, session.ErrCallEnded) || !errors.Is(got.err, context.DeadlineExceeded) {
				t.Fatalf("Run returned %v, want ErrCallEnded wrapping context.DeadlineExceeded", got.err)
			}
		})
		t.Run("cancelled while the greeting's write waits on a caller that does not read: ErrCallEnded", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, answers, nil)
			pair.stallCaller(t)
			ctx, cancel := context.WithCancel(t.Context())
			done := runOn(ctx, pair)
			wait(t, time.Now().Add(quietFor))
			cancel()
			if got := <-done; !errors.Is(got.err, session.ErrCallEnded) || !errors.Is(got.err, context.Canceled) {
				t.Fatalf("Run returned %v, want ErrCallEnded wrapping context.Canceled", got.err)
			}
		})
		t.Run("the caller closes mid-name: ErrCallerClosed", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, refused, nil)
			done := runOn(t.Context(), pair)
			pair.expectReceived(t, asked)
			pair.send(t, []byte("ab"))
			_ = pair.client.CloseWrite()
			if got := <-done; !errors.Is(got.err, session.ErrCallerClosed) {
				t.Fatalf("Run returned %v, want ErrCallerClosed", got.err)
			}
		})
		t.Run("the caller resets mid-name: ErrConnectionFailed wrapping the Line's", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, refused, nil)
			done := runOn(t.Context(), pair)
			pair.expectReceived(t, asked)
			pair.resetCaller(t)
			got := <-done
			if !errors.Is(got.err, session.ErrConnectionFailed) || !errors.Is(got.err, telnet.ErrConnectionFailed) {
				t.Fatalf("Run returned %v, want ErrConnectionFailed wrapping the Line's", got.err)
			}
		})
	})
}

func TestTextConn(t *testing.T) {
	t.Parallel()
	t.Run("New shall return a Conn whose SendChar and RecvChar are the given Chars' own.", func(t *testing.T) {
		t.Parallel()
		t.Run("SendChar of 255 doubled by the Line, RecvChar skipping the Line's commands", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, answers, join(request(doVerb, telnetTypeOption), []byte("k")))
			conn := textio.New(pair.line)
			if err := conn.SendChar(t.Context(), iac); err != nil {
				t.Fatalf("SendChar returned %v", err)
			}
			pair.expectQuiet(t)
			if value, err := conn.RecvChar(t.Context(), time.Now().Add(testrun.Patient(margin))); err != nil || value != 'k' {
				t.Fatalf("RecvChar returned %#02x and %v, want k", value, err)
			}
			if err := pair.line.Flush(t.Context()); err != nil {
				t.Fatalf("Flush returned %v", err)
			}
			pair.expectReceived(t, join([]byte{iac, iac}, request(wont, telnetTypeOption)))
		})
		t.Run("RecvChar's deadline is the Line's: os.ErrDeadlineExceeded", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, answers, nil)
			if _, err := textio.New(pair.line).RecvChar(t.Context(), time.Now().Add(100*time.Millisecond)); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("RecvChar returned %v, want os.ErrDeadlineExceeded", err)
			}
		})
	})
	t.Run("SendString shall queue the bytes of text in order, one SendChar per byte, and then flush.", func(t *testing.T) {
		t.Parallel()
		t.Run("abc, 255 and 1500 bytes more: all of it at once, in order, 255 doubled", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, answers, nil)
			text := "abc\xffdef" + strings.Repeat("n", 1500)
			if err := textio.New(pair.line).SendString(t.Context(), text); err != nil {
				t.Fatalf("SendString returned %v", err)
			}
			pair.expectReceived(t, join([]byte("abc"), []byte{iac, iac}, []byte("def"), repeated([]byte("n"), 1500)))
			pair.expectQuiet(t)
		})
		t.Run("bytes queued by SendChar before go out first", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, answers, nil)
			conn := textio.New(pair.line)
			_ = conn.SendChar(t.Context(), 'x')
			if err := conn.SendString(t.Context(), "yz"); err != nil {
				t.Fatalf("SendString returned %v", err)
			}
			pair.expectReceived(t, []byte("xyz"))
		})
	})
	t.Run("If a SendChar or the flush fails, then SendString shall queue no further byte and return that result.", func(t *testing.T) {
		t.Parallel()
		t.Run("its context's deadline passes while a full buffer waits on a caller that does not read", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, answers, nil)
			pair.stallCaller(t)
			chars := &recordingChars{line: pair.line}
			ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
			defer cancel()
			err := textio.New(chars).SendString(ctx, strings.Repeat("q", 3000))
			if !errors.Is(err, context.DeadlineExceeded) || len(chars.failingResults) != 1 || !errors.Is(chars.failingResults[0], context.DeadlineExceeded) {
				t.Fatalf("SendString returned %v after failures %v, want the one failure's result", err, chars.failingResults)
			}
			if chars.afterFailure != 0 || chars.flushesAfter != 0 {
				t.Fatalf("after the failure SendString made %d SendChar and %d Flush calls", chars.afterFailure, chars.flushesAfter)
			}
		})
		t.Run("the caller resets: the Line's ErrConnectionFailed, and no call after it", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, answers, nil)
			pair.resetCaller(t)
			chars := &recordingChars{line: pair.line}
			var err error
			for range 50 {
				if err = textio.New(chars).SendString(t.Context(), strings.Repeat("q", 3000)); err != nil {
					break
				}
				wait(t, time.Now().Add(10*time.Millisecond))
			}
			if !errors.Is(err, telnet.ErrConnectionFailed) || chars.afterFailure != 0 || chars.flushesAfter != 0 {
				t.Fatalf("SendString returned %v, with %d SendChar and %d Flush calls after the failure", err, chars.afterFailure, chars.flushesAfter)
			}
		})
	})
	t.Run("If the context has ended when SendString is called, then SendString shall write nothing and return the context's error, wrapped.", func(t *testing.T) {
		t.Parallel()
		t.Run("a cancelled context: nothing queued, z after it alone", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, answers, nil)
			conn := textio.New(pair.line)
			if err := conn.SendString(ended(t), "abc"); !errors.Is(err, context.Canceled) {
				t.Fatalf("SendString returned %v, want context.Canceled", err)
			}
			if err := conn.SendString(t.Context(), "z"); err != nil {
				t.Fatalf("SendString returned %v", err)
			}
			pair.expectReceived(t, []byte("z"))
			pair.expectQuiet(t)
		})
	})
	t.Run("RecvString shall read each byte with Edit, in the order RecvChar returns them, those the caller sent before the call included.", func(t *testing.T) {
		t.Parallel()
		t.Run("ab BS c CR sent before the call", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, refused, []byte("ab\x08c\r"))
			if got, err := textio.New(pair.line).RecvString(t.Context(), time.Now().Add(testrun.Patient(margin)), nameMost); err != nil || got != "ac" {
				t.Fatalf("RecvString returned %q and %v, want ac", got, err)
			}
		})
		t.Run("a among commands, ESC and 255 dropped, then b CR", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, refused, join([]byte("a"), request(doVerb, telnetTypeOption), []byte{0x1b, iac, iac}, []byte("b\r")))
			if got, err := textio.New(pair.line).RecvString(t.Context(), time.Now().Add(testrun.Patient(margin)), nameMost); err != nil || got != "ab" {
				t.Fatalf("RecvString returned %q and %v, want ab", got, err)
			}
		})
	})
	t.Run("While the connection echoes, as Echoes says at that byte, RecvString shall send what Edit gives to echo, in order; when it does not, nothing.", func(t *testing.T) {
		t.Parallel()
		t.Run("ECHO agreed, then DONT ECHO after a: a echoed, b and the end not", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, answers, join([]byte("a"), request(dont, echo), []byte("b\r")))
			conn := textio.New(pair.line)
			if got, err := conn.RecvString(t.Context(), time.Now().Add(testrun.Patient(margin)), nameMost); err != nil || got != "ab" {
				t.Fatalf("RecvString returned %q and %v", got, err)
			}
			_ = conn.SendString(t.Context(), "")
			pair.expectReceived(t, join([]byte("a"), request(wont, echo)))
			pair.expectQuiet(t)
		})
		t.Run("ECHO refused, then DO ECHO after a: b and the end echoed", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, refused, join([]byte("a"), request(doVerb, echo), []byte("b\x08c\r")))
			conn := textio.New(pair.line)
			if got, err := conn.RecvString(t.Context(), time.Now().Add(testrun.Patient(margin)), nameMost); err != nil || got != "ac" {
				t.Fatalf("RecvString returned %q and %v", got, err)
			}
			_ = conn.SendString(t.Context(), "")
			pair.expectReceived(t, join(request(will, echo), []byte("b\x08 \x08c\r\n")))
		})
	})
	t.Run("When Edit ends the line, RecvString shall return the line and no error, and read no byte after the one that ended it.", func(t *testing.T) {
		t.Parallel()
		t.Run("ab CR cd CR: ab, then RecvChar gives c", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, refused, []byte("ab\rcd\r"))
			conn := textio.New(pair.line)
			if got, err := conn.RecvString(t.Context(), time.Now().Add(testrun.Patient(margin)), nameMost); err != nil || got != "ab" {
				t.Fatalf("RecvString returned %q and %v", got, err)
			}
			if value, err := conn.RecvChar(t.Context(), time.Now().Add(testrun.Patient(margin))); err != nil || value != 'c' {
				t.Fatalf("RecvChar returned %#02x and %v, want c", value, err)
			}
		})
		t.Run("ab CR then DO 24: no reply, the request unread", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, refused, join([]byte("ab\r"), request(doVerb, telnetTypeOption)))
			conn := textio.New(pair.line)
			if got, err := conn.RecvString(t.Context(), time.Now().Add(testrun.Patient(margin)), nameMost); err != nil || got != "ab" {
				t.Fatalf("RecvString returned %q and %v", got, err)
			}
			_ = conn.SendString(t.Context(), "x")
			pair.expectReceived(t, []byte("x"))
			pair.expectQuiet(t)
		})
	})
	t.Run("If deadline passes before the line ends, then RecvString shall return os.ErrDeadlineExceeded, whatever bytes are waiting.", func(t *testing.T) {
		t.Parallel()
		t.Run("abc and no end: os.ErrDeadlineExceeded at the deadline", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, refused, []byte("abc"))
			deadline := time.Now().Add(300 * time.Millisecond)
			if _, err := textio.New(pair.line).RecvString(t.Context(), deadline, nameMost); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("RecvString returned %v, want os.ErrDeadlineExceeded", err)
			}
			expectWithin(t, "RecvString's return", time.Now(), deadline, deadline.Add(margin))
		})
		t.Run("ab CR waiting and a deadline already past: os.ErrDeadlineExceeded", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, refused, []byte("ab\r"))
			if _, err := textio.New(pair.line).RecvString(t.Context(), time.Now().Add(-time.Millisecond), nameMost); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("RecvString returned %v, want os.ErrDeadlineExceeded", err)
			}
		})
	})
	t.Run("RecvString shall queue its echo with SendChar under the call's context, and call no Flush: the echo goes out when what is queued is next written, as Chars says, or with the next SendString.", func(t *testing.T) {
		t.Parallel()
		t.Run("ab CR all waiting: nothing written by RecvString, the echo with the next SendString", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, answers, []byte("ab\r"))
			chars := &recordingChars{line: pair.line}
			conn := textio.New(chars)
			if got, err := conn.RecvString(t.Context(), time.Now().Add(testrun.Patient(margin)), nameMost); err != nil || got != "ab" {
				t.Fatalf("RecvString returned %q and %v", got, err)
			}
			pair.expectQuiet(t)
			_ = conn.SendString(t.Context(), "x")
			pair.expectReceived(t, []byte("ab\r\nx"))
		})
		t.Run("a, then a wait, then b CR: a's echo goes when RecvChar waits, the rest with the next SendString", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, answers, []byte("a"))
			conn := textio.New(pair.line)
			type received struct {
				line string
				err  error
			}
			// The call's goroutine hands its result back and reports nothing itself, and the row
			// waits for it however it ends, so nothing reports after the row has ended.
			done := make(chan received, 1)
			go func() {
				got, err := conn.RecvString(t.Context(), time.Now().Add(testrun.Patient(testrun.HangBound)), nameMost)
				done <- received{line: got, err: err}
			}()
			finished := false
			defer func() {
				if !finished {
					<-done
				}
			}()
			pair.expectReceived(t, []byte("a"))
			pair.send(t, []byte("b\r"))
			got := <-done
			finished = true
			if got.err != nil || got.line != "ab" {
				t.Fatalf("RecvString returned %q and %v", got.line, got.err)
			}
			pair.expectQuiet(t)
			_ = conn.SendString(t.Context(), "x")
			pair.expectReceived(t, []byte("b\r\nx"))
		})
	})
	t.Run("If most is below 1 or above MostLine, then RecvString shall read nothing and return ErrMostOutOfRange.", func(t *testing.T) {
		t.Parallel()
		for _, most := range []int{0, -1, 256, 1 << 30} {
			t.Run("most "+strconv.Itoa(most)+": nothing read, a is RecvChar's", func(t *testing.T) {
				t.Parallel()
				pair := openStack(t, refused, []byte("a\r"))
				conn := textio.New(pair.line)
				if _, err := conn.RecvString(t.Context(), time.Now().Add(testrun.Patient(margin)), most); !errors.Is(err, textio.ErrMostOutOfRange) {
					t.Fatalf("RecvString returned %v, want ErrMostOutOfRange", err)
				}
				if value, err := conn.RecvChar(t.Context(), time.Now().Add(testrun.Patient(margin))); err != nil || value != 'a' {
					t.Fatalf("RecvChar returned %#02x and %v, want a", value, err)
				}
			})
		}
		for _, most := range []int{1, 255} {
			t.Run("most "+strconv.Itoa(most)+", the edge just inside: a line", func(t *testing.T) {
				t.Parallel()
				pair := openStack(t, refused, []byte("ab\r"))
				want := "ab"
				if most == 1 {
					want = "a"
				}
				if got, err := textio.New(pair.line).RecvString(t.Context(), time.Now().Add(testrun.Patient(margin)), most); err != nil || got != want {
					t.Fatalf("RecvString returned %q and %v, want %q", got, err, want)
				}
			})
		}
	})
	t.Run("RecvString shall return any other result of RecvChar or SendChar as the table gives it.", func(t *testing.T) {
		t.Parallel()
		t.Run("the caller closes mid-line: io.EOF", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, refused, []byte("ab"))
			_ = pair.client.CloseWrite()
			if _, err := textio.New(pair.line).RecvString(t.Context(), time.Now().Add(testrun.Patient(margin)), nameMost); !errors.Is(err, io.EOF) {
				t.Fatalf("RecvString returned %v, want io.EOF", err)
			}
		})
		t.Run("the caller resets mid-line: the Line's ErrConnectionFailed", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, refused, []byte("ab"))
			pair.resetCaller(t)
			if _, err := textio.New(pair.line).RecvString(t.Context(), time.Now().Add(testrun.Patient(margin)), nameMost); !errors.Is(err, telnet.ErrConnectionFailed) {
				t.Fatalf("RecvString returned %v, want the Line's ErrConnectionFailed", err)
			}
		})
		t.Run("cancelled mid-line: context.Canceled", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, refused, []byte("ab"))
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() {
				_, err := textio.New(pair.line).RecvString(ctx, time.Now().Add(5*time.Second), nameMost)
				done <- err
			}()
			wait(t, time.Now().Add(quietFor))
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("RecvString returned %v, want context.Canceled", err)
			}
		})
		t.Run("the context's deadline mid-line: context.DeadlineExceeded", func(t *testing.T) {
			t.Parallel()
			pair := openStack(t, refused, []byte("ab"))
			ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
			defer cancel()
			if _, err := textio.New(pair.line).RecvString(ctx, time.Now().Add(5*time.Second), nameMost); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("RecvString returned %v, want context.DeadlineExceeded", err)
			}
		})
	})
}
