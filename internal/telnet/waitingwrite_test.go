// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests of Negotiate with one of its writes waiting on a caller that does not read: the 3 seconds
// end only a waiting read, a waiting write waits for the caller or the context, and negotiation
// ends where the write does, reading nothing more.
package telnet_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/telnet"
)

// floodRequests is more than any runner's buffers hold: Linux took up to 7 MB of a flood before
// its writes waited, on the laptop's Ubuntu, 2026-10-23.
const floodRequests = 8 << 20

// floodOptions are the option codes the flood asks for in turn: 4 to 255, never ECHO or SGA.
var floodOptions = func() []byte {
	var codes []byte
	for code := range 256 {
		if code >= 4 {
			codes = append(codes, byte(code))
		}
	}
	return codes
}()

// floodOption is the option the flood's request at index asks for.
func floodOption(index int) byte {
	return floodOptions[index%len(floodOptions)]
}

// numbered is length bytes of the flood's stream from offset: DO for options 4 to 255 in turn,
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

// floodNumbered sends the numbered stream and never reads, until a write stops going through. A
// write cut short may have sent more than it reports, as Windows does, so it returns nothing: the
// rows read where the stream stopped from the stream itself.
func floodNumbered(t *testing.T, client *net.TCPConn) {
	t.Helper()
	for offset := 0; offset < 3*floodRequests; {
		_ = client.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
		written, err := client.Write(numbered(offset, 3072))
		offset += written
		if errors.Is(err, os.ErrDeadlineExceeded) {
			_ = client.SetWriteDeadline(time.Time{})
			return
		}
		if err != nil {
			t.Fatalf("flooding: %v", err)
		}
	}
	t.Fatalf("flooding: the writes never waited")
}

// stallNegotiation has the caller of a Negotiate call flood and never read, so that Negotiate is
// left waiting in a write of replies well before its 3 seconds pass.
func stallNegotiation(t *testing.T, pair connected, call negotiating) {
	t.Helper()
	floodNumbered(t, pair.client)
	if time.Since(call.called) > negotiationLimit-200*time.Millisecond {
		t.Fatalf("test fault: the flood took %v", time.Since(call.called))
	}
}

// expectNotReturned checks Negotiate is still waiting at the moment given.
func expectNotReturned(t *testing.T, call negotiating, until time.Time) {
	t.Helper()
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case got := <-call.done:
		t.Fatalf("Negotiate returned (%v, %v) %v after it was called, while its write waited", got.outcome, got.err, got.returned.Sub(call.called))
	case <-timer.C:
	}
}

func TestNegotiateWaitingWrite(t *testing.T) {
	t.Parallel()
	t.Run("While a write is waiting, Negotiate shall wait for it until it ends or the context ends, whether or not NegotiationSeconds have passed.", func(t *testing.T) {
		t.Parallel()
		t.Run("a caller that floods and never reads: still waiting at 5 seconds, then cancelled: ErrDeadlineEnded at once", func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			pair := connect(t)
			call := negotiate(ctx, pair.server)
			stallNegotiation(t, pair, call)
			expectNotReturned(t, call, call.called.Add(5*time.Second))
			cancel()
			cancelledAt := time.Now()
			expectReturn(t, call.result(t, cancelledAt.Add(margin)), 0, []error{telnet.ErrDeadlineEnded, context.Canceled}, cancelledAt, cancelledAt.Add(margin))
		})
		t.Run("a caller that floods, then reads from 5 seconds: Negotiate returns only once it reads", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(t.Context(), pair.server)
			stallNegotiation(t, pair, call)
			expectNotReturned(t, call, call.called.Add(5*time.Second))
			readingAt := time.Now()
			go func() { _, _ = readToEnd(pair.client, time.Now().Add(30*time.Second)) }()
			expectReturn(t, call.result(t, readingAt.Add(margin)), telnet.TimedOut, nil, readingAt, readingAt.Add(margin))
		})
	})
	t.Run("If NegotiationSeconds have passed when a write ends without an error, and Receive has not returned true, then Negotiate shall return TimedOut with no error, reading nothing more.", func(t *testing.T) {
		t.Parallel()
		t.Run("a caller that floods, then reads from 4 seconds: TimedOut, each request answered once or still unread, in order", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(t.Context(), pair.server)
			stallNegotiation(t, pair, call)
			expectNotReturned(t, call, call.called.Add(4*time.Second))
			received := make(chan []byte, 1)
			go func() {
				stream, err := readToEnd(pair.client, time.Now().Add(30*time.Second))
				if !errors.Is(err, io.EOF) {
					t.Errorf("the caller's stream did not end in order: %v", err)
				}
				received <- stream
			}()
			got := call.result(t, time.Now().Add(margin))
			if got.err != nil || got.outcome != telnet.TimedOut {
				t.Fatalf("Negotiate returned (%v, %v), want TimedOut", got.outcome, got.err)
			}
			// The caller has stopped; whatever it sent is now in the server end's buffers.
			unread := readQuiet(t, pair.server)
			_ = pair.server.CloseWrite()
			stream := <-received
			if !bytes.HasPrefix(stream, opening) {
				t.Fatalf("the stream did not start with the opening")
			}
			replies := stream[len(opening):]
			answered := len(replies) / 3
			want := make([]byte, 0, len(replies))
			for index := range answered {
				want = append(want, request(wont, floodOption(index))...)
			}
			if !bytes.Equal(replies, want) {
				t.Fatalf("the %d bytes of replies are not WONT to the first requests, each once, in order", len(replies))
			}
			// Negotiate reads in buffers that need not end between requests, so the unread
			// bytes may start inside the first request it did not answer; they run on from there
			// in order.
			for skipped := range 3 {
				if bytes.Equal(unread, numbered(3*answered+skipped, len(unread))) {
					return
				}
			}
			t.Fatalf("%d requests answered, but the %d unread bytes do not run on from the next", answered, len(unread))
		})
	})
	t.Run("If the context's deadline passes while a write is waiting, or at or before NegotiationSeconds after the opening write began while a read is waiting, then Negotiate shall return ErrDeadlineEnded.", func(t *testing.T) {
		t.Parallel()
		t.Run("a caller that floods and never reads, the context's deadline at 5 seconds: ErrDeadlineEnded at 5 seconds, not TimedOut at 3", func(t *testing.T) {
			t.Parallel()
			deadline := time.Now().Add(5 * time.Second)
			pair := connect(t)
			call := negotiate(withDeadline(t, deadline), pair.server)
			stallNegotiation(t, pair, call)
			expectReturn(t, call.result(t, deadline.Add(margin)), 0, []error{telnet.ErrDeadlineEnded, context.DeadlineExceeded}, deadline, deadline.Add(margin))
		})
		t.Run("the same, the context reporting its end only later: the clock tells", func(t *testing.T) {
			t.Parallel()
			deadline := time.Now().Add(5 * time.Second)
			pair := connect(t)
			call := negotiate(endsLate(t, deadline), pair.server)
			stallNegotiation(t, pair, call)
			expectReturn(t, call.result(t, deadline.Add(margin)), 0, []error{telnet.ErrDeadlineEnded, context.DeadlineExceeded}, deadline, deadline.Add(margin))
		})
	})
}

// readQuiet reads the server end until nothing more comes for a while, and returns the bytes.
func readQuiet(t *testing.T, server *net.TCPConn) []byte {
	t.Helper()
	var all []byte
	chunk := make([]byte, 64<<10)
	for {
		_ = server.SetReadDeadline(time.Now().Add(quiet))
		got, err := server.Read(chunk)
		all = append(all, chunk[:got]...)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return all
		}
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("reading the server end: %v, after %d bytes", err, len(all))
		}
		if err != nil {
			return all
		}
	}
}
