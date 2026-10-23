// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package session runs a caller's call once the connection is ready, whichever way the caller
// came in.
//
// It owns, in this layer, what the call says and asks: the greeting, the prompt, the 60 seconds
// the caller has to answer and the 30 characters a name may hold, and writing Hello and the name.
// It talks to the caller only through a Connection's four calls, SendChar, RecvChar, SendString
// and RecvString, and never knows which kind of connection it has.
//
// It does not own how a line is read, edited or echoed, which the textio package owns once for
// every kind of connection; nor negotiation, whether echoing is in effect, the send and receive
// buffers or how bytes cross the wire, which each kind of connection owns. Accepting, the cap of
// 100, the 70-second ceiling on the whole call, shutting down the sending side, the closing wait
// and closing belong to the Listener. It writes nothing to the local log and never stores a name.
//
// What the engine does as a whole, this package included, is in docs/behavior.md.
//
// # Untrusted input
//
// The name is the caller's text. It reaches the session through RecvString, whose line editor is
// the board's shared cleaner in its first form: only 0x20 to 0x7E, at most the limit given, every
// other byte dropped and never written back. The session writes the name back only after it, so
// no ESC, no byte with its high bit set (0x9B among them), no bell and no CR reaches a screen from
// a name.
//
// # What it needs from its callers
//
// A Connection that is ready: negotiation over, whatever the kind of connection needs done. A
// context that carries the call's ceiling and ends at once on a stop. One Run per connection, from
// one goroutine: Run itself never calls the Connection from two at once.
//
// # Lines for the package
//
//   - The session package shall write to the caller only through its Connection's calls. [read]
//   - The session package shall keep no copy of a name once Run returns, and write none to a file,
//     the database or any log. [read]
//   - The session package shall write nothing to standard output or standard error. [read]
//   - The session package shall import nothing outside the Go standard library. [read]
package session

import (
	"context"
	"errors"
	"time"
)

const (
	// Greeting is written first, in ASCII, CR LF its new line.
	Greeting = "Hello Helios Advance BBS!\r\n"
	// Prompt is written after the greeting; the space after the question mark sets the caller's
	// typing apart from it.
	Prompt = "What is your name? "
	// Reply comes before the name in the answer, which ends with CR LF.
	Reply = "Hello "
	// NameSeconds is counted from the moment Prompt has been written; typing does not restart it.
	// Fixed in this layer; a setting once configuration exists.
	NameSeconds = 60
	// NameMostCharacters bounds this prompt's name only; a handle's own limit is the accounts
	// layer's.
	NameMostCharacters = 30
)

// Connection is a caller's connection as the session uses it, declared here where it is used:
// the four calls of the developer's design, with SendString and RecvString built on SendChar and
// RecvChar. A textio.Conn over any kind of connection is one. Results are the standard library's
// own, the same at every layer: os.ErrDeadlineExceeded when the deadline given passed first,
// io.EOF when the caller closed its side, the context's error, wrapped, when the context ended
// first, any other error when the connection failed.
type Connection interface {
	// SendChar queues one byte for the caller.
	SendChar(ctx context.Context, character byte) error
	// RecvChar returns the caller's next data byte, waiting no later than deadline.
	RecvChar(ctx context.Context, deadline time.Time) (byte, error)
	// SendString writes text to the caller.
	SendString(ctx context.Context, text string) error
	// RecvString reads one line of at most most characters, waiting no later than deadline.
	RecvString(ctx context.Context, deadline time.Time, most int) (string, error)
}

// Ending is how a call ended when nothing failed.
type Ending int

const (
	// Answered means the caller ended the name and Reply, the name and CR LF were written.
	Answered Ending = iota + 1
	// NoName means NameSeconds passed after the prompt before the caller ended the name; nothing
	// more was written.
	NoName
)

var (
	// ErrCallerClosed means the caller closed its side before the call ended.
	ErrCallerClosed = errors.New("session: the caller closed the connection")
	// ErrConnectionFailed means any other failure of the Connection.
	ErrConnectionFailed = errors.New("session: the connection failed")
	// ErrCallEnded means the context ended first: the call's ceiling or a stop. It is returned
	// wrapping context.DeadlineExceeded or context.Canceled, so errors.Is matches both.
	ErrCallEnded = errors.New("session: the call ended first")
)

// Run is the one call the Listener makes per connection once it is ready. It writes Greeting and
// Prompt with SendString, reads the name with RecvString against NameSeconds after Prompt was
// written and a limit of NameMostCharacters, and on a name writes Reply, the name and CR LF with
// SendString. With an error it returns no Ending. Results: ErrCallerClosed, ErrConnectionFailed,
// ErrCallEnded.
//
//   - When it is called, Run shall write Greeting and then Prompt before it reads.
//   - Run shall read the name with RecvString, with a deadline of NameSeconds after Prompt was
//     written, which typing does not move, and a limit of NameMostCharacters.
//   - Run shall count toward the name what the caller sent after negotiation and before Prompt
//     was written, as RecvString reads it.
//   - When RecvString returns a name, Run shall write Reply, the name and CR LF, and return
//     Answered.
//   - When RecvString returns os.ErrDeadlineExceeded, Run shall write nothing more and return
//     NoName.
//   - If the context has ended when Run is called, then Run shall return ErrCallEnded without
//     writing.
//   - When a call returns the context's error, Run shall return ErrCallEnded wrapping it; io.EOF,
//     ErrCallerClosed; any other error, ErrConnectionFailed wrapping it.
func Run(ctx context.Context, connection Connection) (Ending, error) {
	return run(ctx, connection)
}
