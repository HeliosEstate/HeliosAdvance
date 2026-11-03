// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package session runs a caller's call once the connection is ready, whichever way the caller
// came in.
//
// It owns, in this layer, what the call says and asks: the greeting, the name prompt, the 60
// seconds the caller has to answer and the 30 characters a name may hold, and the name reply, each
// text taken by its key from the board's texts it is given, and the CR LF that ends a line.
// It talks to the caller only through a Connection's four calls, SendChar, RecvChar, SendString
// and RecvString, and never knows which kind of connection it has.
//
// It does not own the texts' words, their language or how a value is put into one, which the
// language package owns; nor how a line is read, edited or echoed, which the textio package owns
// once for every kind of connection; nor negotiation, whether echoing is in effect, the send and
// receive buffers or how bytes cross the wire, which each kind of connection owns. Accepting, the
// cap of 100, the 70-second ceiling on the whole call, shutting down the sending side, the closing
// wait and closing belong to the Listener. It writes nothing to the local log and never stores a
// name.
//
// What the engine does as a whole, this package included, is in docs/behavior.md.
//
// # Untrusted input
//
// The name is the caller's text. It reaches the session through RecvString, whose line editor is
// the board's shared cleaner in its first form: only 0x20 to 0x7E, at most the limit given, every
// other byte dropped and never written back. The session writes the name back only after it, so
// no ESC, no byte with its high bit set (0x9B among them), no bell and no CR reaches a screen from
// a name; and only as the value of the name reply's placeholder, which the language package puts
// in as its characters, never read as a text's syntax.
//
// # What it needs from its callers
//
// A Connection that is ready: negotiation over, whatever the kind of connection needs done. A
// context that carries the call's ceiling and ends at once on a stop. The board's Texts, from
// language.Load. One Run per connection, from one goroutine: Run itself never calls the Connection
// from two at once.
//
// # Lines for the package
//
//   - The session package shall write to the caller only through its Connection's calls. [read]
//   - The session package shall keep no copy of a name once Run returns, and write none to a file,
//     the database or any log. [read]
//   - The session package shall write nothing to standard output or standard error. [read]
//   - The session package shall import nothing outside the Go standard library and the language
//     package. [read]
package session

import (
	"context"
	"errors"
	"time"

	"github.com/heliosestate/heliosadvance/internal/language"
)

const (
	// NameSeconds is counted from the moment the name prompt has been written; typing does not
	// restart it. Fixed in this layer; a setting once configuration exists.
	NameSeconds = 60
	// NameMostCharacters bounds this prompt's name only; a handle's own limit is the accounts
	// layer's.
	NameMostCharacters = 30
)

// Connection is a caller's connection as the session uses it, declared here where it is used:
// the four calls of the developer's design, with SendString and RecvString built on SendChar and
// RecvChar. A textio.Conn over any kind of connection is one. Results are the standard library's
// own, the same at every layer: os.ErrDeadlineExceeded when the deadline given passed first,
// io.EOF when the caller closed its side or, for a kind of connection that does not tell them
// apart, as SSH does not, the connection ended however, the context's error, wrapped, when the
// context ended first, any other error when the connection failed.
type Connection interface {
	// SendChar queues one byte for the caller; it goes out with the next SendString, when
	// RecvChar or RecvString waits for the caller or needs room for the connection's own replies,
	// or when the queue is full.
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
	// Answered means the caller ended the name and the name reply and CR LF were written.
	Answered Ending = iota + 1
	// NoName means NameSeconds passed after the name prompt before the caller ended the name;
	// nothing more was written.
	NoName
)

var (
	// ErrCallerClosed means a call returned io.EOF before the call ended: the caller closed its
	// side or, over a kind of connection that does not tell them apart, the connection ended.
	ErrCallerClosed = errors.New("session: the caller closed the connection")
	// ErrConnectionFailed means any other failure of the Connection, or nil Texts.
	ErrConnectionFailed = errors.New("session: the connection failed")
	// ErrCallEnded means the context ended first: the call's ceiling or a stop. It is returned
	// wrapping context.DeadlineExceeded or context.Canceled, so errors.Is matches both.
	ErrCallEnded = errors.New("session: the call ended first")
)

// Run is the one call the Listener makes per connection once it is ready. From texts it takes the
// greeting, language.KeyGreeting, the name prompt, language.KeyNamePrompt, and the name reply,
// language.KeyNameReply, with the name as language.PlaceholderName. It writes the greeting, CR LF
// and the name prompt with SendString, reads the name with RecvString against NameSeconds after
// the name prompt was written and a limit of NameMostCharacters, and on a name writes the name
// reply and CR LF with SendString. With an error it returns no Ending. Results: ErrCallerClosed,
// ErrConnectionFailed, ErrCallEnded.
//
//   - If texts is nil, then Run shall return ErrConnectionFailed without writing.
//   - When it is called, Run shall write the greeting and CR LF, then the name prompt, before it
//     reads.
//   - Run shall read the name with RecvString, with a deadline of NameSeconds after the name
//     prompt was written, which typing does not move, and a limit of NameMostCharacters.
//   - Run shall count toward the name what the caller sent after negotiation and before the name
//     prompt was written, as RecvString reads it.
//   - When RecvString returns a name, Run shall write the name reply, with the name as
//     language.PlaceholderName, and CR LF, and return Answered.
//   - When RecvString returns os.ErrDeadlineExceeded, Run shall write nothing more and return
//     NoName.
//   - If the context has ended when Run is called, then Run shall return ErrCallEnded without
//     writing.
//   - When a call returns the context's error, Run shall return ErrCallEnded wrapping it; io.EOF,
//     ErrCallerClosed; any other error, ErrConnectionFailed wrapping it.
func Run(ctx context.Context, connection Connection, texts *language.Texts) (Ending, error) {
	return run(ctx, connection, texts)
}
