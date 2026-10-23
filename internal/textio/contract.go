// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package textio builds a caller's string calls on a connection's character calls, once for every
// kind of connection.
//
// It owns SendString and RecvString, built on the SendChar and RecvChar each kind of connection
// supplies: the line editor that reads a line, with the characters a line may hold, its length,
// backspace and the end of the line; echoing as it edits, unless the connection says it does not
// echo; and flushing what was sent. A Conn wraps one kind of connection and offers all four calls,
// SendChar, RecvChar, SendString and RecvString, to the session.
//
// It does not own negotiation, whether a connection echoes, how bytes cross the wire or which bytes
// are a connection's own commands: each kind of connection owns those, behind Chars. What the
// session writes and asks for, and the time it allows, belong to the session. It writes nothing to
// the local log and stores nothing.
//
// What the engine does as a whole, this package included, is in docs/behavior.md.
//
// # Untrusted input
//
// Every byte RecvChar returns came from the caller and crosses the trust boundary at the network
// listener. Edit is the one place a line's bytes are read, and the board's shared cleaner in its
// first form: only a character from space to tilde, 0x20 to 0x7E, is ever added to a line; every
// other byte is dropped and never written back as itself. Edit is the fuzz target. On every run:
// it never panics; a line never holds more than its limit nor a byte outside 0x20 to 0x7E; what it
// echoes is only bytes it added, BS, space and BS for one removed, and CR LF at the end; the echo
// is never longer than twice the bytes read plus 2, since a removal echoes three bytes for one but
// needs a character added before it; the same bytes give the same line and the same echo however
// they are split; and once a line ends it stays ended.
//
// # Calls and results
//
// Every call takes the call's context, which carries its ceiling and ends at once on a stop, and
// reports why it stopped in the standard library's own terms, the same at every layer, so no layer
// imports another's errors:
//
//	Result                       Means
//	os.ErrDeadlineExceeded       the deadline the call was given passed first
//	io.EOF                       the caller closed its side
//	the context's error,         the context ended first: the call's ceiling
//	wrapped                      (context.DeadlineExceeded) or a stop (context.Canceled)
//	any other error              the connection failed
//
// When two happen at once, the context ending wins, then a failure, then a passed deadline.
//
// # Lines for the package
//
//   - The textio package shall write to the caller only through its Chars' SendChar and Flush.
//     [read]
//   - The textio package shall keep no copy of a line once RecvString returns. [read]
//   - The textio package shall write nothing to standard output or standard error. [read]
//   - The textio package shall import nothing outside the Go standard library. [read]
package textio

import (
	"context"
	"time"
)

// MostLine is the longest line RecvString takes; a caller asking for more is refused.
const MostLine = 255

// Chars is what a kind of connection supplies, declared here where it is used. Each kind of
// connection is its own type with these calls, and hides inside it everything that kind needs.
type Chars interface {
	// SendChar queues one byte for the caller; Flush, or the next RecvChar, writes what is queued,
	// and so does SendChar itself when the queue is full, waiting no later than the context's
	// deadline. Its results are the table's.
	SendChar(ctx context.Context, character byte) error
	// RecvChar first writes what is queued, then returns the caller's next data byte, waiting no
	// later than deadline: once deadline has passed it returns os.ErrDeadlineExceeded, even with
	// bytes waiting. It returns the bytes the caller sent, in the order sent, those that came
	// before the call included, and never a byte of the connection's own commands. Its results
	// are the table's.
	RecvChar(ctx context.Context, deadline time.Time) (byte, error)
	// Flush writes what is queued. Its results are the table's.
	Flush(ctx context.Context) error
	// Echoes is whether the board echoes what the caller types on this connection now; it may
	// change during the call as the caller asks, and RecvString asks it again at each echo.
	Echoes() bool
}

// Conn is one caller's connection with all four calls the session uses: SendChar and RecvChar,
// passed through to the kind of connection, and SendString and RecvString, built on them here. A
// Conn not made by New, or over nil Chars, fails every call with an error.
type Conn struct {
	state connState
}

// New wraps a kind of connection.
//
//   - New shall return a Conn whose SendChar and RecvChar are the given Chars' own.
func New(chars Chars) *Conn {
	return newConn(chars)
}

// SendChar is the kind of connection's own SendChar.
func (conn *Conn) SendChar(ctx context.Context, character byte) error {
	return conn.sendChar(ctx, character)
}

// RecvChar is the kind of connection's own RecvChar.
func (conn *Conn) RecvChar(ctx context.Context, deadline time.Time) (byte, error) {
	return conn.recvChar(ctx, deadline)
}

// SendString queues text's bytes with SendChar, in order, then flushes them. Results are the
// table's.
//
//   - SendString shall queue the bytes of text in order, one SendChar per byte, and then flush.
//   - If a SendChar or the flush fails, then SendString shall queue no further byte and return
//     that result.
//   - If the context has ended when SendString is called, then SendString shall write nothing and
//     return the context's error, wrapped.
func (conn *Conn) SendString(ctx context.Context, text string) error {
	return conn.sendString(ctx, text)
}

// RecvString reads one line with RecvChar, until CR or LF ends it or deadline passes, reading each
// byte with Edit and echoing what Edit gives when the connection echoes. Results are the table's;
// os.ErrDeadlineExceeded means deadline passed before the line ended.
//
//   - RecvString shall read each byte with Edit, in the order RecvChar returns them, those the
//     caller sent before the call included.
//   - While the connection echoes, as Echoes says at that byte, RecvString shall send what Edit
//     gives to echo, in order; when it does not, nothing.
//   - When Edit ends the line, RecvString shall return the line and no error, and read no byte
//     after the one that ended it.
//   - If deadline passes before the line ends, then RecvString shall return
//     os.ErrDeadlineExceeded, whatever bytes are waiting.
//   - RecvString shall call no Flush: its echo goes out with the next RecvChar, under deadline.
//   - RecvString shall give its SendChar calls a context that also ends at deadline, so a caller
//     that never reads cannot hold it past deadline; when that deadline, not the call's context,
//     ends a SendChar, RecvString shall return os.ErrDeadlineExceeded.
//   - If most is below 1 or above MostLine, then RecvString shall read nothing and return an
//     error.
//   - RecvString shall return any other result of RecvChar or SendChar as the table gives it.
func (conn *Conn) RecvString(ctx context.Context, deadline time.Time, most int) (string, error) {
	return conn.recvString(ctx, deadline, most)
}

// Line is a line being edited: the characters so far, within its limit, and whether it has
// ended. Its zero value is an empty line with a limit of 0, which adds nothing.
type Line struct {
	state lineState
}

// NewLine returns an empty line that holds at most most characters; most is clamped to 0 through
// MostLine.
func NewLine(most int) Line {
	return newLine(most)
}

// Text returns the line's characters.
func (line Line) Text() string {
	return line.text()
}

// Edit reads one byte into the line, with no connection, clock or goroutine, and returns the line
// after it, the bytes to echo and whether the line has ended:
//
//	0x20 to 0x7E, the line below its limit      added; echo it
//	0x20 to 0x7E, the line at its limit         dropped; echo nothing
//	BS 0x08 or DEL 0x7F, the line not empty     the last character removed; echo BS, space, BS
//	CR 0x0D or LF 0x0A, the line not empty      the line ends; echo CR LF
//	BS, DEL, CR or LF, the line empty           nothing; echo nothing
//	any other byte                              dropped; echo nothing
//
// Lines:
//
//   - When the byte is from 0x20 to 0x7E and the line holds fewer than its limit, Edit shall add
//     it to the line and echo it.
//   - Edit shall drop every byte the table does not add, remove with or end on, and echo nothing
//     for it.
//   - When the byte is BS or DEL and the line holds a character, Edit shall remove the last one
//     and echo BS, space, BS.
//   - When the byte is CR or LF and the line holds a character, Edit shall end the line and echo
//     CR LF.
//   - If the byte is BS, DEL, CR or LF and the line is empty, then Edit shall change nothing and
//     echo nothing.
//   - Edit shall keep spaces as they come, leading and trailing ones included.
//   - After the line has ended, Edit shall change nothing and echo nothing.
//   - Edit shall return for every byte without panicking.
func Edit(line Line, character byte) (Line, []byte, bool) {
	return edit(line, character)
}
