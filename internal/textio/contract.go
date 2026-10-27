// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package textio builds a caller's string calls on a connection's character calls, once for every
// kind of connection.
//
// It owns SendString and RecvString, built on the SendChar and RecvChar each kind of connection
// supplies: the line editor that reads a line, with the characters a line may hold, its length,
// backspace, erasing the whole line and the end of the line; echoing as it edits, unless the
// connection says it does not echo; and flushing what was sent. A Conn wraps one kind of
// connection and offers all four calls, SendChar, RecvChar, SendString and RecvString, to the
// session.
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
// first form: only a character from space to tilde, 0x20 to 0x7E, is ever added to a line; no
// other byte is added, and none is ever written back as itself. Edit is the fuzz target. On every
// run: it never panics; a line never holds more than its limit nor a byte outside 0x20 to 0x7E;
// what it echoes is only bytes it added, BS, space and BS for each one removed, and CR LF at the
// end; the echo is never longer than four times the bytes read, since a character echoes at most
// four bytes, one when it is added and three when it is removed, for the one byte that added it,
// and the CR LF that ends a line needs a character added and the byte that ends it; the same bytes
// give the same line and the same echo however they are split; and once a line ends it stays
// ended.
//
// # Calls and results
//
// Every call takes the call's context, which carries its ceiling and ends at once on a stop, and
// reports why it stopped in the standard library's own terms, the same at every layer, so no layer
// imports another's errors to read what the caller or the connection did. The one error of its
// own, ErrMostOutOfRange, is a wrong call, which no caller's doing can bring about:
//
//	Result                       Means
//	os.ErrDeadlineExceeded       the deadline the call was given passed first
//	io.EOF                       the caller closed its side
//	the context's error,         the context ended first: the call's ceiling
//	wrapped                      (context.DeadlineExceeded) or a stop (context.Canceled)
//	any other error              the connection failed; RecvString's ErrMostOutOfRange
//	                             alone means the code calling it is wrong
//
// When two happen at once, the context ending wins, then a failure, then a passed deadline. A
// context whose deadline has passed has ended, by the clock, whatever the connection's own error
// says.
//
// # Lines for the package
//
//   - The textio package shall write to the caller only through its Chars' SendChar and Flush.
//     [read]
//   - The textio package shall keep no copy of a line once RecvString returns. [read]
//   - The textio package shall write nothing to standard output or standard error. [read]
//   - The textio package shall import nothing outside the Go standard library and the timeup
//     package. [read]
package textio

import (
	"context"
	"errors"
	"time"
)

// MostLine is the longest line RecvString takes; a caller asking for more is refused.
const MostLine = 255

// ErrMostOutOfRange is RecvString refusing a limit below 1 or above MostLine: the code calling it
// is wrong, not the caller or the connection, so it is the one error the table does not name.
var ErrMostOutOfRange = errors.New("textio: a line's limit must be from 1 to MostLine")

// Chars is what a kind of connection supplies, declared here where it is used. Each kind of
// connection is its own type with these calls, and hides inside it everything that kind needs.
type Chars interface {
	// SendChar queues one byte for the caller, and writes only when the queue is full. What is
	// queued is written by Flush, by SendChar when the queue is full, under the context, and by
	// RecvChar before it waits for the caller or when a reply needs room, under its deadline. Its
	// results are the table's.
	SendChar(ctx context.Context, character byte) error
	// RecvChar returns the caller's next data byte, waiting no later than deadline: once deadline
	// has passed it returns os.ErrDeadlineExceeded, even with bytes waiting. It writes what is
	// queued before it waits for the caller, and when the queue has no room for the connection's
	// own replies, under deadline. It returns the bytes the caller sent, in the order sent, those
	// that came before the call included, and never a byte of the connection's own commands, but
	// for the editing commands a kind of connection hands on as the bytes Edit reads for them:
	// Telnet's EC as BS, 0x08, and its EL as Ctrl-U, 0x15. Its results are the table's.
	RecvChar(ctx context.Context, deadline time.Time) (byte, error)
	// Flush writes what is queued. Once a write fails, the kind of connection writes nothing
	// more, since what a write cut short sent cannot be known. Its results are the table's.
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

// SendChar is the kind of connection's own SendChar: it queues the byte, which goes out with the
// next SendString or when a RecvChar or RecvString writes, as Chars says.
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
//   - RecvString shall queue its echo with SendChar under the call's context, and call no Flush:
//     the echo goes out when what is queued is next written, as Chars says, or with the next
//     SendString.
//   - If most is below 1 or above MostLine, then RecvString shall read nothing and return
//     ErrMostOutOfRange.
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
//	Ctrl-U 0x15, the line not empty             every character removed; echo the three bytes
//	                                            BS, space, BS once for each, one group after
//	                                            another
//	CR 0x0D or LF 0x0A, the line not empty      the line ends; echo CR LF
//	BS, DEL, Ctrl-U, CR or LF, the line empty   nothing; echo nothing
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
//   - When the byte is Ctrl-U (0x15) and the line holds a character, Edit shall remove every
//     character and echo the three bytes BS, space, BS once for each character, one group after
//     another.
//   - When the byte is CR or LF and the line holds a character, Edit shall end the line and echo
//     CR LF.
//   - If the byte is BS, DEL, Ctrl-U, CR or LF and the line is empty, then Edit shall change
//     nothing and echo nothing.
//   - Edit shall keep spaces as they come, leading and trailing ones included.
//   - After the line has ended, Edit shall change nothing and echo nothing.
//   - Edit shall return for every byte without panicking.
func Edit(line Line, character byte) (Line, []byte, bool) {
	return edit(line, character)
}
