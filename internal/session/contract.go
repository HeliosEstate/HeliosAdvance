// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package session runs a caller's call once the connection is ready, whichever way the caller
// came in.
//
// It owns, in this layer, the greeting, the prompt, reading the name and writing Hello and the
// name: what a name may hold, correcting it with backspace, the 60 seconds the caller has to end
// it, and asking the connection to echo. It reaches the caller only through a Connection, with
// SendString and RecvString built on the Connection's three calls, so the same code serves every
// way in: Telnet now, SSH in Part 3.
//
// It does not own negotiation, whether echoing is in effect, how bytes cross the wire, or which
// bytes are commands rather than data: each kind of connection owns those, inside its own type.
// Accepting, the cap of 100, the 70-second ceiling on the whole call, shutting down the sending
// side, the closing wait and closing belong to the Listener. It writes nothing to the local log
// and never stores a name.
//
// What the engine does as a whole, this package included, is in docs/behavior.md.
//
// # Untrusted input
//
// Every byte RecvChar returns came from the caller and crosses the trust boundary at the network
// listener. Only a character from space to tilde, 0x20 to 0x7E, ever reaches the name, at most
// NameMostCharacters of them; every other byte is dropped, never echoed and never sent back. So
// no ESC, no byte with its high bit set (0x9B among them), no bell and no CR reaches a screen from
// a name. This is the first form of the board's shared cleaner, with no attribute code allowed
// yet. RecvString is the fuzz target: on every input it never crashes, never returns a name
// longer than its limit or holding a byte outside 0x20 to 0x7E, and never echoes such a byte.
//
// # What it needs from its callers
//
// A Connection that is ready: negotiation over, whatever the kind of connection needs done. A
// context that carries the call's ceiling and ends at once on a stop; every call to the Connection
// gets it. One Run per connection, from one goroutine: a Connection is not used from two at once.
//
// # Lines for the package
//
//   - The session package shall write to the caller only through its Connection's SendChar and
//     Echo. [read]
//   - The session package shall keep no copy of a name once Run returns, and write none to a
//     file, the database or any log. [read]
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

// Connection is a caller's connection as the session needs it, declared here where it is used.
// Each kind of connection is its own type with these three calls, and hides inside it everything
// that kind needs: negotiation, whether it echoes, how bytes cross the wire. Every call returns
// at once once its context has ended.
type Connection interface {
	// SendChar writes one byte to the caller. It returns the context's error, wrapped, once the
	// context has ended, and any other failure as an error.
	SendChar(ctx context.Context, character byte) error
	// RecvChar returns the next byte of the caller's data, waiting no later than deadline. It
	// returns os.ErrDeadlineExceeded once deadline has passed, io.EOF once the caller has closed
	// its side, the context's error, wrapped, once the context has ended, and any other failure
	// as an error. It never returns a byte of the kind of connection's own commands.
	RecvChar(ctx context.Context, deadline time.Time) (byte, error)
	// Echo writes one byte back to the caller when this connection echoes, and nothing when it
	// does not; which is the connection's to know, fixed for the call. It fails as SendChar does.
	Echo(ctx context.Context, character byte) error
}

// Ending is how a call ended when nothing failed.
type Ending int

const (
	// Answered means the caller ended the name and Reply, the name and CR LF were written.
	Answered Ending = iota + 1
	// NoName means NameSeconds passed after the prompt before the caller ended the name;
	// nothing more was written.
	NoName
)

var (
	// ErrCallerClosed means the caller closed its side before the name ended.
	ErrCallerClosed = errors.New("session: the caller closed the connection")
	// ErrConnectionFailed means any other failure of the Connection.
	ErrConnectionFailed = errors.New("session: the connection failed")
	// ErrCallEnded means the context ended first: the call's ceiling or a stop. It is returned
	// wrapping context.DeadlineExceeded or context.Canceled, so errors.Is matches both.
	ErrCallEnded = errors.New("session: the call ended first")
)

// SendString writes text to the caller, one SendChar per byte, in order, and stops at the first
// failure. Results: ErrCallEnded, ErrConnectionFailed.
//
//   - SendString shall write the bytes of text in order, one SendChar per byte.
//   - If a SendChar fails, then SendString shall write no further byte and return the result that
//     failure gives.
func SendString(ctx context.Context, connection Connection, text string) error {
	return sendString(ctx, connection, text)
}

// RecvString reads a name from the caller through RecvChar, until CR or LF ends it or deadline
// passes, and echoes through Echo as it goes. Every byte is read by this table:
//
//	0x20 to 0x7E, while the name holds fewer than most   added, and echoed
//	0x20 to 0x7E, while the name holds most              dropped
//	BS 0x08 or DEL 0x7F, while the name holds one        the last character removed; BS,
//	                                                      space, BS echoed
//	CR 0x0D or LF 0x0A, while the name holds one         the name ends; CR LF echoed
//	BS, DEL, CR or LF, while the name is empty           nothing; the wait goes on
//	any other byte                                        dropped, nothing echoed
//
// It returns the name and Answered once the name ends, reading nothing after the byte that ends
// it; NoName once deadline passes. Results: ErrCallerClosed, ErrConnectionFailed, ErrCallEnded.
//
//   - When the caller sends a character from 0x20 to 0x7E and the name holds fewer than most,
//     RecvString shall add it to the name and echo it.
//   - RecvString shall drop every byte the table does not add, remove with or end on, and echo
//     nothing for it.
//   - When the caller sends BS or DEL while the name holds a character, RecvString shall remove
//     the last character and echo BS, space, BS.
//   - When the caller sends CR or LF while the name holds a character, RecvString shall echo CR LF
//     and return the name with Answered.
//   - If the caller sends BS, DEL, CR or LF while the name is empty, then RecvString shall echo
//     nothing and keep waiting.
//   - RecvString shall keep spaces as the caller typed them, leading and trailing ones included.
//   - RecvString shall read no byte after the one that ends the name. [read]
//   - If deadline passes before the name ends, then RecvString shall return NoName.
//   - If RecvChar returns io.EOF before the name ends, then RecvString shall return
//     ErrCallerClosed.
//   - If the context ends before the name ends, then RecvString shall return ErrCallEnded.
//   - RecvString shall hold the name in a buffer of most bytes, and keep no other copy. [read]
//   - RecvString shall return for every input without failing or panicking.
func RecvString(ctx context.Context, connection Connection, deadline time.Time, most int) (string, Ending, error) {
	return recvString(ctx, connection, deadline, most)
}

// Run is the one call the Listener makes per connection once it is ready. It writes Greeting
// and Prompt, reads the name with RecvString against NameSeconds after Prompt was written, and
// on Answered writes Reply, the name and CR LF. Results: ErrCallerClosed, ErrConnectionFailed,
// ErrCallEnded.
//
//   - When it is called, Run shall write Greeting and then Prompt before it reads.
//   - Run shall read the name with a deadline of NameSeconds after Prompt was written, which
//     typing does not move.
//   - Run shall read the name with a limit of NameMostCharacters.
//   - When RecvString returns Answered, Run shall write Reply, the name and CR LF, and return
//     Answered.
//   - When RecvString returns NoName, Run shall write nothing more and return NoName.
//   - If the context has ended when Run is called, then Run shall return ErrCallEnded without
//     writing.
//   - Run shall return the error SendString or RecvString returned, when one did.
func Run(ctx context.Context, connection Connection) (Ending, error) {
	return run(ctx, connection)
}
