// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package listener is the listeners and the shared execution path: it accepts callers on the
// engine's listening sockets and serves each one, from accept to close, whichever way it came in.
//
// It is built on the developer's design for Part 3, in his words: "There are two listeners, one
// for Telnet and one for SSH. The listeners' job is just to accept the connections. It then hands
// each connection off to a shared execution path as a class. That class defines identical
// primitives that the shared execution uses." Each listener is a Kind: one kind of connection's
// listening sockets and its Open. The class is Caller, the identical primitives: SendChar,
// RecvChar, Flush and Echoes, which textio builds the session's calls on, and Close, the kind's
// own close. Telnet's Caller is the telnet package's Line, made by its Accept; SSH's is the ssh
// package's Channel. The listener hands each accepted connection to the shared execution path with
// its kind's Open, and the path makes it the kind's object there, so that negotiation and the
// handshake count toward the cap and the ceiling.
//
// It owns the listeners: one accept loop per listening socket, until Stop, which only accepts;
// after a failed accept, unless Stop closed that socket, it pauses and accepts again, and writes
// nothing; after Stop closes a socket, its accept loop ends. It owns the shared execution path:
// the cap of 100 open connections across every listener, and closing a connection over the cap at
// once without writing to it; and each connection's life, from the 70-second ceiling on the whole
// call, counted from accept, through its kind's Open, textio.New over the Caller and the session's
// Run, to the Caller's Close once the call is answered, and the close. Each connection's context is
// made by Start, carries the ceiling, and is ended at once by Stop.
//
// It does not own negotiation, the handshake, urgent data or either kind's own close, which are
// each kind of connection's; it imports neither. Reading a line and its echo are the textio
// package's; what the call says and asks, the greeting and the name among them, is the session's.
// The command line, opening the listening sockets, reading the host key, the root check, the local
// log and the stop signals belong to the program, which pairs each kind's sockets with its Open.
// Later layers own the per-source cap, settings and the central audit system. It has no files and
// writes no local log.
//
// What the engine does as a whole, this package included, is in docs/behavior.md.
//
// # Untrusted input
//
// Two things cross the trust boundary at the network listeners. Every byte the caller sends: the
// kind of connection reads it, through Open, the Caller and its Close, and the textio package edits
// it; this package reads none. And how the caller behaves: how many connections and how fast,
// silence, never reading, a handshake or a negotiation that never ends; the cap and the ceiling
// bound all of them, for every kind alike. There is no fuzz target here: this package parses
// nothing.
//
// # What it needs from its callers
//
// Listening TCP sockets, already open, each handed to one Start only and not used by the caller
// after a Start that returned a Listener; after a refused Start, the caller closes them. For each
// kind, an Open that makes an accepted connection its kind's object under the context it is given,
// returns an error rather than a nil Caller, and leaves nothing of its own running once the
// connection is closed.
//
// # Each connection
//
// These lines are for a connection kept under the cap; one over it is closed at once, as above.
//
//   - The listener package shall call the kind's Open, then, with textio.New over the Caller it
//     returns, session.Run, each once, under the connection's context, from the connection's own
//     goroutine. [read]
//   - When Run returns session.Answered, the listener package shall call the Caller's Close once,
//     under the connection's context, and then close the connection.
//   - When Open returns an error or a nil Caller, or Run returns anything but session.Answered,
//     the listener package shall close the connection without calling Close.
//   - When the connection's context ends, the listener package shall close the connection at once.
//
// # Lines for the package
//
//   - The listener package shall read nothing from a connection and write nothing to one itself:
//     every byte goes through its kind's Open and Caller. [read]
//   - The listener package shall treat every Kind alike, and name no kind of connection. [read]
//   - The listener package shall write nothing to standard output or standard error. [read]
//   - The listener package shall import nothing outside the Go standard library and the textio
//     and session packages. [read]
package listener

import (
	"context"
	"errors"
	"net"

	"github.com/heliosestate/heliosadvance/internal/textio"
)

const (
	// ConnectionCap is the number of open connections across every listening socket. Fixed in
	// this layer, as are the times below; settings once configuration exists.
	ConnectionCap = 100
	// CeilingSeconds is the whole call, counted from accept, over Open, the name and the Caller's
	// Close, for every kind alike. It is what ends a caller that never reads, whose stalled writes
	// the name's own 60 seconds may never reach.
	CeilingSeconds = 70
	// AcceptPauseFirstMilliseconds is the first pause before the next Accept after a failure; it
	// doubles after each further failure, up to AcceptPauseMostMilliseconds.
	AcceptPauseFirstMilliseconds = 5
	// AcceptPauseMostMilliseconds is the longest pause between tries.
	AcceptPauseMostMilliseconds = 1000
)

// ErrNoListeners means Start was given no Kind, a Kind with no listening socket or a nil one, or
// a Kind with no Open.
var ErrNoListeners = errors.New("listener: no listener, or one without sockets or Open")

// Caller is a connection as its kind's object: the class of the developer's design, whose
// identical primitives the shared execution path uses. Declared here, where it is used.
type Caller interface {
	// SendChar, RecvChar, Flush and Echoes are the kind's character calls, which textio builds
	// the session's calls on.
	textio.Chars
	// Close is the kind's own close once the call is answered, waiting no later than the
	// context's deadline: for Telnet, shutting down the sending side and the closing wait; for
	// SSH, the end of the channel and its wait. It leaves closing the connection to this package.
	Close(ctx context.Context) error
}

// Open makes one accepted connection its kind's object under the call's context: Telnet's
// negotiation, SSH's handshake and channel. On an error it returns a nil Caller, and the shared
// execution path closes the connection without writing to it.
type Open func(ctx context.Context, connection *net.TCPConn) (Caller, error)

// Kind is one listener: one kind of connection's listening sockets, and its Open.
type Kind struct {
	// Sockets are the kind's listening TCP sockets, which the program opened.
	Sockets []*net.TCPListener
	// Open makes each connection accepted on Sockets the kind's object.
	Open Open
}

// Listener is one run's listeners and shared execution path: its listening sockets, its cap and
// its connections. A Listener not made by Start, or nil, does nothing, and Stop on it returns at
// once.
type Listener struct {
	state listenerState
}

// Start is the one call that puts the engine's listeners to work, every kind's at once, on one
// shared execution path, so that the cap counts every kind together: the operating system's TCP
// sockets, which the program opened, so that each accepted connection is a *net.TCPConn. It starts
// one accept loop per listening socket and returns at once; each loop runs until Stop. Each
// accepted connection is served on its own goroutine, with the Open of the Kind whose socket
// accepted it. It refuses before it accepts anything, leaves nothing running, and returns a nil
// Listener with ErrNoListeners, its only error. When it refuses, it closes none of the sockets it
// was given: they stay the caller's to close.
func Start(kinds []Kind) (*Listener, error) {
	return start(kinds)
}

// Stop closes every listening socket and every open connection at once, and returns when nothing
// of this package's is running. A second call, and a call on a Listener Start did not return,
// does nothing. It never fails.
func (listener *Listener) Stop() {
	listener.stop()
}
