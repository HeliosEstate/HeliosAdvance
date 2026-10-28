// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package listener is what every kind of connection's listener is built on, and the shared
// execution path: a Listener accepts callers of one kind at the listening sockets the program
// opened for it, and the shared execution path serves each one, from accept to close, whichever
// way it came in.
//
// It is built on the developer's design for Part 3, in his words: "There are two listeners, one
// for Telnet and one for SSH. The listeners' job is just to accept the connections. It then hands
// each connection off to a shared execution path as a class. That class defines identical
// primitives that the shared execution uses." And for Part 5, his words of 2026-10-25: "Which is
// why I said I wanted a listener per type", with "The cap can live as a global variable.
// Eventually it will just be a configuration item in the database"; and of 2026-10-28:
// "Personally, I would write each listener as a separate function, so that their code is
// grouped", "So long as each Listener can be started and stopped independently." So each kind of
// connection has its own Listener, made by its own function in the program from that kind's
// sockets and its Open, with its own Start and its own Stop. The accept loops are written once,
// here, for every kind. The class is KindConnection, the identical primitives: SendChar and
// RecvChar, the page's; Flush and Echoes, which textio's Chars asks of every kind of connection;
// and Close, the kind's own close.
// Each accepted connection is handed to the shared execution path with its kind's Open, and the
// path makes it the kind's object there, so that negotiation and the handshake count toward the
// cap and the ceiling: the developer's decision of 2026-10-25.
//
// It owns each Listener: from its Start, one accept loop per listening socket, which only accepts,
// until that Listener's Stop; after a failed accept, unless Stop closed that socket, it pauses and
// accepts again, and writes nothing; after Stop closes a socket, its accept loop ends. It owns the
// shared execution path: the cap of ConnectionCap open connections, one limit for every kind
// together, counted in a ConnectionCount every Listener of one engine shares, and closing a
// connection over the cap at once without writing to it; and each connection's life, from the
// 70-second ceiling on the whole call, counted from accept, through its kind's Open, textio.New
// over the KindConnection and the session's Run, to the KindConnection's Close once the call is
// answered, and the close. Each connection's context is made by the shared execution path,
// carries the ceiling, and is ended at once by the Stop of the Listener that accepted it.
//
// It does not own negotiation, the handshake, urgent data or any kind's own close, which are each
// kind of connection's; it imports none of them. Reading a line and its echo are the textio
// package's; what the call says and asks, the greeting and the name among them, is the session's.
// The command line, the addresses each kind listens at, opening the listening sockets, reading the
// host key, the root check, the local log and the stop signals belong to the program, which makes
// the engine's one ConnectionCount, makes every kind's Listener before it starts any, and stops
// them all together. Later layers own the per-source cap, settings and the central audit system.
// It has no files and writes no local log.
//
// What the engine does as a whole, this package included, is in docs/behavior.md.
//
// # Untrusted input
//
// Two things cross the trust boundary at the network listeners. Every byte the caller sends: the
// kind of connection reads it, through Open, the KindConnection and its Close, and the textio
// package edits it; this package reads none. And how the caller behaves: how many connections and
// how fast, silence, never reading, a handshake or a negotiation that never ends; the cap and the
// ceiling bound all of them, for every kind alike. There is no fuzz target here: this package
// parses nothing.
//
// # What it needs from its callers
//
// One ConnectionCount per engine, from NewCount, handed to every New of that engine. One New per
// kind of connection, given every listening socket of that kind and that kind's one Open, so that
// each Listener is one kind's, as the glossary has it, and its Stop stops that kind alone.
// Listening TCP sockets, already open, each handed to one New only and not used by the caller
// after a New that returned a Listener; after a refused New, the caller closes them. For each
// kind, an Open that makes an accepted connection its kind's object under the context it is
// given, returns an error with a nil KindConnection rather than a KindConnection holding a nil
// object, and leaves nothing of its own running once the connection is closed.
//
// # The count
//
//   - The listener package shall keep open, across every Listener made with one ConnectionCount,
//     at most ConnectionCap connections at once.
//   - When a Listener accepts a connection while its ConnectionCount already holds ConnectionCap
//     open connections, the listener package shall close that connection at once without writing
//     to it.
//   - When a connection a Listener kept closes, by any path, the listener package shall free its
//     place in the ConnectionCount.
//   - The listener package shall count only in the ConnectionCount New was given: Listeners made
//     with different ConnectionCounts shall not count each other's connections.
//
// # Each connection
//
// These lines are for a connection kept under the cap; one over it is closed at once, as above.
//
//   - The listener package shall call the kind's Open once, under the connection's context, from
//     the connection's own goroutine. [read]
//   - When Open returns a KindConnection and no error, the listener package shall call
//     session.Run once, with textio.New over it, under the connection's context, from the
//     connection's own goroutine. [read]
//   - When Run returns session.Answered, the listener package shall call the KindConnection's
//     Close once, under the connection's context, and then close the connection.
//   - When Open returns an error or a nil KindConnection, or Run returns anything but
//     session.Answered, the listener package shall close the connection without writing to it and
//     without calling Close.
//   - When the connection's context ends, the listener package shall close the connection at once.
//
// # Lines for the package
//
//   - The listener package shall read nothing from a connection and write nothing to one itself:
//     every byte goes through its kind's Open and KindConnection. [read]
//   - The listener package's code shall treat every kind of connection alike, and name none.
//     [read]
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
	// ConnectionCap is the number of open connections across every Listener sharing one
	// ConnectionCount: one setting for every kind together. Fixed in this layer, as are the times
	// below; a setting in the database once configuration exists.
	ConnectionCap = 100
	// CeilingSeconds is the whole call, counted from accept, over Open, the name and the kind's
	// Close, for every kind alike. It is what ends a caller that never reads, whose stalled writes
	// the name's own 60 seconds may never reach.
	CeilingSeconds = 70
	// AcceptPauseFirstMilliseconds is the first pause before the next Accept after a failure; it
	// doubles after each further failure, up to AcceptPauseMostMilliseconds.
	AcceptPauseFirstMilliseconds = 5
	// AcceptPauseMostMilliseconds is the longest pause between tries.
	AcceptPauseMostMilliseconds = 1000
)

// ErrNoListeners means New was given no listening socket or a nil one, no Open, or a nil
// ConnectionCount.
var ErrNoListeners = errors.New("listener: no sockets, no Open or no count")

// KindConnection is a connection as its kind's object: the class of the developer's design, whose
// identical primitives the shared execution path uses. Declared here, where it is used.
type KindConnection interface {
	// SendChar, RecvChar, Flush and Echoes are the kind's character calls, which textio builds
	// the session's calls on.
	textio.Chars
	// Close is the kind's own close once the call is answered, waiting no later than the
	// context's deadline: for Telnet, shutting down the sending side and the closing wait; for
	// SSH, the end of the channel and its wait. It leaves closing the connection to this package.
	Close(ctx context.Context) error
}

// Open makes one accepted connection its kind's object under the call's context: Telnet's
// negotiation, SSH's handshake and channel. On an error it returns a nil KindConnection, never one
// holding a nil object, and the shared execution path closes the connection without writing to
// it. A kind whose way in returns its own type, as telnet.Accept returns *telnet.Line, is adapted
// by the program so that an error gives a nil KindConnection.
type Open func(ctx context.Context, connection *net.TCPConn) (KindConnection, error)

// ConnectionCount is one engine's count of open connections. The program makes it once and hands
// it to every New, so all kinds share one ConnectionCap: with 51 Telnet callers, SSH takes the
// other 49. It is handed in, not global, so that tests running side by side in one test program
// each count their own engine's callers. A ConnectionCount is safe for use by every Listener at
// once.
type ConnectionCount struct {
	state countState
}

// NewCount makes an empty ConnectionCount, the one every Listener of an engine shares.
func NewCount() *ConnectionCount {
	return newCount()
}

// Listener is one kind of connection's listener: its listening sockets, its Open and its
// connections, counted in the ConnectionCount it was made with, with its own Start and Stop. A
// Listener not made by New, or nil, does nothing, and Start and Stop on it return at once.
type Listener struct {
	state listenerState
}

// New makes one kind's Listener from the listening TCP sockets the program opened for that kind,
// so that each accepted connection is a *net.TCPConn, to make each connection it accepts the
// kind's object with open and count it in count. It serves no caller until Start, so the program
// can make every kind's Listener before any serves, and a start that fails serves no caller. A
// caller who connects before Start waits in the operating system's queue for the socket, which
// this package does not decide and these lines do not pin; once accepted, it is served as any
// other, its ceiling counted from that accept. It refuses before it touches any socket, leaves
// nothing running, and returns a nil Listener with ErrNoListeners, its only error. When it
// refuses, it closes none of the sockets it was given: they stay the caller's to close.
//
//   - New shall serve no caller, at any of the sockets it was given, before Start: no Open runs
//     and nothing is written.
func New(sockets []*net.TCPListener, open Open, count *ConnectionCount) (*Listener, error) {
	return newListener(sockets, open, count)
}

// Start starts this Listener accepting: one accept loop per listening socket, each running until
// this Listener's Stop, and returns at once. Each accepted connection is served on its own
// goroutine, Open included, so that one slow caller never holds up the next accept, of this kind
// or another. A call after Stop does nothing. Start and Stop are safe to call at once, from
// different goroutines, on one Listener or several.
//
//   - Start shall return at once, without waiting for a caller.
//   - Start shall start only this Listener: a Listener not yet started shall serve no caller after
//     another's Start, and one already started shall go on accepting and serving.
//   - Once Start has returned, this Listener shall accept at every one of its sockets.
//   - The listener package shall run nothing of a caller's on an accept loop: while one caller's
//     Open or call is still running, the next caller shall be accepted. [read]
//   - Start after Stop shall accept nothing: a stopped Listener stays stopped, and its kind is
//     started again by a new Listener on new sockets.
func (listener *Listener) Start() {
	listener.start()
}

// Stop closes this Listener's listening sockets and every connection it kept at once, and returns
// when nothing of this Listener's is running. Before Start, it closes the sockets alone; during
// Start, it leaves nothing of Start's running once it returns. A second call, and a call on a
// Listener New did not return, does nothing. It never fails. Stop is safe to call on several
// Listeners at once, from different goroutines, so that a caller can stop them all together.
//
//   - Stop shall close this Listener's listening sockets and every connection it kept, and return
//     only when nothing of this Listener's is running and every place its connections held in the
//     ConnectionCount is free.
//   - When Stop is called on several Listeners at once, each shall close its sockets and
//     connections without waiting for another's.
//   - Stop shall leave every other Listener, whether or not it shares this Listener's
//     ConnectionCount, accepting and serving as before.
func (listener *Listener) Stop() {
	listener.stop()
}
