// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package listener accepts callers on the engine's listening sockets and serves each one, from
// accept to close.
//
// It owns accepting callers on the listening sockets the program opened and hands it, one accept
// loop per listening socket, until Stop; the cap of 100 open connections across them, and closing
// a connection over the cap at once without writing to it; and each connection's life, from the
// 70-second ceiling on the whole call, counted from accept, through keeping TCP urgent data in
// line, the telnet package's Open and the session's Run, to shutting down its sending side,
// reading and discarding until the caller closes or 3 seconds pass, and the close. Each
// connection's context is made by Start, carries the ceiling, and is ended at once by Stop. After
// a failed accept, unless Stop closed that socket, it pauses and accepts again, and writes
// nothing; after Stop closes a socket, its accept loop ends.
//
// It does not own negotiation or the Telnet side of the caller's characters, which are the telnet
// package's; reading a line and its echo, which are the textio package's; nor what the call says
// and asks, the greeting and the name among them, which is the session's. The command line,
// opening the listening sockets, the root check, the local log and the stop signals belong to the
// program. Later layers own the per-source cap, settings and the central audit system. It has no
// files and writes no local log.
//
// What the engine does as a whole, this package included, is in docs/behavior.md.
//
// # Untrusted input
//
// Two things cross the trust boundary at the network listener. Every byte the caller sends: until
// Run returns, the telnet package reads it and the textio package edits it; after Run returns
// Answered, this package reads it into a fixed buffer and discards it unread, and what the Line
// had read and not handed on is dropped with the Line. And how the caller behaves: how many
// connections and how fast, silence, never reading; the cap and the ceiling bound both. There is
// no fuzz target here: this package parses nothing, and every byte read for meaning goes to
// telnet's Receive and Strip and textio's Edit.
//
// # What it needs from its callers
//
// Listening TCP sockets, already open, each handed to one Start only and not used by the caller
// after a Start that returned a Listener; after a refused Start, the caller closes them.
//
// # Each connection
//
// Urgent data is kept in line (SO_OOBINLINE) because RFC 6093 section 6 requires it of an
// application that still uses urgent data, as Telnet's Synch does: without it a Synch's DM byte
// leaves the stream, and the lone IAC before it would swallow the caller's next character. The
// standard library has no call for it, so it is set through the connection's SyscallConn with
// syscall.SetsockoptInt, at the socket level: on Linux the value is syscall.SO_OOBINLINE, 0x0A; on
// Windows, where the syscall package names none, it is Winsock's SO_OOBINLINE, 0x0100. Set after
// accept, it also keeps in line urgent data that arrived before accept (probed on both).
//
// These lines are for a connection kept under the cap; one over it is closed at once, as above.
//
//   - The listener package shall set SO_OOBINLINE on the connection before it reads from or writes
//     to it.
//   - If SO_OOBINLINE cannot be set, then the listener package shall close the connection without
//     writing to it. [read]
//   - Once SO_OOBINLINE is set, the listener package shall call telnet.Open and then, with
//     textio.New over the Line Open returns, session.Run, each once, under the connection's
//     context, from the connection's own goroutine, whichever Outcome Open returns. [read]
//   - When Run returns session.Answered, the listener package shall shut down the connection's
//     sending side, then read and discard until the caller closes or ClosingWaitSeconds pass, no
//     later than the ceiling, then close the connection.
//   - If shutting down the sending side or setting the closing wait's read deadline fails, then
//     the listener package shall close the connection at once. [read]
//   - When Open returns an error, or Run returns anything but session.Answered, the listener
//     package shall close the connection without writing to it.
//   - The listener package shall set the read deadline for the closing wait itself, and rely on no
//     deadline a call of the telnet or textio package left. [read]
//
// # Lines for the package
//
//   - The listener package shall read a caller's bytes itself only after Run returns Answered, only
//     into a buffer of DiscardBufferSize bytes, and keep no copy of them. [read]
//   - The listener package shall write nothing to a connection itself: every byte it sends goes
//     through the telnet package's Open and Line. [read]
//   - The listener package shall write nothing to standard output or standard error. [read]
//   - The listener package shall import nothing outside the Go standard library and the telnet,
//     textio and session packages. [read]
package listener

import (
	"errors"
	"net"
)

const (
	// ConnectionCap is the number of open connections across every listening socket. Fixed in
	// this layer, as are the times below; settings once configuration exists.
	ConnectionCap = 100
	// CeilingSeconds is the whole call, counted from accept, over negotiation, the name, the
	// shutdown and the closing wait. It is what ends a caller that never reads, whose stalled
	// writes the name's own 60 seconds may never reach.
	CeilingSeconds = 70
	// ClosingWaitSeconds is the wait after shutting down the sending side, for the caller to
	// close.
	ClosingWaitSeconds = 3
	// DiscardBufferSize is the fixed buffer read into after Run returns Answered: nothing the
	// caller sends grows it.
	DiscardBufferSize = 256
	// AcceptPauseFirstMilliseconds is the first pause before the next Accept after a failure; it
	// doubles after each further failure, up to AcceptPauseMostMilliseconds.
	AcceptPauseFirstMilliseconds = 5
	// AcceptPauseMostMilliseconds is the longest pause between tries.
	AcceptPauseMostMilliseconds = 1000
)

// ErrNoListeners means Start was given no listening socket, or one that is nil.
var ErrNoListeners = errors.New("listener: no listening socket, or a nil one")

// Listener is one run's accepting: its listening sockets, its cap and its connections. A Listener
// not made by Start, or nil, does nothing, and Stop on it returns at once.
type Listener struct {
	state listenerState
}

// Start is the one call that puts the engine's listening sockets to work: the operating system's
// TCP sockets, which the program opened, so that each accepted connection is a *net.TCPConn whose
// sending side can be shut down on its own. It starts one accept loop per listening socket and
// returns at once; each loop runs until Stop. Each accepted connection is served on its own
// goroutine. It refuses before it accepts anything, leaves nothing running, and returns a nil
// Listener with ErrNoListeners, its only error. When it refuses, it closes none of the sockets
// it was given: they stay the caller's to close.
func Start(listeners []*net.TCPListener) (*Listener, error) {
	return start(listeners)
}

// Stop closes every listening socket and every open connection at once, and returns when nothing
// of this package's is running. A second call, and a call on a Listener Start did not return,
// does nothing. It never fails.
func (listener *Listener) Stop() {
	listener.stop()
}
