// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package listener accepts callers on the engine's listening sockets and serves each one, from
// accept to close.
//
// It owns accepting callers on the listening sockets the program opened and hands it, one accept
// loop per listening socket, until Stop; the cap of 100 open connections across them, and closing
// a connection over the cap at once without writing to it; and each connection's life, from the
// 10-second hard deadline at accept, through negotiation (the telnet package), the greeting,
// shutting down its sending side, reading and discarding until the caller closes or 3 seconds
// pass, to the close. Each connection's context is made by Start, carries the hard deadline, and
// is ended at once by Stop. After a failed accept, unless Stop closed that socket, it pauses and
// accepts again, and writes nothing; after Stop closes a socket, its accept loop ends.
//
// It does not own negotiation itself, which is the telnet package's. The command line, opening the
// listening sockets, the root check, the local log and the stop signals belong to the program.
// Later layers own the per-source cap, settings and the central audit system. It has no files and
// writes no local log.
//
// What the engine does as a whole, this package included, is in docs/behavior.md.
//
// # Untrusted input
//
// Two things cross the trust boundary at the network listener. Every byte the caller sends:
// during negotiation the telnet package reads it; after it, this package reads it into a fixed
// buffer and discards it unread. And how the caller behaves: how many connections and how fast,
// silence, never reading; the cap and the hard deadline bound both. There is no fuzz target here:
// this package parses nothing, and every byte read for meaning goes to telnet's Receive.
//
// # What it needs from its callers
//
// Listening TCP sockets, already open, each handed to one Start only and not used by the caller
// after a Start that returned a Listener; after a refused Start, the caller closes them.
//
// # Lines for the package
//
//   - The listener package shall read a caller's bytes after negotiation only into a buffer of
//     DiscardBufferSize bytes, and keep no copy of them. [read]
//   - The listener package shall write nothing to a connection but what Negotiate writes and the
//     greeting.
//   - The listener package shall write nothing to standard output or standard error. [read]
//   - The listener package shall import nothing outside the Go standard library and the telnet
//     package. [read]
package listener

import (
	"errors"
	"net"
)

const (
	// ConnectionCap is the number of open connections across every listening socket. Fixed in
	// this layer, as are the times below; settings once configuration exists.
	ConnectionCap = 100
	// HardDeadlineSeconds is counted from accept, over every write and wait.
	HardDeadlineSeconds = 10
	// ClosingWaitSeconds is the wait after shutting down the sending side, for the caller to
	// close.
	ClosingWaitSeconds = 3
	// DiscardBufferSize is the fixed buffer read into after negotiation: nothing the caller sends
	// grows it.
	DiscardBufferSize = 256
	// AcceptPauseFirstMilliseconds is the first pause before the next Accept after a failure; it
	// doubles after each further failure, up to AcceptPauseMostMilliseconds.
	AcceptPauseFirstMilliseconds = 5
	// AcceptPauseMostMilliseconds is the longest pause between tries.
	AcceptPauseMostMilliseconds = 1000
	// Greeting is written in ASCII, CR LF its new line (RFC 854).
	Greeting = "Hello Helios Advance BBS!\r\n"
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
