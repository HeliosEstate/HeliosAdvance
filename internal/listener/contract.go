// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package listener accepts callers on the engine's listening sockets and serves each one, from
// accept to close.
//
// It owns accepting callers on the listening sockets the Service opened and hands it, one accept
// loop per listening socket, until Stop; the cap of 100 open connections across them, and closing
// a connection over the cap at once without writing to it; connection floods; the connection ID;
// each connection's life, from the 10-second hard deadline at accept, through negotiation (the
// telnet package), the greeting, shutting down its sending side, reading and discarding until the
// caller closes or 3 seconds pass, to the close; the local log's lines the table below names, each
// handed as an event and its fields to the local log the Service gives it; and the connection
// side of a stop: stop accepting, wait for the open connections to finish, close them all at once
// when the stop's deadline ends, and report how many it closed.
//
// It does not own negotiation itself, which is the telnet package's. The command line, opening
// the listening sockets, failing a start, the root check, the started line, the stop signals,
// deciding when a stop is forced, the 10-second limit on a stop, the exit code, the local log's
// format and standard output, and the stopped line belong to the Service. Later layers own the
// per-source cap, settings and the central audit system.
//
// It has no files.
//
// # Untrusted input
//
// Three things cross the trust boundary at the network listener. Every byte the caller sends:
// during negotiation the telnet package reads it; after it, this package reads it into a fixed
// buffer and discards it unread. How the caller behaves: how many connections and how fast,
// silence, never reading. And the source address, which the operating system reports but the
// caller chooses, written to the local log in the operating system's form and never parsed.
//
// There is no fuzz target here: this package parses nothing, and every byte read for meaning goes
// to telnet's Receive, which is fuzzed.
//
// # Oracles
//
// A connection's life, each closing cause and the negotiated line: QA's own scripted Telnet
// client, written from RFC 854 and RFC 1143 before and apart from this package's code, on real
// loopback sockets. Its callers read the greeting and close, never close, hang up during
// negotiation, reset the connection (a close with linger 0), and stay silent past 10 seconds.
//
// The cap and connection floods: the same client holding 100 connections open and opening more;
// each count line checked against the refusals the client counted, and their sum against the
// total.
//
// Stop: Stop called with a deadline, a cancelled context and one already ended, against held
// connections whose states the client knows.
//
// The local log's lines: a recording local log, QA's own plain LocalLog that keeps each Write in
// a list. It stands in for the Service at this package's edge and fakes nothing behind it, so it
// is not a mock.
//
// The accept_failed and accept_resumed lines: on Linux, a child process with a low limit on open
// descriptors, so that Accept really fails and recovers once one frees; on Windows, by reading the
// code, the path shared with Linux.
//
// Tests run on Linux x86-64, Linux ARM64 and Windows x86-64, as an ordinary user with no admin,
// root or container, over loopback on a port the operating system picks. A test proving a fixed
// time takes that long, runs in parallel with the others, and waits on socket deadlines, never on
// a sleep. It uses the Go standard library and the telnet package only.
//
// # What it needs from its callers
//
// Listening TCP sockets, already open, each handed to one Start only and not used by the caller
// after it. A local log whose Write is safe from many goroutines at once and turns each call into
// exactly one whole line, never interleaved with another. For Stop, a context with a deadline 10
// seconds out for a stop, cancelled by a forced stop, or already ended when the console window
// closes.
//
// # The local log
//
// The events this package writes, and their fields; the Service gives them their format. A
// connection refused over the cap gets no accepted and no closed line: the connection flood lines
// are its only record.
//
//	Event                    Fields
//	accepted                 source: the caller's address and port, as the operating system
//	                         reports them; connection: the connection ID
//	negotiated               connection; result: answered or timed_out
//	closed                   connection; how: caller_closed, timed_out, hung_up, failed,
//	                         deadline or stopped
//	refused                  source, of the refusal that starts a connection flood
//	connection_flood         count: refusals in one FloodWindowSeconds span, the first included
//	connection_flood_ended   none
//	accept_failed            listener: the listening socket's address and port; error: the
//	                         operating system's error, never caller bytes
//	accept_resumed           listener
//
// The values of how, by precedence when two land together: stopped, then deadline, then failed
// and hung_up.
//
//	caller_closed   after the greeting, the caller closed its side
//	timed_out       ClosingWaitSeconds after the shutdown, it had not
//	hung_up         the caller closed its side during negotiation
//	failed          a read, a write or the shutdown failed, a reset included
//	deadline        HardDeadlineSeconds from accept passed
//	stopped         Stop closed it at once; Stop counts these
//
// # Calls
//
// Each read with go doc on Go 1.27.2, the same on Linux and Windows unless the row says.
//
// Start's accept loops:
//
//	Call                  Why                                   Documented failures
//	AcceptTCP             waits for the next caller             net.ErrClosed once Stop closed
//	                                                            the socket. Go retries an
//	                                                            interrupted call and a connection
//	                                                            aborted before it was accepted on
//	                                                            Linux, and an early reset on
//	                                                            Windows. Linux accept(2) leaves:
//	                                                            out of descriptors, out of memory
//	                                                            or buffers, a firewall refusal, a
//	                                                            protocol error, and pending
//	                                                            network errors, to be retried
//	Addr                  the listener field                    none
//	sync.WaitGroup.Go     counts each loop and connection, so   none
//	                      Stop waits for it
//	time.AfterFunc        the pause between tries, and a        none
//	                      connection flood's spans and end
//
// A connection:
//
//	Call                  Why                                   Documented failures
//	crypto/rand.Text      the connection ID                     none
//	RemoteAddr            the source field                      none
//	context.WithDeadline  the hard deadline, which Stop's       none
//	                      cancel also ends
//	telnet.Negotiate      negotiation                           ErrCallerClosed,
//	                                                            ErrConnectionFailed,
//	                                                            ErrDeadlineEnded
//	Write                 the greeting                          an error whenever fewer bytes are
//	                                                            written; os.ErrDeadlineExceeded;
//	                                                            net.ErrClosed; any other
//	CloseWrite            shuts down the sending side           an error
//	SetReadDeadline       the earlier of ClosingWaitSeconds     an error, such as net.ErrClosed
//	                      after the shutdown and the hard
//	                      deadline
//	Read                  the reading and discarding, into a    io.EOF; os.ErrDeadlineExceeded;
//	                      buffer of DiscardBufferSize           net.ErrClosed; any other
//	Close                 the close, by the connection's own    an error
//	                      goroutine only
//
// Stop:
//
//	Call                  Why                                   Documented failures
//	the socket's Close    stops accepting; wakes a waiting      an error; connections already
//	                      Accept                                accepted are not closed
//	sync.WaitGroup.Wait   waits for the loops and connections   none
//	the cancel of each    ends every open connection's context  none
//	connection's context  at once
//
// # Lines for the package
//
//   - While one caller is silent or slow, the listener package shall serve every other connection
//     without waiting on that one.
//   - The listener package shall write to the local log only through the LocalLog that Start was
//     given. [read]
//   - The listener package shall write no event and no key to the local log other than those its
//     constants name.
//   - The listener package shall write no byte a caller sent to the local log.
//   - The listener package shall read a caller's bytes after negotiation only into a buffer of
//     DiscardBufferSize bytes, and keep no copy of them. [read]
//   - The listener package shall write nothing to a connection but what Negotiate writes and the
//     greeting.
//   - The listener package shall write nothing to standard output or standard error. [read]
//   - The listener package shall create no file. [read]
//   - The listener package shall import nothing outside the Go standard library and the telnet
//     package. [read]
//   - The listener package shall let Stop be called from any goroutine while Start's accept loops
//     and connections run.
package listener

import (
	"context"
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
	// FloodWindowSeconds is a count line's span, and the quiet that ends a connection flood.
	FloodWindowSeconds = 10
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

// The local log's events this package writes.
const (
	EventAccepted             = "accepted"
	EventNegotiated           = "negotiated"
	EventClosed               = "closed"
	EventRefused              = "refused"
	EventConnectionFlood      = "connection_flood"
	EventConnectionFloodEnded = "connection_flood_ended"
	EventAcceptFailed         = "accept_failed"
	EventAcceptResumed        = "accept_resumed"
)

// Their keys.
const (
	KeySource     = "source"     // the caller's address and port, as the operating system reports
	KeyConnection = "connection" // the connection ID
	KeyResult     = "result"     // how negotiation ended
	KeyHow        = "how"        // how the connection closed
	KeyCount      = "count"      // refusals in one FloodWindowSeconds span
	KeyListener   = "listener"   // the listening socket's address and port
	KeyError      = "error"      // the operating system's error, never caller bytes
)

// The values of result.
const (
	ResultAnswered = "answered"  // the caller answered both requests
	ResultTimedOut = "timed_out" // 3 seconds after the opening requests came first
)

// The values of how, by precedence when two land together: stopped, then deadline, then failed
// and hung_up.
const (
	HowCallerClosed = "caller_closed" // after the greeting, the caller closed its side
	HowTimedOut     = "timed_out"     // ClosingWaitSeconds after the shutdown, it had not
	HowHungUp       = "hung_up"       // the caller closed its side during negotiation
	HowFailed       = "failed"        // a read, a write or the shutdown failed, a reset included
	HowDeadline     = "deadline"      // HardDeadlineSeconds from accept passed
	HowStopped      = "stopped"       // Stop closed it at once; Stop counts these
)

// LogField is one field of a local log line: a key from the constants above, and the engine's
// own value.
type LogField struct {
	Key   string
	Value string
}

// LocalLog is the local log as this package needs it; the Service implements it. Declared here,
// where it is used.
type LocalLog interface {
	// Write is how every line leaves this package: the Service owns the format and standard
	// output, and this package only names the event and its fields. It is called from every
	// connection's own goroutine at once. It returns nothing: a broken standard output is the
	// Service's to handle.
	Write(event string, fields ...LogField)
}

var (
	// ErrNoListeners means Start was given no listening socket, or one that is nil.
	ErrNoListeners = errors.New("listener: no listening socket, or a nil one")
	// ErrNoLocalLog means Start was given no local log.
	ErrNoLocalLog = errors.New("listener: no local log")
)

// Listener is one run's accepting: its listening sockets, its cap and its connections. A Listener
// not made by Start does nothing, and Stop on it returns 0.
type Listener struct {
	state listenerState
}

// Start is the one call that puts the engine's listening sockets to work: the operating system's
// TCP sockets, which the Service opened, so that each accepted connection is a *net.TCPConn whose
// sending side can be shut down on its own. It starts one accept loop per listening socket and
// returns at once; each loop runs until Stop closes its socket.
//
// Each accepted connection is served on its own goroutine. Over the cap, it is closed at once
// without a write, and counted for the connection flood lines, with no accepted or closed line.
// Otherwise it is given a connection ID, 26 random characters, and the accepted line; then, within
// HardDeadlineSeconds from accept, Negotiate, the negotiated line when it returns an outcome, the
// greeting, the shutdown of the sending side, reading into a fixed buffer of DiscardBufferSize and
// discarding until the caller closes or ClosingWaitSeconds pass (or the hard deadline, if
// earlier), the close, and the closed line with how it closed.
//
// A connection counts toward ConnectionCap from the moment Accept returns it until its close
// returns. A connection flood starts at a refusal with none in the FloodWindowSeconds before it,
// with the refused line; each FloodWindowSeconds from its start, a connection_flood line counts
// the refusals in that span, the first included; it ends FloodWindowSeconds after its last
// refusal, with the connection_flood_ended line; when that falls on a span's end, the count line
// comes first.
//
// After an Accept failure, other than its socket being closed, the loop pauses, from
// AcceptPauseFirstMilliseconds doubling to AcceptPauseMostMilliseconds, and tries again; an Accept
// that works sets the pause back to the first. The first failure of a run writes accept_failed
// with the listener and error fields, and the next Accept that works writes accept_resumed with
// the listener field.
//
// It refuses before it accepts anything, and leaves nothing running. Results: ErrNoListeners,
// ErrNoLocalLog.
//
// Accepting:
//
//   - If Listeners is empty or holds a nil listening socket, then Start shall return
//     ErrNoListeners, whatever LocalLog is.
//   - If LocalLog is nil and Listeners holds at least one listening socket and no nil one, then
//     Start shall return ErrNoLocalLog.
//   - If Start returns an error, then Start shall leave every listening socket open, accept on
//     none, and write nothing to the local log.
//   - If Start returns an error, then Start shall leave no goroutine of its own running. [read]
//   - When it is given at least one listening socket, no nil one, and a LocalLog, Start shall
//     return a Listener and no error without waiting for a caller.
//   - After it returns a Listener, Start shall accept callers on every listening socket it was
//     given until Stop closes that socket.
//   - While Accept on one listening socket is waiting or pausing, Start shall accept on every other
//     listening socket without waiting on that one.
//   - If Accept fails because Stop closed its listening socket, then Start shall end that socket's
//     accept loop and write nothing to the local log.
//   - If Stop closes a listening socket while its accept loop is pausing, then Start shall end that
//     accept loop without finishing the pause.
//   - If Accept fails for any other reason, then Start shall pause AcceptPauseFirstMilliseconds
//     before the next Accept on that listening socket, and double the pause after each further
//     failure on it, up to AcceptPauseMostMilliseconds.
//   - When Accept succeeds on a listening socket, Start shall set that socket's pause back to
//     AcceptPauseFirstMilliseconds.
//   - When Accept fails on a listening socket for a reason other than Stop, and the Accept before
//     it on that socket did not fail, Start shall write one accept_failed line with the listener
//     field and the error field.
//   - While Accept on a listening socket keeps failing, Start shall write no further accept_failed
//     line for that socket.
//   - When Accept succeeds on a listening socket whose last Accept failed, Start shall write one
//     accept_resumed line with the listener field.
//   - Start shall give the listener field the listening socket's address and port as the operating
//     system reports them, and the error field the text of the operating system's error.
//   - Start shall return no error other than ErrNoListeners and ErrNoLocalLog. [read]
//
// A connection:
//
//   - When Accept returns a connection while fewer than ConnectionCap connections are open, Start
//     shall give that connection a connection ID from crypto/rand.Text.
//   - Start shall give no two connections the same connection ID, and give every line of one
//     connection that connection's ID.
//   - When it has given a connection its ID, Start shall write one accepted line with the source
//     field and the connection field.
//   - Start shall give the source field the caller's address and port as the operating system
//     reports them.
//   - Start shall give every connection a hard deadline HardDeadlineSeconds after Accept returned
//     it, and pass that deadline to Negotiate as the context's deadline.
//   - When it has written the accepted line, Start shall call Negotiate on the connection before it
//     writes anything to the connection.
//   - When Negotiate returns an outcome, Start shall write one negotiated line with the connection
//     field, and the result field answered for Answered or timed_out for TimedOut.
//   - When Negotiate returns an error, Start shall write no negotiated line.
//   - When Negotiate returns an outcome, Start shall write the greeting to the connection, whatever
//     the outcome.
//   - When the greeting is written in full, Start shall shut down the connection's sending side.
//   - After it has shut down the sending side, Start shall read from the connection and discard
//     what it reads until the caller closes its side, ClosingWaitSeconds pass after the shutdown,
//     or the hard deadline passes, whichever comes first.
//   - When the reading after the shutdown ends, Start shall close the connection.
//   - When it closes a connection, Start shall write one closed line with the connection field and
//     the how field.
//   - Start shall write the accepted, negotiated and closed lines of one connection in that order,
//     each at most once, and no line for that connection after the closed line.
//   - Start shall serve each connection on a goroutine of its own, one that Stop waits for. [read]
//
// Closing a connection:
//
//   - If Negotiate returns ErrCallerClosed, then Start shall close the connection without writing
//     to it, and give how hung_up.
//   - If Negotiate returns ErrConnectionFailed, then Start shall close the connection without
//     writing to it, and give how failed.
//   - If Negotiate returns ErrDeadlineEnded wrapping context.DeadlineExceeded, then Start shall
//     close the connection without writing to it, and give how deadline.
//   - If Negotiate returns ErrDeadlineEnded wrapping context.Canceled, then Start shall close the
//     connection without writing to it, and give how stopped.
//   - If writing the greeting fails, then Start shall close the connection without shutting down
//     its sending side, and give how failed.
//   - If shutting down the sending side fails, then Start shall close the connection without
//     reading from it, and give how failed.
//   - If a read after the shutdown returns end of file, then Start shall close the connection and
//     give how caller_closed.
//   - If ClosingWaitSeconds pass after the shutdown while the caller has not closed its side,
//     before the hard deadline, then Start shall close the connection and give how timed_out.
//   - If a read after the shutdown fails other than by end of file or a passed deadline, then Start
//     shall close the connection and give how failed.
//   - If the hard deadline passes before the connection is closed, then Start shall close the
//     connection at once, in whatever state it is in, and give how deadline.
//   - If the hard deadline has passed when a read, a write or the shutdown fails, then Start shall
//     give how deadline, whatever the failure.
//   - If Stop has ended the connection's context when a read, a write or the shutdown fails, then
//     Start shall give how stopped, whatever the failure.
//   - If Stop ends the connection's context at the moment its hard deadline passes, then Start
//     shall give how stopped. [read]
//   - If the caller drops the connection before Start closes it, then Start shall close its end of
//     the connection and write nothing more to it.
//   - If Close fails, then Start shall still write the closed line with the how its cause gave, and
//     count the connection as closed.
//   - If any failure not named above occurs on a connection, then Start shall close that
//     connection, give how failed, and leave nothing of that connection's behind.
//
// The cap and connection floods:
//
//   - While ConnectionCap connections are open, Start shall close each connection Accept returns at
//     once, without reading from it or writing to it.
//   - Start shall write no accepted, negotiated or closed line for a connection it refuses over the
//     cap.
//   - Start shall count a connection as open from the moment Accept returns it until its Close
//     returns, and shall not count a connection it refuses over the cap.
//   - Start shall apply one ConnectionCap across every listening socket it was given.
//   - When Start refuses a connection with no refusal in the FloodWindowSeconds before it, Start
//     shall start a connection flood and write one refused line with the source field of that
//     connection.
//   - While a connection flood lasts, Start shall write no refused line after its first.
//   - While a connection flood lasts, Start shall write one connection_flood line each
//     FloodWindowSeconds from the flood's start, with the count field set to the number of
//     connections refused in the FloodWindowSeconds that end at that line, the first refusal
//     included.
//   - When FloodWindowSeconds pass with no refusal, Start shall end the connection flood and write
//     one connection_flood_ended line.
//   - When a connection flood's end falls at the end of a count span, Start shall write that span's
//     connection_flood line before the connection_flood_ended line.
//   - Start shall count every connection it refuses over the cap in exactly one connection_flood
//     line.
//   - While no connection flood lasts, Start shall write no connection_flood or
//     connection_flood_ended line.
func Start(listeners []*net.TCPListener, localLog LocalLog) (*Listener, error) {
	return start(listeners, localLog)
}

// Stop is the connection side of a stop, one call for both a drain and a forced stop. It closes
// every listening socket, so nothing more is accepted, then waits until every open connection has
// closed or the context ends; a context with no deadline that is never cancelled waits for every
// connection, each bounded by its hard deadline. If the context ends first, it closes every open
// connection at once and returns how many it closed; else it returns 0. A connection flood still
// running gets its last count, if any refusal came since the last count line, and its end line.
// On return, nothing of this package's is running. A second or later call, also while the first
// waits, does nothing and returns 0. It never fails.
//
//   - When it is first called on a Listener that Start returned, Stop shall close every listening
//     socket Start was given, so that no further connection is accepted.
//   - When the listening sockets are closed, Stop shall wait until every open connection has closed
//     or its context ends, whichever comes first.
//   - If every open connection closes before its context ends, then Stop shall return 0.
//   - If its context ends while connections are open, then Stop shall end every open connection's
//     context at once, wait until each has closed, and return how many it closed this way.
//   - If its context has already ended when it is called, then Stop shall close the listening
//     sockets, end every open connection's context at once, and return how many it closed this way.
//   - If its context has no deadline and is never cancelled, then Stop shall wait until every open
//     connection has closed, and return 0.
//   - If a connection flood lasts when every accept loop has ended, then Stop shall write a last
//     connection_flood line, if any connection was refused since that flood's last count line, and
//     then the connection_flood_ended line.
//   - When it returns, Stop shall have written the closed line of every connection Start accepted
//     under the cap.
//   - When it returns, Stop shall leave no goroutine of the Listener's running: no accept loop, no
//     connection and no connection flood timer. [read]
//   - If Stop is called a second or later time, also while the first call waits, then Stop shall do
//     nothing and return 0 at once.
//   - If Stop is called on a Listener that Start did not return, then Stop shall do nothing and
//     return 0.
//   - If any failure not named above occurs, then Stop shall still close every connection and
//     return how many it closed at once.
func (listener *Listener) Stop(ctx context.Context) int {
	return listener.stop(ctx)
}
