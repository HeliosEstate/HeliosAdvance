// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package telnet is the Telnet kind of connection: it negotiates Telnet options over one accepted
// connection, and then carries the caller's characters for the session as the Line.
//
// During negotiation it owns the opening requests, WILL ECHO and WILL SGA; reading what the caller
// sends through a fixed buffer; the Q-method state of ECHO and SGA on the engine's side (RFC 1143);
// the replies, refusing every other Telnet option, at most one reply per option request;
// discarding every other byte; and ending negotiation when the caller has answered both requests or
// 3 seconds pass, saying which. After it, the Line owns the Telnet side of the textio package's
// Chars: a receive buffer of the caller's bytes, read in stream order, each option request
// answered by the same rules and tables and every other Telnet command discarded; a send buffer
// written with the data byte 255 doubled, which also carries those answers and what negotiation
// still owed the caller; and whether the board echoes, which is whether the caller has agreed to
// ECHO as of the byte just read. It writes nothing to the local log.
//
// It does not own accepting, the cap of 100, the ceiling on a whole call, shutting down the sending
// side, the closing wait or closing: the Listener owns those. It does not own reading a line,
// editing it or deciding what to echo, which the textio package owns, nor what the call says and
// asks, which the session owns; it declares nothing of either package's and imports nothing of
// them. The command line, running as root, stop signals, stopping and the local log belong to the
// program. Later layers own any Telnet option other than ECHO and SGA beyond refusing it.
//
// It has no files.
//
// # Untrusted input
//
// Every byte the caller sends crosses the trust boundary at the network listener. During
// negotiation Negotiate reads it and hands it to Receive; after it, the Line reads it and hands it
// to Strip, one byte at a time. Receive and Strip are the fuzz targets. Receive, on every run: it
// never crashes; one call's replies are never longer than its input plus the 2 bytes a split
// request carries in, and all the calls' replies together never longer than all their input;
// every reply is a well-formed 3-byte WILL, WONT or DONT and nothing else; the same bytes split
// into chunks any other way give the same replies and end at the same byte; and once ended it
// stays ended and nothing changes. Strip, on every run, after Receive is fed the bytes one at a
// time up to a point the fuzzer picks, stopping early if it returns true, and Strip the rest one
// at a time: it never crashes; it calls data exactly the bytes that are neither part of a
// command nor inside a subnegotiation, and the second IAC of each IAC IAC outside one; one call
// appends at most one reply; the replies of Receive's calls and Strip's together are never longer
// than all their input, and well-formed; and they are the same as when Strip takes over at the
// first byte instead.
//
// # Oracles
//
// Reading and replies: RFC 854's command list and RFC 1143 section 7's state table as test
// vectors, one test row per entry, and the fuzz checks above. Negotiate over a socket: QA's own
// scripted Telnet client, written from RFC 854 and RFC 1143 before and apart from this package's
// code, on real loopback sockets, without this package's constants. Its callers answer yes, answer
// no, stay silent, ask for other options, never read, hang up halfway, break the connection, send
// a subnegotiation that never ends, and send requests a byte at a time. The Line over a socket: the
// same client typing after negotiation, with commands, IAC IAC and option requests among its
// characters, ahead of the prompt, and across negotiation's end. Tests run on Linux x86-64,
// Linux ARM64 and Windows x86-64, as an ordinary user with no admin, root or container, over
// loopback on a port the operating system picks. It uses the Go standard library only.
//
// # What it needs from its callers
//
// A connection with read and write deadlines. For Open and the Line, a connection that keeps TCP
// urgent data in line (SO_OOBINLINE), as RFC 6093 section 6 requires of Telnet: without it a
// Synch's DM byte leaves the stream and the lone IAC before it would swallow the caller's next
// character. A context carrying the call's ceiling, cancelled by a stop. One Negotiate or one Open
// per connection, never both, from that connection's own goroutine, before anything else is
// written to it. After either returns an error, the Listener closes the connection without writing
// to it. One goroutine per Negotiation and per Line: neither is safe
// for use from two at once.
//
// # The wire format
//
// RFC 854 frames the stream; every value is one byte, so there is no byte order. An option
// request is three bytes:
//
//	Offset  Length  Value
//	0       1       255, IAC
//	1       1       the verb: 251 WILL, 252 WONT, 253 DO, 254 DONT
//	2       1       the Telnet option's code: 1 ECHO (RFC 857), 3 SGA (RFC 858)
//
// The opening requests are the six bytes 255 251 1 255 251 3: IAC WILL ECHO, then IAC WILL SGA.
// The commands Receive reads by name are IAC 255, DONT 254, DO 253, WONT 252, WILL 251, SB 250
// and SE 240; a subnegotiation runs from IAC SB to IAC SE (RFC 855). The tables on Receive give
// how every byte is read and answered.
//
// # Calls
//
// New and Receive make no call that can fail. Negotiate's calls, the same on Linux and
// Windows, each read with go doc on Go 1.27.1:
//
//	Call                   Why                                        Documented failures
//	context.AfterFunc      wakes a waiting read or write when the     none
//	                       context ends, by a deadline in the past
//	SetReadDeadline,       the earlier of 3 seconds after the         an error, such as
//	SetWriteDeadline       opening write and the context's deadline;  net.ErrClosed on a
//	                       at return, the context's deadline          closed connection
//	Write                  the opening requests and the replies       an error whenever fewer
//	                                                                  bytes are written;
//	                                                                  os.ErrDeadlineExceeded;
//	                                                                  net.ErrClosed; any other
//	Read                   the caller's bytes, into the fixed buffer  bytes and an error from
//	                                                                  one call, the bytes to be
//	                                                                  handled first; io.EOF;
//	                                                                  os.ErrDeadlineExceeded;
//	                                                                  net.ErrClosed; any other
//	time.Now               the start of the 3 seconds, and which      none
//	                       deadline passed
//
// # Lines for the package
//
//   - The telnet package shall send the caller no option request other than WILL ECHO, WILL SGA
//     and the replies the tables on Receive give.
//   - The telnet package shall keep a state for no Telnet option other than ECHO and SGA. [read]
//   - The telnet package shall write nothing to the local log. [read]
//   - The telnet package shall import nothing outside the Go standard library. [read]
package telnet

import (
	"context"
	"errors"
	"time"
)

// The commands of RFC 854 that the tables on Receive name.
const (
	TelnetIAC  = 255 // starts every command; IAC IAC is the data byte 255
	TelnetDONT = 254 // asks the other side to stop an option, or refuses its offer
	TelnetDO   = 253 // asks the other side to start an option, or accepts its offer
	TelnetWONT = 252 // refuses to start an option, or stops one
	TelnetWILL = 251 // offers an option, or accepts the other side's request
	TelnetSB   = 250 // starts a subnegotiation, which runs to IAC SE
	TelnetSE   = 240 // ends a subnegotiation
)

// The two Telnet options this layer offers.
const (
	OptionEcho            = 1 // ECHO, RFC 857
	OptionSuppressGoAhead = 3 // SUPPRESS-GO-AHEAD, SGA, RFC 858
)

const (
	// ReadBufferSize is the fixed buffer Negotiate reads into: nothing the caller sends grows it.
	ReadBufferSize = 256
	// ReplyBufferSize holds every reply one read can yield. Every reply is 3 bytes and answers a
	// request of 3, but a request split across reads can carry IAC and a verb in from the read
	// before, so a read of N bytes yields at most N + 2 bytes of replies. Over the whole
	// connection, replies never outgrow input.
	ReplyBufferSize = ReadBufferSize + 2
	// NegotiationSeconds is counted from the opening write. Fixed in this layer; a setting once
	// configuration exists.
	NegotiationSeconds = 3
)

// Outcome is how negotiation ended when nothing failed. The call goes on after either.
type Outcome int

const (
	// Answered means the caller answered both requests, each with DO or DONT.
	Answered Outcome = iota + 1
	// TimedOut means 3 seconds after the opening write came first, with a read or a write
	// waiting.
	TimedOut
)

// Conn is the connection as Negotiate needs it; the Listener's accepted net.Conn satisfies it.
// Declared here, where it is used.
type Conn interface {
	// Read returns end of file, a passed deadline and any other failure as its error.
	Read(buffer []byte) (int, error)
	// Write may have written part of buffer when it fails on a passed deadline.
	Write(buffer []byte) (int, error)
	// SetReadDeadline wakes a read that is waiting when the deadline has passed; zero clears it.
	SetReadDeadline(deadline time.Time) error
	// SetWriteDeadline wakes a write that is waiting when the deadline has passed; zero clears
	// it.
	SetWriteDeadline(deadline time.Time) error
}

var (
	// ErrCallerClosed means the caller closed its side in order before negotiation ended: a read
	// met end of file. A half-close cannot be told from a hang-up, so the Listener writes nothing
	// after it.
	ErrCallerClosed = errors.New("telnet: the caller closed the connection")
	// ErrConnectionFailed means any other read or write failure on the connection, a reset
	// included.
	ErrConnectionFailed = errors.New("telnet: the connection failed")
	// ErrDeadlineEnded means Negotiate's context ended first: the call's ceiling or a forced stop,
	// also when it had ended before anything was written. It is returned wrapping
	// context.DeadlineExceeded or context.Canceled, so errors.Is matches it and the one wrapped.
	ErrDeadlineEnded = errors.New("telnet: the deadline ended first")
)

// Negotiation is the negotiation of one connection: bytes in, replies out. It has no connection,
// clock or goroutine of its own, so it is tested and fuzzed without a socket. A Negotiation not
// made by New behaves as one New returned; only New hands out the opening requests.
type Negotiation struct {
	state negotiationState
}

// New makes the requests and the state together, since the Q method moves an option to WANTYES
// when its request is sent; a second opening, or a Receive before it, cannot happen. It returns a
// negotiation with ECHO and SGA in WANTYES, and the opening requests to write.
//
//   - New shall return the opening requests as the six bytes IAC WILL ECHO IAC WILL SGA, in that
//     order.
//   - New shall return a negotiation with ECHO and SGA both in the WANTYES state.
//   - New shall return a negotiation that shares no state with any other negotiation.
//   - New shall not fail. [read]
//   - A Negotiation not made by New shall behave as one New returned, with ECHO and SGA both in
//     the WANTYES state.
func New() (*Negotiation, [6]byte) {
	return newNegotiation()
}

// Receive is the one place the caller's bytes are read. It appends to replies the reply to each
// option request in input, and returns true once negotiation has ended, at the byte that
// completes the caller's second answer; bytes after that byte, in this call or a later one, get
// no reply and change nothing. It keeps where it stopped between calls (after IAC, after a verb,
// inside a subnegotiation, after IAC inside one), a few fixed values. It never fails: every byte
// sequence has a reading.
//
// How input is read (RFC 854, RFC 855):
//
//	IAC, then WILL, WONT, DO or DONT, then one byte   an option request
//	IAC IAC                                           data byte 255, discarded
//	IAC SB, to IAC SE                                 a subnegotiation, discarded whole,
//	                                                  IAC IAC inside it a data byte
//	IAC, then any other byte                          a two-byte command, discarded;
//	                                                  AYT gets no reply
//	any other byte                                    data, discarded
//
// ECHO and SGA on the engine's side (RFC 1143 section 7, us and him swapped):
//
//	State     Caller sends DO              Caller sends DONT
//	WANTYES   YES, no reply; answered      NO, no reply; answered
//	YES       ignored                      NO, reply WONT
//	NO        YES, reply WILL              ignored
//
// Every other option request, with no state kept:
//
//	WILL, any Telnet option, ECHO and SGA too         reply DONT
//	WONT, any Telnet option                           no reply
//	DO, a Telnet option other than ECHO and SGA       reply WONT
//	DONT, a Telnet option other than ECHO and SGA     no reply
//
// Lines:
//
//   - When input holds IAC, then WILL, WONT, DO or DONT, then one more byte, Receive shall read
//     those three bytes as one option request.
//   - When input holds IAC IAC outside a subnegotiation, Receive shall discard both bytes without
//     reply.
//   - When input holds IAC SB, Receive shall discard every byte up to and including the next IAC
//     SE without reply.
//   - While it is inside a subnegotiation, Receive shall read IAC IAC as one data byte, so that
//     IAC IAC SE does not end the subnegotiation.
//   - When input holds IAC and then a byte other than WILL, WONT, DO, DONT, SB or IAC, Receive
//     shall discard both bytes without reply.
//   - When input holds a byte that is not part of a sequence starting with IAC, Receive shall
//     discard it without reply.
//   - When a sequence is split across calls, Receive shall reply to it and end negotiation as it
//     would had the sequence come in one call.
//   - When the byte that completes the caller's second answer arrives, Receive shall return true.
//   - After the byte that completes the caller's second answer, Receive shall append no reply and
//     change no state, for the rest of that input and every later call.
//   - After it has returned true, Receive shall return true on every later call.
//   - Receive shall append its replies after the bytes already in replies and leave those bytes
//     unchanged.
//   - Receive shall append at most one reply per option request.
//   - Receive shall append at most the length of input plus 2 bytes to replies in one call.
//   - Receive shall append, over all its calls on one negotiation, no more bytes than all their
//     input held.
//   - If input is empty, then Receive shall append nothing and return what it returned on the
//     call before, or false on the first call.
//   - Receive shall return for every input without failing or panicking.
//   - While negotiation lasts, when the caller sends DO for ECHO or SGA while that Telnet option
//     is in WANTYES, Receive shall move it to YES and append no reply.
//   - While negotiation lasts, when the caller sends DONT for ECHO or SGA while that Telnet
//     option is in WANTYES, Receive shall move it to NO and append no reply.
//   - While negotiation lasts, when the caller sends DO for ECHO or SGA while that Telnet option
//     is in YES, Receive shall append no reply and leave its state unchanged.
//   - While negotiation lasts, when the caller sends DONT for ECHO or SGA while that Telnet
//     option is in YES, Receive shall move it to NO and append IAC WONT and that Telnet option.
//   - While negotiation lasts, when the caller sends DO for ECHO or SGA while that Telnet option
//     is in NO, Receive shall move it to YES and append IAC WILL and that Telnet option.
//   - While negotiation lasts, when the caller sends DONT for ECHO or SGA while that Telnet
//     option is in NO, Receive shall append no reply and leave its state unchanged.
//   - While negotiation lasts, when the caller sends WILL for any Telnet option, Receive shall
//     append IAC DONT and that Telnet option.
//   - While negotiation lasts, when the caller sends WONT for any Telnet option, Receive shall
//     append no reply.
//   - While negotiation lasts, when the caller sends DO for a Telnet option other than ECHO and
//     SGA, Receive shall append IAC WONT and that Telnet option.
//   - While negotiation lasts, when the caller sends DONT for a Telnet option other than ECHO and
//     SGA, Receive shall append no reply.
func (negotiation *Negotiation) Receive(input, replies []byte) ([]byte, bool) {
	return negotiation.receive(input, replies)
}

// Negotiate negotiates over one connection; the Listener calls Open, which negotiates as Negotiate
// does and goes on as the Line. It writes the opening requests, then reads into a fixed buffer of
// ReadBufferSize, hands the bytes to Receive and writes its replies from a fixed buffer of
// ReplyBufferSize, until Receive reports the end or NegotiationSeconds after the opening write.
// When two things happen at once, the context ending wins, then any read or write failure, whose
// replies are not written; Answered only when nothing failed. A read or write that gives up on a
// passed deadline is told apart by the clock, not by whether the context reports it has ended:
// ErrDeadlineEnded if the context's deadline had passed by then, else TimedOut. On return, with an
// outcome or an error, it leaves nothing behind: the connection's read and write deadlines at the
// context's deadline, cleared if it has none, and nothing of its own running. Results:
// ErrCallerClosed, ErrConnectionFailed, ErrDeadlineEnded.
//
//   - If the context has ended when Negotiate is called, then Negotiate shall return
//     ErrDeadlineEnded without writing to the connection.
//   - When it is called, Negotiate shall write the opening requests New returns before it reads
//     from the connection.
//   - Negotiate shall read into a buffer of ReadBufferSize bytes and write its replies from a
//     buffer of ReplyBufferSize bytes, and keep no other copy of the caller's bytes. [read]
//   - Negotiate shall hand the bytes a read returns to Receive before it looks at that read's
//     error. [read]
//   - When Receive appends replies and returns false, Negotiate shall write those replies before
//     its next read.
//   - When Receive returns true, Negotiate shall write that call's replies and, if neither that
//     read nor that write returned an error, return Answered with no error.
//   - If NegotiationSeconds pass after Negotiate begins the opening write, before the context's
//     deadline, while a read or a write is waiting, then Negotiate shall return TimedOut with no
//     error.
//   - If the context's deadline passes at or before NegotiationSeconds after the opening write
//     began, while a read or a write is waiting, then Negotiate shall return ErrDeadlineEnded.
//   - If the context is cancelled while a read or a write is waiting, then Negotiate shall stop
//     waiting and return ErrDeadlineEnded.
//   - Negotiate shall return ErrDeadlineEnded wrapping context.DeadlineExceeded when the
//     context's deadline passed, and context.Canceled when it was cancelled, so that errors.Is
//     matches both.
//   - If the context has ended when a read or a write fails, then Negotiate shall return
//     ErrDeadlineEnded, whatever the failure.
//   - If a read returns end of file, then Negotiate shall return ErrCallerClosed without writing
//     that read's replies.
//   - If a read returns bytes together with an error, then Negotiate shall write none of that
//     read's replies and return the result that error gives. [read]
//   - If a read or a write fails other than by end of file or a passed deadline, then Negotiate
//     shall return ErrConnectionFailed.
//   - Negotiate shall write nothing to the connection but the opening requests and the replies
//     Receive appends.
//   - When it returns, Negotiate shall leave the connection's read and write deadlines at the
//     context's deadline.
//   - If the context has no deadline, then Negotiate shall leave the connection's read and write
//     deadlines cleared when it returns. [read]
//   - When it returns, Negotiate shall leave no goroutine of its own running. [read]
//   - If any failure not named above occurs, then Negotiate shall return ErrConnectionFailed and
//     leave nothing behind.
func Negotiate(ctx context.Context, connection Conn) (Outcome, error) {
	return negotiate(ctx, connection)
}

// Strip reads one byte the caller sent after negotiation, with no connection, clock or goroutine,
// and returns true when that byte is a data byte, the character itself; false when it is part of
// a Telnet command. It answers each option request into replies by the same rules and tables as
// Receive (RFC 854, RFC 1143), keeping the same option states, and discards every other Telnet
// command. It goes on from where Receive stopped, so a command that negotiation's end split is
// read whole; from its first call, Receive appends nothing more. The option rules and tables are
// in one place, Receive's, used by both, so a later layer adds a Telnet option there alone. It
// never fails. One byte at a time, it cannot read a byte past the data byte it returns.
//
// How the bytes are read after negotiation (RFC 854, RFC 855):
//
//	IAC, then WILL, WONT, DO or DONT, then one byte   an option request, answered by the tables
//	                                                  on Receive, as while negotiation lasts
//	IAC IAC, outside a subnegotiation                 the second IAC is the data byte 255
//	IAC SB, to IAC SE                                 a subnegotiation, discarded whole;
//	                                                  IAC IAC inside it does not end it
//	IAC, then any other byte                          a two-byte command, discarded
//	any other byte                                    data
//
// Lines:
//
//   - Strip shall return true for each data byte and false for each byte of a Telnet command.
//   - When the bytes hold IAC IAC outside a subnegotiation, Strip shall return false for the
//     first IAC and true for the second, the data byte 255.
//   - When a byte completes an option request, Strip shall answer it into replies and change the
//     option's state exactly as Receive's lines do while negotiation lasts.
//   - When the bytes hold IAC and then a byte other than WILL, WONT, DO, DONT, SB or IAC, or a
//     subnegotiation, Strip shall discard them without reply.
//   - When a sequence is split across negotiation's end, Strip shall read it as it would had the
//     sequence come after it whole.
//   - Strip shall append its reply after the bytes already in replies, and leave those unchanged.
//   - Strip shall append at most one reply, 3 bytes, in one call.
//   - Strip shall append to replies, over all its calls and Receive's on one negotiation, no more
//     bytes than all their input held.
//   - After Strip's first call, Receive shall append no reply and change no state on that
//     negotiation, for every later call.
//   - Strip shall return for every byte without failing or panicking.
func (negotiation *Negotiation) Strip(character byte, replies []byte) ([]byte, bool) {
	return negotiation.strip(character, replies)
}

// SendBufferSize is the Line's fixed send buffer. When it is full, the call adding to it writes
// it out first, so nothing the caller does grows it.
const SendBufferSize = 1024

// Line is a caller's Telnet connection once negotiation is over: the Telnet side of the textio
// package's Chars. It keeps a receive buffer of the caller's bytes not yet read, a send buffer of
// SendBufferSize, and the negotiation, whose option states go on changing as the caller asks.
// It reads in stream order, so an option request is answered, and ECHO changes, exactly where it
// falls among the caller's characters. A Line not made by Open, or nil, fails every call with
// ErrConnectionFailed, and its Echoes returns false. One goroutine per Line.
//
// Its calls report as the textio package's table has it: os.ErrDeadlineExceeded when the
// deadline given passed first; io.EOF when the caller closed its side; the context's error,
// wrapped, when the context ended first; ErrConnectionFailed, wrapping the cause, for any other
// failure. When two happen at once, the context ending wins, then a failure, then a passed
// deadline. Each is judged by the clock: a context whose deadline has passed has ended, with
// context.DeadlineExceeded, whether or not it reports it yet. A context ending wakes a waiting
// call at once. A call sets the connection's deadline itself before each read or write, the
// earlier of its own deadline and the context's, or none when neither has one, and leaves
// nothing of its own running when it returns.
type Line struct {
	state lineState
}

// Open negotiates exactly as Negotiate does and, when negotiation ends with an outcome, returns a
// Line over the same connection that carries on where negotiation stopped. On an error it
// returns a nil Line and Negotiate's error, which also matches the standard library's cause
// through errors.Is: io.EOF for ErrCallerClosed, the context's error for ErrDeadlineEnded.
//
// The bytes negotiation read, up to the byte at which Receive returned true or all of them when
// Receive never did, are negotiation's: discarded as data, their option requests answered. Every
// byte after them is the Line's to read, in order: the engine cannot tell when an unread byte was
// sent, so typing ahead works however negotiation ended.
//
//   - Open shall negotiate as Negotiate does, and return the Outcome, or an error matching
//     Negotiate's through errors.Is.
//   - When Open returns ErrCallerClosed, the error shall also match io.EOF.
//   - When negotiation ends with an outcome, Open shall return a Line that writes first, in order,
//     every byte Negotiate was to write and did not: the rest of a write cut short, and the
//     replies of a read that returned with a passed deadline.
//   - When negotiation ends with an outcome after Receive returned true, Open shall return a Line
//     whose receive buffer holds, unread and in order, every byte negotiation's last read
//     returned after the byte at which Receive returned true, and no other byte.
//   - When negotiation ends TimedOut before Receive returned true, Open shall return a Line whose
//     receive buffer is empty.
//   - When it returns an error, Open shall return a nil Line.
func Open(ctx context.Context, connection Conn) (*Line, Outcome, error) {
	return open(ctx, connection)
}

// SendChar queues one data byte for the caller. It writes only when the send buffer is full.
//
//   - SendChar shall queue a byte other than 255 as itself, and the data byte 255 as IAC IAC.
//   - If the context has ended when SendChar is called, then SendChar shall queue nothing and
//     return the context's error, wrapped.
//   - When the send buffer has room for the byte, or for both bytes of IAC IAC, SendChar shall
//     queue it without writing and return no error.
//   - When the send buffer has no room for the byte, or for both bytes of IAC IAC, SendChar shall
//     first write it out as Flush does, with Flush's results, and queue nothing unless that write
//     emptied it.
func (line *Line) SendChar(ctx context.Context, character byte) error {
	return line.sendChar(ctx, character)
}

// Flush writes the send buffer out and empties it, waiting no later than the context's deadline.
//
//   - Flush shall write the send buffer's bytes in order, and leave it empty once they are
//     written.
//   - If the context has ended when Flush is called, or ends while it waits, then Flush shall
//     write nothing more and return the context's error, wrapped.
//   - If a write fails otherwise, then Flush shall return ErrConnectionFailed.
//   - If a write is cut short, then Flush shall keep what it did not write at the front of the
//     send buffer, in order, so that each byte is written once.
//   - Flush shall hold the send buffer in SendBufferSize bytes, and keep no other copy. [read]
func (line *Line) Flush(ctx context.Context) error {
	return line.flush(ctx)
}

// RecvChar returns the caller's next data byte. It hands Strip the receive buffer's bytes one at
// a time, queues Strip's replies, and stops at the first data byte, reading nothing after it.
// It writes the send buffer out before it waits for the caller, and when a reply needs room, both
// no later than deadline.
//
//   - RecvChar shall return the caller's data bytes in the order sent, and no byte of a Telnet
//     command.
//   - RecvChar shall read no byte after the data byte it returns.
//   - RecvChar shall queue Strip's replies as they are, unescaped, in order.
//   - Before it hands Strip a byte, RecvChar shall have room for one reply, 3 bytes, writing the
//     send buffer out as Flush does, under deadline, when it has not.
//   - Before it waits for the caller, RecvChar shall write the send buffer out as Flush does,
//     under deadline.
//   - Once deadline has passed, RecvChar shall return os.ErrDeadlineExceeded, even with bytes in
//     the receive buffer.
//   - If the caller closes its side while no data byte is waiting, then RecvChar shall return
//     io.EOF.
//   - If the context has ended when RecvChar is called, or ends while it waits, then RecvChar
//     shall return the context's error, wrapped, and no byte.
//   - If a read or a write fails otherwise, then RecvChar shall return ErrConnectionFailed.
//   - RecvChar shall keep the bytes a read returns before it looks at that read's error.
//   - RecvChar shall read into a buffer of ReadBufferSize bytes and hold at most that many bytes
//     not yet read. [read]
func (line *Line) RecvChar(ctx context.Context, deadline time.Time) (byte, error) {
	return line.recvChar(ctx, deadline)
}

// Echoes is whether the board echoes on this Line now: true while the caller has agreed to ECHO
// as of the last byte RecvChar read; false when it refused, has not answered, or has since asked
// to stop, and echoes for itself (RFC 857).
//
//   - While the caller has agreed to ECHO, Echoes shall return true.
//   - While the caller has not agreed to ECHO, Echoes shall return false.
//   - If the Line was not made by Open, or is nil, then Echoes shall return false.
func (line *Line) Echoes() bool {
	return line.echoes()
}
