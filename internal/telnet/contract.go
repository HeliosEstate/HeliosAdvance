// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package telnet is the Telnet kind of connection: it negotiates Telnet options over one accepted
// connection, and then carries the caller's characters for the session as the Line.
//
// The Line is Telnet's object in the developer's design for Part 3: "There are two listeners, one
// for Telnet and one for SSH. The listeners' job is just to accept the connections. It then hands
// each connection off to a shared execution path as a class. That class defines identical
// primitives that the shared execution uses." Accept makes an accepted connection Telnet's object,
// and the Line offers the identical primitives: SendChar and RecvChar, the page's; Flush and
// Echoes, which the textio package's Chars asks of every kind of connection; and Close, the kind's
// own close.
//
// During negotiation it owns the eight opening requests; reading what the caller sends through a
// fixed buffer; the RFC 1143 state of ECHO, SGA and BINARY on the engine's side, and of SGA,
// BINARY, TTYPE, NAWS, NEW-ENVIRON and TSPEED on the caller's side; the replies, refusing every
// other Telnet option, at most one reply per option request; the SEND for TTYPE, TSPEED and
// NEW-ENVIRON, each at most once; the answers to AYT, AO and IP; discarding every other byte; and
// ending negotiation when the caller has answered all eight requests or 3 seconds pass, saying
// which. After it, the Line owns the Telnet side of the textio package's Chars: a receive buffer of
// the caller's bytes, read in stream order, each option request and command answered by the same
// rules and tables, EC handed on as BS and EL as Ctrl-U; a send buffer written with the data byte
// 255 doubled, which also carries those answers and what negotiation still owed the caller; the
// Synch, IAC DM with DM sent as TCP urgent data; and whether the board echoes, which is whether the
// caller has agreed to ECHO as of the byte just read. On an accepted connection it owns keeping TCP
// urgent data in line and writing it, and, once the call is answered, Telnet's own close: shutting
// down the sending side, and reading and discarding until the caller closes or 3 seconds pass. It
// writes nothing to the local log.
//
// It does not own accepting, the cap of 100, the ceiling on a whole call or closing the
// connection: the listeners and the shared execution path own those. It does not own reading a
// line, editing it or deciding what to echo, which the textio package owns, nor what the call says
// and asks, which the session owns; it declares nothing of either package's and imports nothing of
// them. The command line, running as root, stop signals, stopping and the local log belong to the
// program. Keeping what TTYPE, NAWS, NEW-ENVIRON and TSPEED report belongs to terminal negotiation,
// a later layer: this one reads it inside a subnegotiation and keeps none of it.
//
// It has no files.
//
// # Untrusted input
//
// Every byte the caller sends crosses the trust boundary at the network listener. During
// negotiation Negotiate, or Open as Negotiate does, reads it and hands it to Receive; after it, the
// Line reads it and hands it to Strip, one byte at a time. Receive and Strip are the fuzz targets.
// Receive, on every run: it never crashes; one call's replies are never longer than five times its
// input plus MostReply, and all the calls' replies together never longer than five times all their
// input; every reply is a well-formed 3-byte WILL, WONT, DONT or DO, one of the three SENDs, or
// AYT's answer, and nothing else; each SEND appears at most once over the negotiation; the same
// bytes split into chunks any other way give the same replies, the same Synch requests and end at
// the same byte; and once ended it stays ended and nothing changes. Strip, on every run, after
// Receive is fed the bytes one at a time up to a point the fuzzer picks, stopping early if it
// returns true, and Strip the rest one at a time: it never crashes; it hands on as data exactly the
// bytes that are neither part of a command nor inside a subnegotiation, the second IAC of each IAC
// IAC outside one, and BS for each EC and Ctrl-U for each EL; one call appends at most MostReply
// bytes; the replies of Receive's calls and Strip's together are never longer
// than five times all their input, and well-formed; and they are the same as when Strip takes over
// at the first byte instead. Nothing inside a subnegotiation changes a reply, a state or a byte
// handed on. Once the call is answered, Close reads what the caller still sends into a fixed buffer
// of DiscardBufferSize and discards it unread, for at most ClosingWaitSeconds.
//
// # Oracles
//
// Reading and replies: RFC 854's command list, RFC 1143 section 7's state table on both sides, and
// the SEND formats of RFC 1091, RFC 1079 and RFC 1572, as test vectors, one test row per entry, and
// the fuzz checks above. Negotiate over a socket: QA's own scripted Telnet client, written from RFC
// 854, 856, 1073, 1079, 1091, 1123, 1143 and 1572 before and apart from this package's code, on
// real loopback sockets, without this package's constants. Its callers answer yes, answer no,
// answer some of the eight and not the rest, stay silent, ask for other options, agree, refuse and
// agree again, never read, hang up halfway, break the connection, send subnegotiations that never
// end, run long, hold escape codes or IAC IAC, or come for options never agreed, send NAWS of 0
// and of 65535, send AYT, AO and IP, flood them while never reading, the call still ending at its
// ceiling, send a Synch as urgent data, and send requests a byte at a time. The Line over a
// socket: the same client typing after negotiation, with commands, EC, EL, IAC IAC and option
// requests among its characters, ahead of the prompt, and across negotiation's end. Two Telnet
// clients others wrote, driven through their standard input and output as outside programs,
// never read for their source: the stock Linux telnet client on Linux, and PuTTY's command-line
// client, Plink, on Linux and Windows; each connects, negotiates and reaches the greeting. Tests
// run on Linux x86-64, Linux ARM64 and Windows x86-64, as an ordinary user with no admin, root or
// container, over loopback on a port the operating system picks. QA's scripted client and the
// tests use the Go standard library only.
//
// # What it needs from its callers
//
// A connection with read and write deadlines that also writes urgent data. For Open and the Line
// it makes, a connection that keeps TCP urgent data in line (SO_OOBINLINE), as RFC 6093 section 6
// requires of Telnet: without it a Synch's DM byte leaves the stream and the lone IAC before it
// would swallow the caller's next character; Accept sets it itself. A context carrying the call's
// ceiling, cancelled by a stop. One Negotiate, one Open or one Accept per connection, never two,
// from that connection's own goroutine, before anything else is written to it. After any of them
// returns an error, the shared execution path closes the connection without writing to it, and it
// closes the connection after Close. One goroutine per Negotiation and per Line: neither is safe
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
//	2       1       the Telnet option's code: 0 BINARY (RFC 856), 1 ECHO (RFC 857), 3 SGA
//	                (RFC 858), 24 TTYPE (RFC 1091), 31 NAWS (RFC 1073), 32 TSPEED (RFC 1079),
//	                39 NEW-ENVIRON (RFC 1572)
//
// The opening requests are the 24 bytes IAC WILL ECHO, IAC WILL SGA, IAC WILL BINARY, IAC DO
// BINARY, IAC DO TTYPE, IAC DO NAWS, IAC DO NEW-ENVIRON and IAC DO TSPEED, in that order. The
// SENDs: TTYPE's is IAC SB 24 1 IAC SE; TSPEED's is IAC SB 32 1 IAC SE; NEW-ENVIRON's is IAC SB 39
// 1 0 85 83 69 82 IAC SE, SEND, then VAR, then the name USER. AYT's answer is the 9 bytes CR LF
// "[Yes]" CR LF. The Synch is IAC DM, written with DM as TCP urgent data. The commands Receive and
// Strip read by name are IAC 255, DONT 254, DO 253, WONT 252, WILL 251, SB 250, EL 248, EC 247,
// AYT 246, AO 245, IP 244 and SE 240; a subnegotiation runs from IAC SB to IAC SE (RFC 855). The
// tables on Receive give how every byte is read and answered.
//
// # Calls
//
// New and Receive make no call that can fail. Negotiate's calls, the same on Linux and
// Windows, each read with go doc on Go 1.27.1, but timeup.WakeOnEnd, the engine's own, read
// from the timeup package's contract:
//
//	Call                   Why                                        Documented failures
//	timeup.WakeOnEnd       wakes a waiting read or write when the     none; a failure to set
//	                       context ends, by a deadline in the past    a deadline is dropped
//	SetReadDeadline        the earlier of 3 seconds after the         an error, such as
//	                       opening write and the context's deadline;  net.ErrClosed on a
//	                       at return, the context's deadline          closed connection
//	SetWriteDeadline       the context's deadline, so the 3 seconds   the same
//	                       never cut a write
//	Write                  the opening requests and the replies       an error whenever fewer
//	                                                                  bytes are written;
//	                                                                  os.ErrDeadlineExceeded;
//	                                                                  net.ErrClosed; any other
//	WriteUrgent            the Synch, after the replies before it     the same as Write
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
//   - The telnet package shall send the caller no option request other than the opening
//     requests and the replies the tables on Receive give.
//   - The telnet package shall keep a state for no Telnet option other than ECHO, SGA and BINARY
//     on the engine's side and SGA, BINARY, TTYPE, NAWS, NEW-ENVIRON and TSPEED on the caller's
//     side. [read]
//   - The telnet package shall keep nothing a subnegotiation carries. [read]
//   - The telnet package shall write nothing to the local log. [read]
//   - The telnet package shall judge whether a call's context has run out only with timeup.Ended,
//     take every time a call must stop by from timeup.Limit, and wake a waiting call only with
//     timeup.WakeOnEnd or timeup.Wake, keeping no copy of their rules. [read]
//   - The telnet package shall call each release timeup.WakeOnEnd returns once, before the call
//     that registered it returns. [read]
//   - The telnet package shall import nothing outside the Go standard library, the timeup package
//     and, in its Windows urgent write alone, golang.org/x/sys/windows. [read]
package telnet

import (
	"context"
	"errors"
	"net"
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
	TelnetEL   = 248 // Erase Line: handed on as Ctrl-U
	TelnetEC   = 247 // Erase Character: handed on as BS
	TelnetAYT  = 246 // Are You There: answered with AYTAnswer
	TelnetAO   = 245 // Abort Output: answered with a Synch
	TelnetIP   = 244 // Interrupt Process: answered with a Synch
	TelnetDM   = 242 // Data Mark: the urgent byte of a Synch
	TelnetSE   = 240 // ends a subnegotiation
)

// The Telnet options the tables on Receive accept on one side or both.
const (
	OptionBinary          = 0  // BINARY, RFC 856: eight-bit data in the direction agreed
	OptionEcho            = 1  // ECHO, RFC 857: the board echoes while the caller agrees
	OptionSuppressGoAhead = 3  // SUPPRESS-GO-AHEAD, SGA, RFC 858: character at a time
	OptionTerminalType    = 24 // TTYPE, RFC 1091: the caller's terminal type
	OptionWindowSize      = 31 // NAWS, RFC 1073: the caller's window size, sent unasked
	OptionTerminalSpeed   = 32 // TSPEED, RFC 1079: the caller's terminal speed
	OptionNewEnviron      = 39 // NEW-ENVIRON, RFC 1572: the caller's environment variables
)

// The subnegotiation codes the SENDs use.
const (
	SubnegotiationSend = 1 // SEND, in TTYPE, TSPEED and NEW-ENVIRON
	EnvironVar         = 0 // VAR, before a variable's name in NEW-ENVIRON
)

const (
	// OpeningLength is the length of the opening requests: eight requests of 3 bytes.
	OpeningLength = 24
	// AYTAnswer is written for each AYT: visible evidence that the board is there (RFC 854).
	AYTAnswer = "\r\n[Yes]\r\n"
	// MostReply is the most one byte can append: the last byte of a WILL NEW-ENVIRON after an
	// earlier WONT, answered DO and then NEW-ENVIRON's SEND, 3 and 11 bytes.
	MostReply = 14
	// ReadBufferSize is the fixed buffer Negotiate reads into: nothing the caller sends grows it.
	ReadBufferSize = 256
	// ReplyBufferSize holds every reply one read can yield: at most five times the bytes read,
	// AYT's 9 bytes for 2 and a WILL NEW-ENVIRON's 14 for 3 the most, and MostReply more for a
	// request split across reads, whose first bytes came in the read before.
	ReplyBufferSize = 5*ReadBufferSize + MostReply
	// NegotiationSeconds is counted from the opening write. Fixed in this layer; a setting once
	// configuration exists.
	NegotiationSeconds = 3
)

// Outcome is how negotiation ended when nothing failed. The call goes on after either.
type Outcome int

const (
	// Answered means the caller answered all eight opening requests: each of the engine's WILL
	// with DO or DONT, each of its DO with WILL or WONT.
	Answered Outcome = iota + 1
	// TimedOut means 3 seconds after the opening write came first, with a read waiting, or
	// passed while a write waited.
	TimedOut
)

// Conn is the connection as Negotiate needs it; Accept makes one of an accepted TCP connection.
// Declared here, where it is used.
type Conn interface {
	// Read returns end of file, a passed deadline and any other failure as its error.
	Read(buffer []byte) (int, error)
	// Write may have written part of buffer when it fails on a passed deadline.
	Write(buffer []byte) (int, error)
	// WriteUrgent writes buffer with its last byte as TCP urgent data. Like Write, a passed write
	// deadline wakes it, a deadline set while it waits included, and it may have written part of
	// buffer when it fails.
	WriteUrgent(buffer []byte) (int, error)
	// SetReadDeadline wakes a read that is waiting when the deadline has passed; zero clears it.
	SetReadDeadline(deadline time.Time) error
	// SetWriteDeadline wakes a write that is waiting when the deadline has passed; zero clears
	// it.
	SetWriteDeadline(deadline time.Time) error
}

var (
	// ErrCallerClosed means the caller closed its side in order before negotiation ended: a read
	// met end of file. A half-close cannot be told from a hang-up, so the shared execution path
	// writes nothing after it.
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
// negotiation with the eight requested options in WANTYES, and the opening requests to write.
//
//   - New shall return the opening requests as the 24 bytes IAC WILL ECHO, IAC WILL SGA, IAC WILL
//     BINARY, IAC DO BINARY, IAC DO TTYPE, IAC DO NAWS, IAC DO NEW-ENVIRON and IAC DO TSPEED, in
//     that order.
//   - New shall return a negotiation with ECHO, SGA and BINARY on the engine's side and BINARY,
//     TTYPE, NAWS, NEW-ENVIRON and TSPEED on the caller's side in the WANTYES state, SGA on the
//     caller's side in the NO state, and no SEND sent.
//   - New shall return a negotiation that shares no state with any other negotiation.
//   - New shall not fail. [read]
//   - A Negotiation not made by New shall behave as one New returned.
func New() (*Negotiation, [OpeningLength]byte) {
	return newNegotiation()
}

// Receive is the one place negotiation reads the caller's bytes. It appends to replies the reply
// to each option request and each command in input, and returns true once negotiation has ended,
// at the byte that completes the caller's last answer to the eight opening requests; bytes after
// that byte, in this call or a later one, get no reply and change nothing. It keeps where it
// stopped between calls (after IAC, after a verb, inside a subnegotiation, after IAC inside one),
// a few fixed values, and whether a Synch is owed, which TakeSynch hands out. It never fails:
// every byte sequence has a reading.
//
// How input is read (RFC 854, RFC 855):
//
//	IAC, then WILL, WONT, DO or DONT, then one byte   an option request
//	IAC IAC                                           data byte 255, discarded
//	IAC SB, to IAC SE                                 a subnegotiation, discarded whole,
//	                                                  IAC IAC inside it a data byte
//	IAC AYT                                           append AYTAnswer
//	IAC AO, IAC IP                                    a Synch owed
//	IAC, then any other byte                          a two-byte command, discarded; EC and EL
//	                                                  too, as there is no name yet
//	any other byte                                    data, discarded
//
// ECHO, SGA and BINARY on the engine's side (RFC 1143 section 7, us and him swapped):
//
//	State     Caller sends DO              Caller sends DONT
//	WANTYES   YES, no reply; answered      NO, no reply; answered
//	YES       ignored                      NO, reply WONT
//	NO        YES, reply WILL              ignored
//
// SGA, BINARY, TTYPE, NAWS, NEW-ENVIRON and TSPEED on the caller's side (RFC 1143 section 7);
// SGA starts in NO, as the engine does not ask for it, and is answered by no opening request:
//
//	State     Caller sends WILL            Caller sends WONT
//	WANTYES   YES, no reply; answered      NO, no reply; answered
//	YES       ignored                      NO, reply DONT
//	NO        YES, reply DO                ignored
//
// When the caller's side of TTYPE, TSPEED or NEW-ENVIRON moves to YES and that option's SEND has
// not been sent, the SEND follows, after any reply: TTYPE's and TSPEED's are SEND alone,
// NEW-ENVIRON's asks for the variable USER alone. NAWS has no SEND: the caller sends its size
// unasked.
//
// Every other option request, with no state kept:
//
//	WILL, a Telnet option not on the caller's side above, ECHO too   reply DONT
//	WONT, any such Telnet option                                     no reply
//	DO, a Telnet option not on the engine's side above               reply WONT
//	DONT, any such Telnet option                                     no reply
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
//   - When input holds IAC AYT, Receive shall append AYTAnswer.
//   - When input holds IAC AO or IAC IP, Receive shall owe a Synch, appending no reply.
//   - When input holds IAC and then a byte other than WILL, WONT, DO, DONT, SB, IAC, AYT, AO or
//     IP, Receive shall discard both bytes without reply.
//   - When input holds a byte that is not part of a sequence starting with IAC, Receive shall
//     discard it without reply.
//   - When a sequence is split across calls, Receive shall reply to it, owe a Synch and end
//     negotiation as it would had the sequence come in one call.
//   - When the byte that completes the caller's last answer to the eight opening requests
//     arrives, Receive shall return true.
//   - After the byte that completes the caller's last answer, Receive shall append no reply, owe
//     no Synch and change no state, for the rest of that input and every later call.
//   - After it has returned true, Receive shall return true on every later call.
//   - Receive shall append its replies after the bytes already in replies and leave those bytes
//     unchanged.
//   - Receive shall append at most one reply per option request, and after it at most one SEND.
//   - Receive shall append at most five times the length of input plus MostReply bytes to replies
//     in one call.
//   - Receive shall append, over all its calls on one negotiation, no more bytes than five times
//     all their input held.
//   - If input is empty, then Receive shall append nothing and return what it returned on the
//     call before, or false on the first call.
//   - Receive shall return for every input without failing or panicking.
//   - While negotiation lasts, Receive shall answer each option request about ECHO, SGA or
//     BINARY on the engine's side by the first table above, moving its state and appending the
//     reply that table gives.
//   - While negotiation lasts, Receive shall answer each option request about SGA, BINARY, TTYPE,
//     NAWS, NEW-ENVIRON or TSPEED on the caller's side by the second table above, moving its
//     state and appending the reply that table gives.
//   - When the caller's side of TTYPE or TSPEED moves to YES and that option's SEND has not been
//     appended on this negotiation, Receive shall append that SEND after any reply.
//   - When the caller's side of NEW-ENVIRON moves to YES and its SEND has not been appended on
//     this negotiation, Receive shall append the SEND for the variable USER alone after any
//     reply.
//   - While negotiation lasts, when the caller sends WILL for a Telnet option other than SGA,
//     BINARY, TTYPE, NAWS, NEW-ENVIRON and TSPEED, Receive shall append IAC DONT and that Telnet
//     option.
//   - While negotiation lasts, when the caller sends DO for a Telnet option other than ECHO, SGA
//     and BINARY, Receive shall append IAC WONT and that Telnet option.
//   - While negotiation lasts, when the caller sends WONT for a Telnet option other than SGA,
//     BINARY, TTYPE, NAWS, NEW-ENVIRON and TSPEED, or DONT for one other than ECHO, SGA and
//     BINARY, Receive shall append no reply and change no state.
//   - Receive shall let nothing inside a subnegotiation change a reply, a state or whether a
//     Synch is owed.
func (negotiation *Negotiation) Receive(input, replies []byte) ([]byte, bool) {
	return negotiation.receive(input, replies)
}

// TakeSynch returns how many Synchs Receive and Strip owe, one for each AO and IP their lines say
// owes one, since the last TakeSynch, and clears the count: the writer writes the replies appended
// so far, then that many Synchs.
//
//   - TakeSynch shall return the number of Synchs Receive's and Strip's lines have owed since the
//     last TakeSynch, or since New.
//   - After it returns, TakeSynch shall return zero until Receive or Strip owes another.
//   - TakeSynch shall change no option state and no reply. [read]
func (negotiation *Negotiation) TakeSynch() int {
	return negotiation.takeSynch()
}

// Negotiate negotiates over one connection; Accept calls Open, which negotiates as Negotiate does
// and goes on as the Line. It writes the opening requests, then reads into a fixed buffer of
// ReadBufferSize, hands the bytes to Receive and writes its replies from a fixed buffer of
// ReplyBufferSize, then the Synchs TakeSynch says are owed, until Receive reports the end or
// NegotiationSeconds after the opening write. The 3 seconds end a read that waits, never a write:
// a write, the Synch's included, waits until it is done or the context ends. A write cut short can
// reach the caller whole while reporting nothing written, as Go on Windows reports a cancelled
// send, so nothing written after one could be trusted to be right; the context's end closes the
// call, so nothing is written after it.
// When two things happen at once, the context ending wins, then any read or write failure, whose
// replies are not written; Answered only when nothing failed. Whether the context has ended is
// judged by the clock, as on the Line, whatever the failure: a context whose deadline has passed
// has ended, with context.DeadlineExceeded, whether or not it reports it yet. Answered and TimedOut
// are only ever the result while the context has not ended.
// On return, with an outcome or an error, it leaves nothing behind: the connection's read and
// write deadlines at the context's deadline, cleared if it has none, and nothing of its own
// running. Results: ErrCallerClosed, ErrConnectionFailed, ErrDeadlineEnded.
//
//   - If the context has ended when Negotiate is called, judged by the clock, then Negotiate shall
//     return ErrDeadlineEnded without writing to the connection.
//   - Negotiate shall return Answered or TimedOut only while the context has not ended, judged by
//     the clock; once it has ended, Negotiate shall write nothing more and return
//     ErrDeadlineEnded.
//   - When it is called, Negotiate shall write the opening requests New returns before it reads
//     from the connection.
//   - Negotiate shall read into a buffer of ReadBufferSize bytes and write its replies from a
//     buffer of ReplyBufferSize bytes, and keep no other copy of the caller's bytes. [read]
//   - Negotiate shall hand the bytes a read returns to Receive before it looks at that read's
//     error. [read]
//   - When Receive appends replies and returns false, Negotiate shall write those replies before
//     its next read.
//   - When TakeSynch returns more than zero after a read that returned no error, Negotiate shall
//     write that read's replies, then IAC DM repeated that many times in one WriteUrgent, before
//     its next read.
//   - When Receive returns true on a read that returned no error, Negotiate shall write that
//     call's replies and the Synchs owed and, if those writes returned no error, return Answered
//     with no error.
//   - If NegotiationSeconds pass after Negotiate begins the opening write, while a read is
//     waiting, and the context has not ended, then Negotiate shall return TimedOut with no error.
//   - While a write is waiting, Negotiate shall wait for it until it ends or the context ends,
//     whether or not NegotiationSeconds have passed.
//   - If NegotiationSeconds have passed when a write ends without an error, Receive has not
//     returned true, and the context has not ended, then Negotiate shall return TimedOut with no
//     error, reading nothing more.
//   - If NegotiationSeconds have passed when a read or a write ends, Receive has not returned
//     true, and the context has ended, then Negotiate shall return ErrDeadlineEnded.
//   - If the context's deadline passes while a write is waiting, or at or before
//     NegotiationSeconds after the opening write began while a read is waiting, then Negotiate
//     shall return ErrDeadlineEnded.
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
//     read's replies and no Synch, and return the result that error gives. [read]
//   - If a read or a write fails other than by end of file or a passed deadline, then Negotiate
//     shall return ErrConnectionFailed.
//   - Negotiate shall write nothing to the connection but the opening requests, the replies
//     Receive appends, and IAC DM written with WriteUrgent once for each Synch TakeSynch returns.
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
// and returns the data byte to hand on and true when the byte comes to one; false when it is part
// of a Telnet command that hands nothing on. It answers each option request into replies by the
// same rules and tables as Receive (RFC 854, RFC 1143), keeping the same option states and the
// same record of SENDs sent; appends AYTAnswer for AYT; owes a Synch for AO and IP, which
// TakeSynch hands out; hands on BS for EC and Ctrl-U for EL; and discards every other Telnet
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
//	IAC AYT                                           append AYTAnswer
//	IAC AO, IAC IP                                    a Synch owed
//	IAC EC                                            the data byte BS, 0x08
//	IAC EL                                            the data byte Ctrl-U, 0x15
//	IAC, then any other byte                          a two-byte command, discarded
//	any other byte                                    data, itself
//
// Lines:
//
//   - Strip shall return true, with the byte to hand on, for each data byte, for the second IAC
//     of IAC IAC outside a subnegotiation, and for the last byte of IAC EC and of IAC EL; and
//     false for every other byte.
//   - When the bytes hold IAC IAC outside a subnegotiation, Strip shall return false for the
//     first IAC and the data byte 255 with true for the second.
//   - When the bytes hold IAC EC, Strip shall return false for IAC and BS, 0x08, with true for
//     EC.
//   - When the bytes hold IAC EL, Strip shall return false for IAC and Ctrl-U, 0x15, with true for
//     EL.
//   - When a byte completes an option request, Strip shall answer it into replies, change the
//     option's state and append a SEND exactly as Receive's lines do while negotiation lasts.
//   - When the bytes hold IAC AYT, Strip shall append AYTAnswer.
//   - When the bytes hold IAC AO or IAC IP, Strip shall owe a Synch, appending no reply.
//   - When the bytes hold IAC and then a byte other than WILL, WONT, DO, DONT, SB, IAC, AYT, AO,
//     IP, EC or EL, or a subnegotiation, Strip shall discard them without reply.
//   - When a sequence is split across negotiation's end, Strip shall read it as it would had the
//     sequence come after it whole.
//   - Strip shall append its reply after the bytes already in replies, and leave those unchanged.
//   - Strip shall append at most MostReply bytes in one call.
//   - Strip shall append to replies, over all its calls and Receive's on one negotiation, no more
//     bytes than five times all their input held.
//   - After Strip's first call, Receive shall append no reply and change no state on that
//     negotiation, for every later call.
//   - Strip shall let nothing inside a subnegotiation change a reply, a state, a byte handed on
//     or whether a Synch is owed.
//   - Strip shall return for every byte without failing or panicking.
func (negotiation *Negotiation) Strip(character byte, replies []byte) ([]byte, byte, bool) {
	return negotiation.strip(character, replies)
}

// SendBufferSize is the Line's fixed send buffer. When it is full, the call adding to it writes
// it out first, so nothing the caller does grows it. It holds at least ReplyBufferSize, so the
// replies negotiation still owed when its last read failed fit in it whole.
const SendBufferSize = 2048

// Line is a caller's Telnet connection once negotiation is over: the Telnet side of the textio
// package's Chars. It keeps a receive buffer of the caller's bytes not yet read, a send buffer of
// SendBufferSize, and the negotiation, whose option states go on changing as the caller asks.
// It reads in stream order, so an option request is answered, a command acted on, and ECHO
// changes, exactly where it falls among the caller's characters. A Line not made by Open or
// Accept, or nil, fails every call with ErrConnectionFailed, and its Echoes returns false. Close
// needs a Line made by Accept: on one made by Open it fails with ErrConnectionFailed. One goroutine
// per Line.
//
// Its calls report as the textio package's table has it: os.ErrDeadlineExceeded when the
// deadline given passed first; io.EOF when the caller closed its side; the context's error,
// wrapped, when the context ended first; ErrConnectionFailed, wrapping the cause, for any other
// failure. When two happen at once, the context ending wins, then a failure, then a passed
// deadline. Each is judged by the clock: a context whose deadline has passed has ended, with
// context.DeadlineExceeded, whether or not it reports it yet. A context ending wakes a waiting
// call at once, a Synch's write included. A call sets the connection's deadline itself before
// each read or write, the earlier of its own deadline and the context's, or none when neither has
// one, and leaves nothing of its own running when it returns. Once a write fails, whatever it
// wrote, the Line writes nothing more, for the reason given on Negotiate: what a write cut short
// sent cannot be known.
type Line struct {
	state lineState
}

// Open negotiates exactly as Negotiate does and, when negotiation ends with an outcome, returns a
// Line over the same connection that carries on where negotiation stopped. On an error it
// returns a nil Line and Negotiate's error, which also matches the standard library's cause
// through errors.Is: io.EOF for ErrCallerClosed, the context's error for ErrDeadlineEnded.
//
// The bytes negotiation read, up to the byte at which Receive returned true or all of them when
// Receive never did, are negotiation's: discarded as data, their option requests and commands
// answered. Every byte after them is the Line's to read, in order: the engine cannot tell when an
// unread byte was sent, so typing ahead works however negotiation ended.
//
//   - Open shall negotiate as Negotiate does, and return the Outcome, or an error matching
//     Negotiate's through errors.Is.
//   - When Open returns ErrCallerClosed, the error shall also match io.EOF.
//   - When negotiation ends with an outcome, Open shall return a Line that writes first, in order,
//     the replies and then the Synchs owed of a read that returned bytes with a passed deadline,
//     which Negotiate did not write.
//   - When negotiation ends with an outcome after Receive returned true, Open shall return a Line
//     whose receive buffer holds, unread and in order, every byte negotiation's last read
//     returned after the byte at which Receive returned true, and no other byte.
//   - When negotiation ends TimedOut before Receive returned true, Open shall return a Line whose
//     receive buffer is empty.
//   - When it returns an error, Open shall return a nil Line.
func Open(ctx context.Context, connection Conn) (*Line, Outcome, error) {
	return open(ctx, connection)
}

const (
	// ClosingWaitSeconds is the wait after Close shuts down the sending side, for the caller to
	// close. Fixed in this layer; a setting once configuration exists.
	ClosingWaitSeconds = 3
	// DiscardBufferSize is the fixed buffer Close reads into: nothing the caller sends grows it.
	DiscardBufferSize = 256
)

// Accept makes one accepted TCP connection Telnet's object for the shared execution path: it keeps
// urgent data in line, makes the connection a Conn whose WriteUrgent writes TCP urgent data, then
// negotiates and returns the Line exactly as Open does, whichever Outcome negotiation ends with.
// Urgent data is kept in line (SO_OOBINLINE) because RFC 6093 section 6 requires it of an
// application that still uses urgent data, as Telnet's Synch does. The standard library has no
// call for either, so both go through the connection's SyscallConn: SO_OOBINLINE with
// syscall.SetsockoptInt, at the socket level, on Linux syscall.SO_OOBINLINE, 0x0A, on Windows,
// where the syscall package names none, Winsock's SO_OOBINLINE, 0x0100; and the urgent write with
// the flag MSG_OOB. Set after accept, SO_OOBINLINE also keeps in line urgent data that arrived
// before accept (probed on both).
//
// On Windows, Go's SyscallConn cannot wait for room: its Write runs the callback once and fails
// when the callback says "not yet" (internal/poll). So the urgent write there takes Winsock's
// documented route for a send with a time limit, an overlapped send with an event, whose calls
// the syscall package lacks; they come from golang.org/x/sys/windows, in that file alone (the
// developer, 2026-10-27).
//
//   - Accept shall keep the caller's urgent data in line, so that a Synch, IAC with DM sent as
//     urgent data, reaches negotiation whole and, after negotiation, the caller's next character
//     after it is read as data, and none of the data before it is discarded.
//   - Accept shall set SO_OOBINLINE on the connection before it reads from or writes to it.
//     [read]
//   - If SO_OOBINLINE cannot be set, then Accept shall return ErrConnectionFailed and a nil Line
//     without writing to the connection.
//   - When the engine sends a Synch on a Line Accept made, the caller shall receive IAC DM with DM
//     as TCP urgent data.
//   - While a Synch's write on a Line Accept made waits for room, a passed write deadline or the
//     context ending shall wake it, as it wakes every other write, on Linux and on Windows.
//   - Once SO_OOBINLINE is set, Accept shall negotiate and return a Line as Open does, whichever
//     Outcome negotiation ends with, or a nil Line and Open's error.
func Accept(ctx context.Context, connection *net.TCPConn) (*Line, error) {
	return accept(ctx, connection)
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
//   - After a write has failed, whatever it wrote, every later SendChar, Flush and RecvChar on the
//     Line shall write nothing and return ErrConnectionFailed.
//   - Flush shall hold the send buffer in SendBufferSize bytes, and keep no other copy. [read]
func (line *Line) Flush(ctx context.Context) error {
	return line.flush(ctx)
}

// RecvChar returns the caller's next data byte, with EC handed on as BS and EL as Ctrl-U. It hands
// Strip the receive buffer's bytes one at a time, queues Strip's replies, writes the Synch when one
// is owed, and stops at the first byte Strip hands on, reading nothing after it. It writes the
// send buffer out before it waits for the caller and when a reply needs room, and a Synch after
// the replies queued before it, all no later than deadline. Whether the data bytes queued before an
// AO or IP are written or thrown away is not pinned here: Part 4's page leaves it to the first
// long screen.
//
//   - RecvChar shall return the caller's data bytes in the order sent, BS for each EC and Ctrl-U
//     for each EL among them, and no other byte of a Telnet command.
//   - RecvChar shall read no byte after the byte it returns.
//   - RecvChar shall queue Strip's replies as they are, unescaped, in order.
//   - Before it hands Strip a byte, RecvChar shall have room for MostReply bytes, writing the send
//     buffer out as Flush does, under deadline, when it has not.
//   - When TakeSynch returns more than zero after Strip, RecvChar shall write IAC DM with
//     WriteUrgent, under deadline, after every reply queued before it and before it hands Strip
//     another byte.
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
//   - If the Line was not made by Open or Accept, or is nil, then Echoes shall return false.
func (line *Line) Echoes() bool {
	return line.echoes()
}

// Close is Telnet's own close, called once the call is answered: it shuts down the sending side
// of the Line's connection, then reads and discards what the caller sends until the caller closes
// or ClosingWaitSeconds pass, no later than the context's deadline. It writes nothing, what is
// still queued included, and leaves closing the connection to the shared execution path. A close
// with the caller's bytes still unread may reach the caller as a reset rather than an orderly end
// of stream; either is the close these lines ask for.
//
//   - Close shall shut down the sending side of the Line's connection, then read and discard until
//     the caller closes or ClosingWaitSeconds pass, no later than the context's deadline.
//   - Close shall write nothing to the connection.
//   - Close shall set the read deadline for its wait itself, and rely on no deadline an earlier
//     call left. [read]
//   - Close shall read only into a buffer of DiscardBufferSize bytes, and keep no copy of what it
//     reads. [read]
//   - When the caller closes, or ClosingWaitSeconds pass, Close shall return no error.
//   - If the context has ended when Close is called, then Close shall return the context's
//     error, wrapped, without touching the connection.
//   - If the context ends while Close waits, then Close shall return the context's error,
//     wrapped.
//   - If shutting down the sending side or setting the read deadline fails, then Close shall
//     return ErrConnectionFailed at once.
//   - If the Line was not made by Accept, or is nil, then Close shall return ErrConnectionFailed
//     without touching the connection.
func (line *Line) Close(ctx context.Context) error {
	return line.close(ctx)
}
