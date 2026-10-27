// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package ssh is the SSH kind of connection: it does the SSH handshake over one accepted
// connection, opens the caller's session channel, and then carries the caller's characters for
// the session as the Channel.
//
// The Channel is SSH's object in the developer's design for Part 3: "There are two listeners, one
// for Telnet and one for SSH. The listeners' job is just to accept the connections. It then hands
// each connection off to a shared execution path as a class. That class defines identical
// primitives that the shared execution uses." Accept makes an accepted connection SSH's object,
// and the Channel offers the identical primitives: SendChar, RecvChar, Flush, Echoes, and Close,
// the kind's own close.
//
// It owns reading the host key file the sysop names; the handshake, on golang.org/x/crypto/ssh at
// v0.58.0 or later, with the version line and the algorithms below and nothing else; sign-in with
// the method none under any username, and closing the connection on any other method; the answer
// to every channel and request a caller opens or sends; whether the board echoes, which is whether
// the caller asked for a terminal; the Channel's send and receive buffers; and, once the call is
// answered, SSH's own close: exit status 0, end of file, closing the channel, and waiting up to 3
// seconds for the caller to close. It writes nothing to the local log.
//
// It does not own accepting, the cap of 100, the ceiling on a whole call or closing the
// connection: the listeners and the shared execution path own those. It does not own reading a
// line, editing it or deciding what to echo, which the textio package owns, nor what the call says
// and asks, which the session owns. The command line, which names the host key file, and the
// local log line that says why the key was refused belong to the program. Sign-in with a key, the
// login prompt, the host key in the vault and the terminal's type and size belong to later layers.
//
// What the engine does as a whole, this package included, is in docs/behavior.md.
//
// # Untrusted input
//
// Every byte the caller sends crosses the trust boundary at the network listener. Before the shell
// the library reads it: the version line, the key exchange, sign-in, channels and requests; this
// package answers what the library hands it by the table on Accept. The engine keeps none of it:
// the username and everything a pty-req carries are never stored, logged or shown by the engine;
// the library alone keeps the username, on its connection, for the connection's life. Signing in
// with none proves nothing about the caller, so the Channel carries no identity (the map's section
// 2, item 10: the board's own prompt is the only way in). The Channel hands the caller's channel
// data, one byte at a time, to the textio package's Edit, those sent before the shell included:
// the library keeps channel data and requests in separate queues, so a byte sent before the shell
// cannot be told from one typed ahead with it. Which bytes a caller sends after its own end of
// file reach the engine is the library's timing, and is not pinned; every byte the Channel reads
// is handled as typed data. Extended data is never read as the caller's data. Per connection the
// library holds at most one channel window, 2 MiB, of channel data and extended data together for
// the one channel the engine opens; two request queues, the connection's and the channel's, 16
// requests deep, each request one packet of at most 256 KiB; and its queue of channels the
// caller asks to open, 16 deep, each keeping up to one such packet: about 15 MiB a connection
// when the caller stops reading, bounded by the call's ceiling. No error this package returns holds
// the library's text, which can quote what the caller sent. The host key file is the sysop's, not
// the caller's; it is read once, at most HostKeyMostBytes. There is no fuzz target here: the
// library parses the wire.
//
// # Oracles
//
// The handshake, the refusals and the call over a socket: the OpenSSH client, ssh, an independent
// program, driven through its standard input and output, with a host key made by ssh-keygen for
// the run; and, for what that client will not send in order, QA's own scripted client, written
// apart from this package's code. Tests run on Linux x86-64, Linux ARM64 and Windows x86-64, as an
// ordinary user, over loopback on a port the operating system picks.
//
// # What it needs from its callers
//
// An accepted TCP connection, and a context carrying the call's ceiling, cancelled by a stop. One
// Accept per connection, from that connection's own goroutine, before anything else is written to
// it. After Accept returns an error, the shared execution path closes the connection without
// writing to it, and it closes the connection after Close. One goroutine per Channel: it is not
// safe for use from two at once.
//
// # The wire format
//
// SSH (RFC 4253, RFC 4252, RFC 4254) frames the stream; the library writes and reads it. What this
// package sets in the version line and the key exchange's fields:
//
//	The version line      SSH-2.0-HeliosAdvance, then CR LF
//	Key exchanges         mlkem768x25519-sha256, curve25519-sha256,
//	                      curve25519-sha256@libssh.org, and the marker
//	                      kex-strict-s-v00@openssh.com; strict key exchange
//	                      whenever the caller offers it
//	Ciphers               chacha20-poly1305@openssh.com, aes256-gcm@openssh.com,
//	                      aes128-gcm@openssh.com
//	MAC                   hmac-sha2-256-etm@openssh.com, which those ciphers never use
//	Compression           none
//	Host key              ssh-ed25519
//	Sign-in               none, under any username
//
// What the library sends of its own, which this package does not choose: to a caller that offers
// ext-info-c, the extensions message after the first key exchange (RFC 8308), with server-sig-algs,
// which this package sets to ssh-ed25519 alone, and ping@openssh.com, which the library answers
// itself with a pong; and the channel close SSH requires in reply to the caller's.
//
// # Lines for the package
//
//   - The ssh package shall set the version line and the key exchange's fields, the key
//     exchanges, ciphers, MAC, compression and host key, to the table's values and no others.
//     [read]
//   - The ssh package shall set server-sig-algs to ssh-ed25519 alone. [read]
//   - The ssh package shall not store, log or show the SSH username, nor anything a pty-req
//     carries. [read]
//   - The ssh package shall give the Channel no identity of the caller. [read]
//   - No error the ssh package returns shall hold, in its text, any byte the caller sent or the
//     username. [read]
//   - The ssh package shall write nothing to the local log. [read]
//   - Once the connection is closed, the ssh package shall leave no goroutine of its own, or of
//     the library's for that connection, running. [read]
//   - The ssh package shall import nothing outside the Go standard library and
//     golang.org/x/crypto/ssh. [read]
package ssh

import (
	"context"
	"errors"
	"net"
	"time"
)

const (
	// VersionLine is sent first, followed by CR LF; it names the board and no version number.
	VersionLine = "SSH-2.0-HeliosAdvance"
	// HostKeyMostBytes bounds the host key file: an Ed25519 key in OpenSSH's format is far
	// shorter, so a longer file is not one.
	HostKeyMostBytes = 16384
	// ReadBufferSize is the fixed buffer the Channel reads the caller's data into.
	ReadBufferSize = 256
	// SendBufferSize is the Channel's fixed send buffer. When it is full, the call adding to it
	// writes it out first, so nothing the caller does grows it.
	SendBufferSize = 1024
	// ClosingWaitSeconds is the wait after Close closes the channel, for the caller to close.
	// Fixed in this layer; a setting once configuration exists.
	ClosingWaitSeconds = 3
)

var (
	// ErrHostKeyMissing means no file is at the path given.
	ErrHostKeyMissing = errors.New("ssh: the host key file does not exist")
	// ErrHostKeyUnreadable means the file is there but cannot be read.
	ErrHostKeyUnreadable = errors.New("ssh: the host key file cannot be read")
	// ErrHostKeyNotOpenSSH means the file is not one PEM block of type "OPENSSH PRIVATE KEY", or
	// is longer than HostKeyMostBytes.
	ErrHostKeyNotOpenSSH = errors.New("ssh: the host key file is not a private key in OpenSSH's format")
	// ErrHostKeyPassphrase means the key is protected by a passphrase.
	ErrHostKeyPassphrase = errors.New("ssh: the host key is protected by a passphrase")
	// ErrHostKeyNotEd25519 means the key is not an Ed25519 key.
	ErrHostKeyNotEd25519 = errors.New("ssh: the host key is not an Ed25519 key")
	// ErrHostKeyReadableByOthers means, on Linux, the file's mode lets its group or others read
	// it.
	ErrHostKeyReadableByOthers = errors.New("ssh: the host key file's mode lets its group or others read it")
)

var (
	// ErrNoShell means the connection or the session channel ended before the shell, however it
	// ended, end of file apart: the caller's close, a disconnect message, a sign-in method other
	// than none, a handshake that fails or any other failure. How it ended is not told apart (the
	// developer, 2026-10-27): the shared execution path ends the call the same way for each. It
	// never carries the library's text.
	ErrNoShell = errors.New("ssh: the call ended before the shell")
	// ErrConnectionFailed means a wrong call: a nil connection, a HostKey not made by ReadHostKey,
	// or a Channel not made by Accept.
	ErrConnectionFailed = errors.New("ssh: a nil connection, or a key or Channel not made here")
	// ErrDeadlineEnded means Accept's context ended first: the call's ceiling or a stop. It is
	// returned wrapping context.DeadlineExceeded or context.Canceled, so errors.Is matches both.
	ErrDeadlineEnded = errors.New("ssh: the deadline ended first")
)

// HostKey is the board's SSH host key, read once at start. A HostKey not made by ReadHostKey, or
// nil, makes every Accept fail with ErrConnectionFailed.
type HostKey struct {
	state hostKeyState
}

// ReadHostKey reads the host key file at path once: an Ed25519 private key with no passphrase in
// OpenSSH's format, a PEM block of type "OPENSSH PRIVATE KEY" as ssh-keygen makes it; every other
// PEM type the library reads, such as "PRIVATE KEY" (PKCS#8) or "RSA PRIVATE KEY", is refused.
// Each error names the problem and holds no part of the file's contents, so the program can write
// it to the local log as it is. The checks run in the order of the lines below, and the first that
// applies is the result.
//
//   - ReadHostKey shall check the file in the order of these lines and return the first refusal
//     that applies.
//   - If no file is at path, then ReadHostKey shall return ErrHostKeyMissing.
//   - If, on Linux, the file's mode lets its group or others read it, then ReadHostKey shall
//     return ErrHostKeyReadableByOthers without reading the file.
//   - If the file cannot be read, then ReadHostKey shall return ErrHostKeyUnreadable.
//   - If the file is longer than HostKeyMostBytes, or is not one PEM block of type "OPENSSH
//     PRIVATE KEY", then ReadHostKey shall return ErrHostKeyNotOpenSSH.
//   - If the key is protected by a passphrase, then ReadHostKey shall return
//     ErrHostKeyPassphrase.
//   - If the key is not an Ed25519 key, then ReadHostKey shall return ErrHostKeyNotEd25519.
//   - ReadHostKey shall return an error whose text holds no part of the file's contents.
//   - ReadHostKey shall read at most HostKeyMostBytes and one byte more from the file. [read]
func ReadHostKey(path string) (*HostKey, error) {
	return readHostKey(path)
}

// Accept makes one accepted TCP connection SSH's object for the shared execution path: it does the
// handshake with key, signs the caller in with none, and waits for the first session channel and
// its shell, answering everything the caller opens or sends by the table below, then returns the
// Channel. The library closes the connection itself when the handshake or sign-in fails; otherwise
// the shared execution path closes it, after an error too. On an error it returns a nil Channel.
// It reports only what the engine decides (the developer, 2026-10-27): ErrDeadlineEnded when the
// context ended first, a context whose deadline has passed having ended, by the clock; ErrNoShell
// for every other end of the connection or the session channel before the shell, however it ended.
//
// End of file before the shell changes nothing (Part 7, the developer's of 2026-10-26): the
// channel stays open after it (RFC 4254), so Accept goes on waiting, and once the shell has
// started the Channel returns the data sent before the end of file, then io.EOF, for a caller
// that sends nothing after its end of file (see Untrusted input).
//
//	The caller opens or sends            Accept answers
//	sign-in none, any username           accepted
//	any other sign-in method             the call ends: ErrNoShell
//	the first session channel            accepted
//	a second session channel             refused
//	any other channel                    refused
//	pty-req, before shell                accepted; the board will echo
//	shell, the first                     accepted; Accept returns the Channel
//	any other channel request            refused
//	any global request                   refused
//	ping@openssh.com                     the library's pong
//	data on the channel                  kept, in order, for the Channel
//	end of file, before shell            nothing changes; Accept waits on
//	extended data                        never read as the caller's data
//
// Refused means nothing changes and, where the caller asks for a reply, the reply is failure.
//
//   - Accept shall send VersionLine and CR LF, and set the key exchange's fields to the package's
//     table.
//   - When the caller offers strict key exchange, Accept shall use it.
//   - Accept shall answer each thing the caller opens or sends before the shell as the table above
//     gives.
//   - When the caller has signed in, opened a session channel and asked for a shell, Accept shall
//     return the Channel and no error.
//   - If the connection or the session channel ends before the shell, however it ends, end of
//     file apart, and the context has not ended, then Accept shall return ErrNoShell.
//   - If the caller sends end of file on the session channel before the shell, then Accept shall
//     not return because of it; every other line still applies.
//   - If the context has ended when Accept is called, or ends while it waits, then Accept shall
//     return ErrDeadlineEnded wrapping the context's error, without writing more.
//   - If the context has ended when the connection or the session channel ends, however it ends,
//     then Accept shall return ErrDeadlineEnded.
//   - If connection is nil, or key is nil or not made by ReadHostKey, then Accept shall return
//     ErrConnectionFailed without writing to the connection.
func Accept(ctx context.Context, connection *net.TCPConn, key *HostKey) (*Channel, error) {
	return accept(ctx, connection, key)
}

// Channel is a caller's SSH session channel once the shell has started: the SSH side of the
// textio package's Chars. It keeps a receive buffer of the caller's data not yet read and a send
// buffer of SendBufferSize, and goes on answering what the caller opens or sends: a second shell,
// a pty-req after the shell and every other request or channel are refused, so the greeting never
// comes twice and the echo never changes mid-name. When the caller closes the channel, the
// library answers with the channel close SSH requires, the one write after it; end of file needs
// no answer. A Channel not made by Accept, or nil, fails every call with ErrConnectionFailed, and
// its Echoes returns false. One goroutine per Channel.
//
// SendChar, Flush and RecvChar report only what the engine decides (the developer, 2026-10-27),
// as the textio package's table has it: os.ErrDeadlineExceeded when the deadline given passed
// first; the context's error, wrapped, when the context ended first; and io.EOF for every end of
// the caller's data or of the connection, however it ended: end of file, the channel's close, the
// connection's close, a disconnect message, a reset, or a write that failed. When two happen at
// once, the context ending wins, then an end with no byte waiting or an earlier failed write,
// then a passed deadline; a context whose deadline has passed has ended, by the clock. A context
// ending wakes a waiting call at once. The library gives a channel write no deadline, so a write
// cut short by a deadline or the context gives that call the deadline's or the context's result
// and counts as failed for every later call: the Channel writes nothing more, and what that write
// handed the library may still go out before the connection closes. Once a write has failed,
// every later SendChar, Flush and RecvChar writes nothing and returns io.EOF, unless the context
// has ended; once the caller's data has ended and no byte is waiting, every later RecvChar returns
// io.EOF, unless the context has ended. End of file on the channel alone closes nothing, and
// writes go on.
type Channel struct {
	state channelState
}

// SendChar queues one byte for the caller, as itself. It writes only when the send buffer is full.
//
//   - SendChar shall queue each byte as itself.
//   - If the context has ended when SendChar is called, then SendChar shall queue nothing and
//     return the context's error, wrapped.
//   - When the send buffer has room for the byte, SendChar shall queue it without writing and
//     return no error.
//   - When the send buffer has no room, SendChar shall first write it out as Flush does, with
//     Flush's results, and queue nothing unless that write emptied it.
func (channel *Channel) SendChar(ctx context.Context, character byte) error {
	return channel.sendChar(ctx, character)
}

// Flush writes the send buffer out on the channel and empties it, waiting no later than the
// context's deadline.
//
//   - Flush shall write the send buffer's bytes in order as channel data, and leave it empty once
//     they are written.
//   - If the context has ended when Flush is called, or ends while it waits, then Flush shall
//     write nothing more and return the context's error, wrapped.
//   - If a write fails otherwise, then Flush shall return io.EOF.
//   - After a write has failed, every later SendChar, Flush and RecvChar on the Channel shall
//     write nothing and return io.EOF, unless the context has ended.
func (channel *Channel) Flush(ctx context.Context) error {
	return channel.flush(ctx)
}

// RecvChar returns the caller's next byte of channel data. It writes the send buffer out before it
// waits for the caller, no later than deadline.
//
//   - RecvChar shall return the caller's channel data bytes in the order sent, those sent before
//     the call included, and no byte of extended data.
//   - Before it waits for the caller, RecvChar shall write the send buffer out as Flush does,
//     under deadline.
//   - Once deadline has passed, RecvChar shall return os.ErrDeadlineExceeded, even with bytes
//     waiting, unless an earlier write on the Channel has failed, or no byte is waiting and the
//     caller's data has ended; then it shall return io.EOF.
//   - If the caller's data ends, however it ends, while no byte is waiting, then RecvChar shall
//     return io.EOF.
//   - If the write it makes before it waits fails, other than by its deadline or the context,
//     then RecvChar shall return io.EOF.
//   - If the context has ended when RecvChar is called, or ends while it waits, then RecvChar
//     shall return the context's error, wrapped, and no byte.
//   - RecvChar shall read into a buffer of ReadBufferSize bytes and hold at most that many bytes
//     not yet read. [read]
func (channel *Channel) RecvChar(ctx context.Context, deadline time.Time) (byte, error) {
	return channel.recvChar(ctx, deadline)
}

// Echoes is whether the board echoes on this Channel: true when the caller asked for a terminal,
// a pty-req, before the shell; false when it did not, and its own terminal echoes. It does not
// change during the call: a pty-req after the shell is refused.
//
//   - While the caller asked for a terminal before the shell, Echoes shall return true.
//   - While the caller did not ask for a terminal before the shell, Echoes shall return false.
//   - If the Channel was not made by Accept, or is nil, then Echoes shall return false.
func (channel *Channel) Echoes() bool {
	return channel.echoes()
}

// Close is SSH's own close, called once the call is answered: it sends exit status 0 and end of
// file, closes the channel, then waits until the caller closes the connection or
// ClosingWaitSeconds pass, no later than the context's deadline. It writes nothing of its own but
// those, what is still queued included, and leaves closing the connection to the shared execution
// path. During its wait the caller's requests and channels are still refused, and the library may
// still answer on its own: its channel close in reply to the caller's, and a ping's pong.
//
//   - Close shall send exit status 0, then end of file, then close the channel.
//   - Close shall wait until the caller closes the connection or ClosingWaitSeconds pass, no later
//     than the context's deadline.
//   - When the caller closes the connection, or ClosingWaitSeconds pass, Close shall return no
//     error.
//   - If the context has ended when Close is called, then Close shall return the context's
//     error, wrapped, without touching the connection.
//   - If the context ends while Close waits, then Close shall return the context's error,
//     wrapped.
//   - If sending any of them fails, then Close shall return io.EOF at once.
//   - If the Channel was not made by Accept, or is nil, then Close shall return
//     ErrConnectionFailed without touching the connection.
func (channel *Channel) Close(ctx context.Context) error {
	return channel.close(ctx)
}
