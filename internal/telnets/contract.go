// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package telnets is the Telnet over TLS kind of connection: it reads the TLS certificate and its
// key once, makes the TLS handshake over one accepted connection, and then hands the encrypted
// connection to the telnet package, which serves the call inside it exactly as it serves a Telnet
// caller it has just accepted.
//
// It is the developer's shape for Part 5, his "yes" of 2026-10-25 to its own slice, "a wrapper
// around Telnet's object". The object it returns is the telnet package's Line, made by
// telnet.Open over the encrypted connection, so the shared execution path serves it with the same
// identical primitives as every other kind of connection.
//
// It owns reading the certificate file and the key file the sysop names, each opened once and
// checked as opened, never by its path again (the developer's decision of 2026-10-26); the TLS
// table below and nothing else, on the Go standard library's crypto/tls; the handshake; and the
// encrypted connection as Telnet's connection: its urgent write, which writes DM as an ordinary
// byte, since TLS carries no urgent data, and its CloseWrite, which sends TLS's close_notify
// before it shuts down the sending side. It writes nothing to the local log.
//
// It does not own negotiation, the Line or Telnet's own close, which are the telnet package's; nor
// accepting, the cap of 100, the ceiling on a whole call or closing the connection, which the
// listeners and the shared execution path own. The command line, which names the two files, and
// the local log line that says why a file was refused belong to the program. The certificate and
// key in the vault, made or installed by hadv-cert, reloading them and watching their expiry, and
// listening at every address belong to later layers.
//
// What the engine does as a whole, this package included, is in docs/behavior.md.
//
// # Untrusted input
//
// Every byte the caller sends crosses the trust boundary at the network listener. Before and
// inside the handshake, crypto/tls reads it: the records, the ClientHello and everything after it,
// each record bounded by TLS itself. The engine keeps none of what the handshake carries: the
// server name a caller asks for among it is never stored, logged or shown. After the handshake,
// every byte is a Telnet caller's, read through the encrypted connection by the telnet package
// under its own tables. A caller's close_notify ends the encrypted connection's reads with end of
// file, as a hang-up; a damaged record ends them with a failure. No error this package returns
// holds crypto/tls's text, which can quote what the caller sent. The two files are the sysop's,
// not the caller's; each is read once, at most TLSFileMostBytes. There is no fuzz target here:
// crypto/tls parses the wire.
//
// # Oracles
//
// The TLS table and the refusals: OpenSSL's openssl s_client, an independent program, driven
// through its standard input and output, with a self-signed certificate and keys made by openssl
// for the run: each version and suite offered is taken, and TLS 1.1, a CBC suite, a weak group and
// a renegotiation are refused; the call itself, its greeting, prompt and Hello, through its
// standard input. The Telnet side over TLS: QA's own scripted Telnet client, run over a TLS client
// on crypto/tls, written apart from this package's code. Tests run on Linux x86-64, Linux ARM64
// and Windows x86-64, as an ordinary user, over loopback on a port the operating system picks.
//
// # What it needs from its callers
//
// One ReadCertificate at start. An accepted TCP connection, and a context carrying the call's
// ceiling, cancelled by a stop. One Accept per connection, from that connection's own goroutine,
// before anything else is written to it. After Accept returns an error, the shared execution path
// closes the connection without writing to it, and it closes the connection after the Line's
// Close.
//
// # The TLS table
//
//	Offered                 Only these
//	versions                TLS 1.3 and TLS 1.2
//	TLS 1.3 suites          TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
//	                        TLS_CHACHA20_POLY1305_SHA256
//	TLS 1.2 suites          ECDHE with an ECDSA or RSA certificate, and AES_128_GCM_SHA256,
//	                        AES_256_GCM_SHA384 or CHACHA20_POLY1305_SHA256: the six
//	                        TLS_ECDHE_ECDSA_WITH_ and TLS_ECDHE_RSA_WITH_ suites of those three
//	key exchanges           X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519, P-256,
//	                        P-384, P-521
//	certificate             the certificate file's whole chain, in the file's order
//	client certificate      none asked for
//	renegotiation           refused
//	session resumption      refused: no session ticket and no session ID is issued or accepted
//
// The order within each row is crypto/tls's own; the caller and crypto/tls pick from what is
// offered. These are Go 1.27.3's defaults with its four TLS 1.2 CBC suites taken out, each set
// explicitly, so that no GODEBUG setting widens or narrows them.
//
// # Lines for the package
//
//   - The telnets package shall offer, in every handshake, only what the TLS table names.
//   - The telnets package shall store, log and show nothing a caller sends in its handshake, the
//     server name it asks for among it. [read]
//   - The telnets package shall write nothing to the local log, and no part of the private key
//     anywhere. [read]
//   - The telnets package shall judge whether a call's context has run out only with
//     timeup.Ended, take every time a call must stop by from timeup.Limit, and wake a waiting call
//     only with timeup.WakeOnEnd or timeup.Wake, keeping no copy of their rules. [read]
//   - The telnets package shall import nothing outside the Go standard library and the telnet and
//     timeup packages. [read]
package telnets

import (
	"context"
	"errors"
	"net"

	"github.com/heliosestate/heliosadvance/internal/telnet"
)

// TLSFileMostBytes is the most ReadCertificate reads of either file: a certificate with its chain
// is far shorter, so a longer file is not one.
const TLSFileMostBytes = 65536

// Why ReadCertificate refused a file. Each error's text names the file it is about, the
// certificate file or the key file, so the start_failed line says which, and holds no part of
// either file's contents, so the program can write it to the local log as it is.
var (
	// ErrTLSFileMissing means no file is at the path given.
	ErrTLSFileMissing = errors.New("telnets: no file is at the path given")
	// ErrTLSFileUnreadable means the file is there but cannot be opened or read.
	ErrTLSFileUnreadable = errors.New("telnets: the file cannot be read")
	// ErrTLSFileNotRegular means the path names a folder, a named pipe or anything but a file.
	ErrTLSFileNotRegular = errors.New("telnets: the path is not a regular file")
	// ErrTLSFileNotPEM means the file is not PEM, holds no certificate or no private key block, or
	// is longer than TLSFileMostBytes.
	ErrTLSFileNotPEM = errors.New("telnets: the file is not a PEM certificate or key")
	// ErrKeyPassphrase means the key is protected by a passphrase.
	ErrKeyPassphrase = errors.New("telnets: the key is protected by a passphrase")
	// ErrKeyMismatch means the key does not match the certificate.
	ErrKeyMismatch = errors.New("telnets: the key does not match the certificate")
	// ErrKeyType means the key is not RSA of 2048 bits or more, ECDSA P-256 or P-384, or Ed25519.
	ErrKeyType = errors.New(
		"telnets: the key is not RSA of 2048 bits or more, ECDSA P-256 or P-384, or Ed25519")
	// ErrKeyReadableByOthers means, on Linux, the key file's mode lets its group or others read it.
	ErrKeyReadableByOthers = errors.New("telnets: the key file can be read by its group or others")
)

// Why the call ended before Telnet took it; neither holds anything the caller sent.
var (
	// ErrHandshakeFailed means the handshake failed, however it failed.
	ErrHandshakeFailed = errors.New("telnets: the TLS handshake failed")
	// ErrDeadlineEnded means the call's ceiling or a stop came before the handshake completed.
	ErrDeadlineEnded = errors.New("telnets: the call ended before the handshake completed")
)

// Certificate is the certificate with its chain and its private key, read once at start. A
// Certificate ReadCertificate did not make, or nil, fails every Accept.
type Certificate struct {
	state certificateState
}

// ReadCertificate reads the certificate file at certificatePath and the key file at keyPath once
// each: the certificate file holds the certificate first and then its chain, as PEM CERTIFICATE
// blocks; the key file holds its private key, as one PEM private key block with no passphrase.
// Each file is opened once, and every check after the open is made on the opened file, never on
// its path again. The checks run in the order of the lines below, the certificate file's first,
// and the first that applies is the result; its error wraps one of the errors above.
//
//   - ReadCertificate shall check the certificate file and then the key file, in the order of
//     these lines, and return the first refusal that applies.
//   - If no file is at the path, then ReadCertificate shall return ErrTLSFileMissing.
//   - If the file cannot be opened, then ReadCertificate shall return ErrTLSFileUnreadable.
//   - If the opened file is not a regular file, such as a folder or a named pipe, then
//     ReadCertificate shall return ErrTLSFileNotRegular, without reading it and without waiting
//     on it, its open included.
//   - If, on Linux, the opened key file's mode lets its group or others read it, then
//     ReadCertificate shall return ErrKeyReadableByOthers without reading the file.
//   - If the opened file cannot be read, then ReadCertificate shall return ErrTLSFileUnreadable.
//   - If the file is longer than TLSFileMostBytes, is not PEM, or holds no CERTIFICATE block (the
//     certificate file) or no private key block (the key file), then ReadCertificate shall return
//     ErrTLSFileNotPEM.
//   - If the key is protected by a passphrase, then ReadCertificate shall return
//     ErrKeyPassphrase.
//   - If the key is not RSA of 2048 bits or more, ECDSA P-256 or P-384, or Ed25519, then
//     ReadCertificate shall return ErrKeyType.
//   - If the key does not match the certificate, then ReadCertificate shall return
//     ErrKeyMismatch.
//   - ReadCertificate shall return an error whose text names the file it is about, the
//     certificate file or the key file, and holds no part of either file's contents.
//   - ReadCertificate shall read at most TLSFileMostBytes and one byte more from each file.
//     [read]
//   - ReadCertificate shall keep no file open once it returns. [read]
func ReadCertificate(certificatePath, keyPath string) (*Certificate, error) {
	return readCertificate(certificatePath, keyPath)
}

// Accept makes one accepted TCP connection Telnet over TLS's object for the shared execution
// path: it makes the TLS handshake with certificate, by the TLS table, and then returns the Line
// telnet.Open makes over the encrypted connection, whichever Outcome negotiation ends with. TLS
// starts with the first byte on the connection: there is no plain Telnet before it. The
// encrypted connection is Telnet's Conn: its WriteUrgent writes every byte as an ordinary byte,
// and its CloseWrite sends close_notify and then shuts down the TCP connection's sending side. On
// an error it returns a nil Line.
//
//   - Accept shall write nothing to the connection but the TLS handshake until the handshake
//     completes.
//   - If the handshake fails, then Accept shall return ErrHandshakeFailed and a nil Line, having
//     written no Telnet byte to the connection.
//   - If the context ends before the handshake completes, then Accept shall return
//     ErrDeadlineEnded, which also matches the context's error through errors.Is, and a nil Line,
//     having written no Telnet byte to the connection.
//   - When the handshake completes, Accept shall call telnet.Open once over the encrypted
//     connection, under the same context, so that negotiation, its 3 seconds and its eight
//     opening requests start only then, and return its Line, or a nil Line and Open's error.
//   - When the engine sends a Synch on a Line Accept made, the caller shall receive IAC DM inside
//     the encrypted stream, DM as an ordinary byte, and the engine shall send no TCP urgent data
//     on the connection.
//   - When the Line's Close shuts down the sending side, the encrypted connection shall send
//     close_notify, and then shut down the TCP connection's sending side.
//   - Once a write on the encrypted connection has failed, its CloseWrite shall send no
//     close_notify, and only shut down the TCP connection's sending side.
//   - While close_notify's write waits for room, a passed write deadline shall wake it, as it
//     wakes every other write.
//   - When the caller sends close_notify, the encrypted connection's reads shall end with end of
//     file; when it sends a damaged record, they shall end with a failure.
//   - If connection is nil, or certificate was not made by ReadCertificate or is nil, then Accept
//     shall return telnet.ErrConnectionFailed and a nil Line without touching the connection.
//   - Accept shall return no error that holds crypto/tls's text. [read]
func Accept(
	ctx context.Context, connection *net.TCPConn, certificate *Certificate,
) (*telnet.Line, error) {
	return accept(ctx, connection, certificate)
}
