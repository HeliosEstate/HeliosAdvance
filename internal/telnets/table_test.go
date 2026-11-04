// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package telnets_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/telnets"
	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// served is one listener serveAll started. Beside its address and Accept's results it keeps when
// it began and, for each connection, when the listener accepted it and when its Accept returned,
// so a row whose Accept never returns can show which connection stopped, and where.
type served struct {
	address     string
	results     <-chan accepted
	began       time.Time
	mutex       sync.Mutex
	connections []connectionTimes
}

// connectionTimes is one connection's two moments; returned is zero while its Accept runs.
type connectionTimes struct {
	accepted, returned time.Time
}

// serveAll listens on loopback at a port the operating system picks and hands every connection to
// Accept on its own goroutine, closing the connection once Accept returns, as the shared execution
// path does after a failure; each result arrives on the server's channel.
func serveAll(t *testing.T, certificate *telnets.Certificate) *served {
	t.Helper()
	listening, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on loopback: %v", err)
	}
	t.Cleanup(func() { _ = listening.Close() })
	results := make(chan accepted, 64)
	server := &served{address: listening.Addr().String(), results: results, began: time.Now()}
	go func() {
		for {
			connection, err := listening.Accept()
			if err != nil {
				return
			}
			server.mutex.Lock()
			index := len(server.connections)
			server.connections = append(server.connections, connectionTimes{accepted: time.Now()})
			server.mutex.Unlock()
			tcp, isTCP := connection.(*net.TCPConn)
			if !isTCP {
				_ = connection.Close()
				continue
			}
			go func() {
				ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), testrun.Patient(testrun.HangBound))
				defer cancel()
				line, err := telnets.Accept(ctx, tcp, certificate)
				returned := time.Now()
				server.mutex.Lock()
				server.connections[index].returned = returned
				server.mutex.Unlock()
				results <- accepted{line: line, err: err, returned: returned}
				_ = tcp.Close()
			}()
		}
	}()
	return server
}

// awaitAccept waits for the next Accept to return, by the hang bound. A row that fails here says
// when the listener began, accepted each connection and saw its Accept return, and what s_client
// printed and when, every time from the wait's start: a machine too slow to start s_client or to
// connect is told from a handshake that began and stalled.
func (server *served) awaitAccept(t *testing.T, client *sClient) accepted {
	t.Helper()
	waited := time.Now()
	return waitAcceptedTelling(t, server.results, waited.Add(testrun.Patient(testrun.HangBound)), func() string {
		return server.describe(waited) + "\n" + client.describe(waited)
	})
}

// describe gives the listener's moments, every time from since.
func (server *served) describe(since time.Time) string {
	server.mutex.Lock()
	defer server.mutex.Unlock()
	connections := make([]string, 0, len(server.connections))
	for _, connection := range server.connections {
		ended := "its Accept had not returned"
		if !connection.returned.IsZero() {
			ended = "its Accept returned at " + offset(connection.returned, since)
		}
		connections = append(connections, offset(connection.accepted, since)+" ("+ended+")")
	}
	return "Times are from the wait's start. The listener began at " + offset(server.began, since) +
		"; it accepted connections at [" + strings.Join(connections, ", ") + "]."
}

// certificateKind is the certificate a case is served with.
type certificateKind struct {
	name string
	key  keyKind
}

var (
	ecdsaCertificate   = certificateKind{"an ECDSA certificate", ecdsaP256}
	rsaCertificate     = certificateKind{"an RSA certificate", rsa2048}
	ed25519Certificate = certificateKind{"an Ed25519 certificate", ed25519Key}
)

// tableCase is one handshake s_client offers, its options as typed after the address: taken with
// the protocol, cipher and key exchange given, or refused with the alert given.
type tableCase struct {
	name                    string
	certificate             certificateKind
	options                 string
	protocol, cipher, group string
	refused                 string
}

// The protocols and the alert the table's rows expect, as s_client words them.
const (
	versionTLS13     = "TLSv1.3"
	versionTLS12     = "TLSv1.2"
	handshakeFailure = "handshake_failure"
)

// ecdsaSuiteOffer is the one offer the table makes against an ECDSA, an Ed25519 and an RSA
// certificate.
const ecdsaSuiteOffer = "-tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256"

// tableCases are the TLS table's rows as s_client offers them, every version, suite and key
// exchange it names taken and those around it refused. A TLS 1.2 key exchange is offered beside
// an RSA certificate, since in TLS 1.2 an ECDSA certificate's own curve must be among the
// caller's.
var tableCases = []tableCase{
	{name: "-tls1_3: taken", certificate: ecdsaCertificate, options: "-tls1_3", protocol: versionTLS13},
	{name: "-tls1_2: taken", certificate: ecdsaCertificate, options: "-tls1_2", protocol: versionTLS12},
	{name: "-tls1_1 at security level 0: refused with protocol_version, nothing else written", certificate: ecdsaCertificate,
		options: "-tls1_1 -cipher DEFAULT:@SECLEVEL=0", refused: "protocol_version"},
	{name: "-tls1 at security level 0: refused with protocol_version, nothing else written", certificate: ecdsaCertificate,
		options: "-tls1 -cipher DEFAULT:@SECLEVEL=0", refused: "protocol_version"},

	{name: "TLS 1.3, TLS_AES_128_GCM_SHA256: taken", certificate: ecdsaCertificate,
		options: "-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256", protocol: versionTLS13, cipher: "TLS_AES_128_GCM_SHA256"},
	{name: "TLS 1.3, TLS_AES_256_GCM_SHA384: taken", certificate: ecdsaCertificate,
		options: "-tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384", protocol: versionTLS13, cipher: "TLS_AES_256_GCM_SHA384"},
	{name: "TLS 1.3, TLS_CHACHA20_POLY1305_SHA256: taken", certificate: ecdsaCertificate,
		options: "-tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256", protocol: versionTLS13, cipher: "TLS_CHACHA20_POLY1305_SHA256"},
	{name: "TLS 1.3, TLS_AES_128_CCM_SHA256: refused with handshake_failure", certificate: ecdsaCertificate,
		options: "-tls1_3 -ciphersuites TLS_AES_128_CCM_SHA256", refused: handshakeFailure},
	{name: "TLS 1.3, TLS_AES_128_CCM_8_SHA256: refused with handshake_failure", certificate: ecdsaCertificate,
		options: "-tls1_3 -ciphersuites TLS_AES_128_CCM_8_SHA256 -cipher DEFAULT:@SECLEVEL=0", refused: handshakeFailure},

	{name: "TLS 1.2, ECDHE-ECDSA-AES128-GCM-SHA256 with an ECDSA certificate: taken", certificate: ecdsaCertificate,
		options: ecdsaSuiteOffer, protocol: versionTLS12, cipher: "ECDHE-ECDSA-AES128-GCM-SHA256"},
	{name: "TLS 1.2, ECDHE-ECDSA-AES256-GCM-SHA384 with an ECDSA certificate: taken", certificate: ecdsaCertificate,
		options: "-tls1_2 -cipher ECDHE-ECDSA-AES256-GCM-SHA384", protocol: versionTLS12, cipher: "ECDHE-ECDSA-AES256-GCM-SHA384"},
	{name: "TLS 1.2, ECDHE-ECDSA-CHACHA20-POLY1305 with an ECDSA certificate: taken", certificate: ecdsaCertificate,
		options: "-tls1_2 -cipher ECDHE-ECDSA-CHACHA20-POLY1305", protocol: versionTLS12, cipher: "ECDHE-ECDSA-CHACHA20-POLY1305"},
	{name: "TLS 1.2, ECDHE-RSA-AES128-GCM-SHA256 with an RSA certificate: taken", certificate: rsaCertificate,
		options: "-tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256", protocol: versionTLS12, cipher: "ECDHE-RSA-AES128-GCM-SHA256"},
	{name: "TLS 1.2, ECDHE-RSA-AES256-GCM-SHA384 with an RSA certificate: taken", certificate: rsaCertificate,
		options: "-tls1_2 -cipher ECDHE-RSA-AES256-GCM-SHA384", protocol: versionTLS12, cipher: "ECDHE-RSA-AES256-GCM-SHA384"},
	{name: "TLS 1.2, ECDHE-RSA-CHACHA20-POLY1305 with an RSA certificate: taken", certificate: rsaCertificate,
		options: "-tls1_2 -cipher ECDHE-RSA-CHACHA20-POLY1305", protocol: versionTLS12, cipher: "ECDHE-RSA-CHACHA20-POLY1305"},
	{name: "TLS 1.2, ECDHE-ECDSA-AES128-GCM-SHA256 with an Ed25519 certificate: taken", certificate: ed25519Certificate,
		options: ecdsaSuiteOffer, protocol: versionTLS12, cipher: "ECDHE-ECDSA-AES128-GCM-SHA256"},
	{name: "TLS 1.2, CBC ECDHE-ECDSA-AES128-SHA with an ECDSA certificate: refused with handshake_failure", certificate: ecdsaCertificate,
		options: "-tls1_2 -cipher ECDHE-ECDSA-AES128-SHA", refused: handshakeFailure},
	{name: "TLS 1.2, CBC ECDHE-ECDSA-AES256-SHA with an ECDSA certificate: refused with handshake_failure", certificate: ecdsaCertificate,
		options: "-tls1_2 -cipher ECDHE-ECDSA-AES256-SHA", refused: handshakeFailure},
	{name: "TLS 1.2, CBC ECDHE-RSA-AES128-SHA with an RSA certificate: refused with handshake_failure", certificate: rsaCertificate,
		options: "-tls1_2 -cipher ECDHE-RSA-AES128-SHA", refused: handshakeFailure},
	{name: "TLS 1.2, CBC ECDHE-RSA-AES256-SHA with an RSA certificate: refused with handshake_failure", certificate: rsaCertificate,
		options: "-tls1_2 -cipher ECDHE-RSA-AES256-SHA", refused: handshakeFailure},
	{name: "TLS 1.2, CBC ECDHE-RSA-AES128-SHA256 with an RSA certificate: refused with handshake_failure", certificate: rsaCertificate,
		options: "-tls1_2 -cipher ECDHE-RSA-AES128-SHA256", refused: handshakeFailure},
	{name: "TLS 1.2, RSA key exchange AES128-GCM-SHA256: refused with handshake_failure", certificate: rsaCertificate,
		options: "-tls1_2 -cipher AES128-GCM-SHA256", refused: handshakeFailure},
	{name: "TLS 1.2, DHE-RSA-AES128-GCM-SHA256: refused with handshake_failure", certificate: rsaCertificate,
		options: "-tls1_2 -cipher DHE-RSA-AES128-GCM-SHA256", refused: handshakeFailure},
	{name: "TLS 1.2, ECDHE-ECDSA-AES128-GCM-SHA256 with an RSA certificate: refused with handshake_failure", certificate: rsaCertificate,
		options: ecdsaSuiteOffer, refused: handshakeFailure},

	{name: "TLS 1.3, X25519MLKEM768: taken", certificate: ecdsaCertificate, options: "-tls1_3 -groups X25519MLKEM768", protocol: versionTLS13, group: "X25519MLKEM768"},
	{name: "TLS 1.3, SecP256r1MLKEM768: taken", certificate: ecdsaCertificate, options: "-tls1_3 -groups SecP256r1MLKEM768", protocol: versionTLS13, group: "SecP256r1MLKEM768"},
	{name: "TLS 1.3, SecP384r1MLKEM1024: taken", certificate: ecdsaCertificate, options: "-tls1_3 -groups SecP384r1MLKEM1024", protocol: versionTLS13, group: "SecP384r1MLKEM1024"},
	{name: "TLS 1.3, X25519: taken", certificate: ecdsaCertificate, options: "-tls1_3 -groups X25519", protocol: versionTLS13, group: "X25519"},
	{name: "TLS 1.3, P-256: taken", certificate: ecdsaCertificate, options: "-tls1_3 -groups P-256", protocol: versionTLS13, group: curveP256},
	{name: "TLS 1.3, P-384: taken", certificate: ecdsaCertificate, options: "-tls1_3 -groups P-384", protocol: versionTLS13, group: curveP384},
	{name: "TLS 1.3, P-521: taken", certificate: ecdsaCertificate, options: "-tls1_3 -groups P-521", protocol: versionTLS13, group: curveP521},
	{name: "TLS 1.2, X25519: taken", certificate: rsaCertificate, options: "-tls1_2 -groups X25519", protocol: versionTLS12, group: "X25519"},
	{name: "TLS 1.2, P-256: taken", certificate: rsaCertificate, options: "-tls1_2 -groups P-256", protocol: versionTLS12, group: curveP256},
	{name: "TLS 1.2, P-384: taken", certificate: rsaCertificate, options: "-tls1_2 -groups P-384", protocol: versionTLS12, group: curveP384},
	{name: "TLS 1.2, P-521: taken", certificate: rsaCertificate, options: "-tls1_2 -groups P-521", protocol: versionTLS12, group: curveP521},
	{name: "TLS 1.3, X448: refused with handshake_failure", certificate: ecdsaCertificate, options: "-tls1_3 -groups X448", refused: handshakeFailure},
	{name: "TLS 1.3, ffdhe2048: refused with handshake_failure", certificate: ecdsaCertificate, options: "-tls1_3 -groups ffdhe2048", refused: handshakeFailure},
	{name: "TLS 1.3, brainpoolP256r1tls13: refused with handshake_failure", certificate: ecdsaCertificate, options: "-tls1_3 -groups brainpoolP256r1tls13", refused: handshakeFailure},
	{name: "TLS 1.3, pure MLKEM768: refused with handshake_failure", certificate: ecdsaCertificate, options: "-tls1_3 -groups MLKEM768", refused: handshakeFailure},
	{name: "TLS 1.3, pure MLKEM1024: refused with handshake_failure", certificate: ecdsaCertificate, options: "-tls1_3 -groups MLKEM1024", refused: handshakeFailure},
	{name: "TLS 1.2, X448: refused with handshake_failure", certificate: rsaCertificate, options: "-tls1_2 -groups X448", refused: handshakeFailure},
	{name: "TLS 1.2, ffdhe2048: refused with handshake_failure", certificate: rsaCertificate, options: "-tls1_2 -groups ffdhe2048", refused: handshakeFailure},
}

// shownCertificate is a certificate s_client prints with -showcerts.
var shownCertificate = regexp.MustCompile(`(?s)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----`)

// shownChain is the DER of each certificate s_client printed, in order.
func shownChain(t *testing.T, text string) [][]byte {
	t.Helper()
	var chain [][]byte
	for _, match := range shownCertificate.FindAllString(text, -1) {
		block, _ := pem.Decode([]byte(match))
		if block == nil {
			t.Fatalf("s_client printed a certificate that is not PEM:\n%s", match)
		}
		chain = append(chain, block.Bytes)
	}
	return chain
}

func TestTLSTable(t *testing.T) {
	t.Parallel()

	t.Run("With none of Go's own settings in force, the telnets package shall offer, in every handshake, only what the TLS table names.", func(t *testing.T) {
		t.Parallel()
		for _, row := range tableCases {
			t.Run(row.name+", against "+row.certificate.name, func(t *testing.T) {
				t.Parallel()
				server := serveAll(t, readCertificate(t, goodFiles(t, row.certificate.key)))
				client := startSClient(t, server.address, strings.Fields(row.options)...)
				got := server.awaitAccept(t, client)
				seen := readHandshake(client.finish(t))
				if row.refused != "" {
					expectRefusedWith(t, seen, row.refused)
					if !errors.Is(got.err, telnets.ErrHandshakeFailed) || got.line != nil {
						t.Fatalf("Accept gave %v and %v, want no Line and ErrHandshakeFailed", got.line, got.err)
					}
					return
				}
				expectTaken(t, seen, row.protocol, row.cipher, row.group)
				if got.line == nil {
					t.Fatalf("Accept gave %v where the handshake completed, want a Line", got.err)
				}
			})
		}
		for _, version := range []string{"-tls1_3", "-tls1_2"} {
			t.Run(version+": the certificate file's whole chain, a leaf and an intermediate, sent in the file's order, byte for byte", func(t *testing.T) {
				t.Parallel()
				made := makeChain(t)
				server := serveAll(t, readCertificate(t, made.files))
				client := startSClient(t, server.address, version, "-showcerts")
				server.awaitAccept(t, client)
				text := client.finish(t)
				chain := shownChain(t, text)
				if len(chain) != 2 || !bytes.Equal(chain[0], made.leaf) || !bytes.Equal(chain[1], made.intermediate) {
					t.Fatalf("s_client received %d certificates, want the leaf, then the intermediate, as the file holds them:\n%s", len(chain), text)
				}
			})
			t.Run(version+": no CertificateRequest, so no client certificate is asked for", func(t *testing.T) {
				t.Parallel()
				server := serveAll(t, readCertificate(t, goodFiles(t, ecdsaP256)))
				client := startSClient(t, server.address, version)
				server.awaitAccept(t, client)
				seen := readHandshake(client.finish(t))
				expectTaken(t, seen, "TLSv1."+strings.TrimPrefix(version, "-tls1_"), "", "")
				for _, message := range seen.serverMessages {
					if message == "CertificateRequest" {
						t.Fatalf("the engine asked for a client certificate:\n%s", seen.text)
					}
				}
			})
			t.Run(version+", with -reconnect: every one of the six handshakes New, no NewSessionTicket, and no session ID", func(t *testing.T) {
				t.Parallel()
				server := serveAll(t, readCertificate(t, goodFiles(t, ecdsaP256)))
				client := startSClient(t, server.address, version, "-reconnect")
				for range 6 {
					server.awaitAccept(t, client)
				}
				text := client.finish(t)
				if count := strings.Count(text, "\nNew, TLSv1."); count != 6 || strings.Contains(text, "Reused, ") {
					t.Fatalf("s_client saw %d new handshakes of six, or a session resumed:\n%s", count, text)
				}
				if strings.Contains(text, "NewSessionTicket") {
					t.Fatalf("the engine issued a session ticket:\n%s", text)
				}
				if regexp.MustCompile(`(?m)^[ \t]*Session-ID:[ \t]*[0-9A-Fa-f]`).MatchString(text) {
					t.Fatalf("the engine issued a session ID:\n%s", text)
				}
			})
		}
		t.Run("TLS 1.2, a renegotiation asked for with s_client's R: refused with a fatal unexpected_message, and the connection ends", func(t *testing.T) {
			t.Parallel()
			server := serveAll(t, readCertificate(t, goodFiles(t, ecdsaP256)))
			client := startSClientCommands(t, server.address, "-tls1_2")
			client.waitFor(t, "New, TLSv1.2", time.Now().Add(testrun.Patient(testrun.HangBound)))
			client.send(t, "R\n")
			got := server.awaitAccept(t, client)
			seen := readHandshake(client.finish(t))
			if !strings.Contains(seen.text, "RENEGOTIATING") || !strings.Contains(seen.text, "fatal unexpected_message") {
				t.Fatalf("s_client did not see its renegotiation refused with unexpected_message:\n%s", seen.text)
			}
			if got.line != nil || got.err == nil {
				t.Fatalf("Accept gave %v and %v after a renegotiation during negotiation, want no Line and an error", got.line, got.err)
			}
		})
	})
}
