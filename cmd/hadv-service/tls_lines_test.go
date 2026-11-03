// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The program's lines for Telnet over TLS: the certificate, key and port options, the refusals
// they bring, the TLS table as s_client sees it, the call served inside the channel and how it
// ends, and the earlier lines that stand for a Telnet over TLS caller as for a Telnet one, each
// driven from outside through the built program.
package main_test

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// Telnet's commands Part 4's lines name, from RFC 854, and the 70-second ceiling on a call.
const (
	areYouThere      byte = 246
	abortOutput      byte = 245
	interruptProcess byte = 244
	dataMark         byte = 242
	backspace        byte = 8

	callCeiling = 70 * time.Second
)

// aytAnswer is the answer to AYT Part 4's line gives.
const aytAnswer = "\r\n[Yes]\r\n"

// threeKinds sorts a started line's listeners into Telnet's, SSH's and Telnet over TLS's
// addresses; anything else in the line fails the row.
func threeKinds(t *testing.T, listeners []string) (telnet, ssh, telnets []string) {
	t.Helper()
	for _, listener := range listeners {
		switch {
		case strings.HasPrefix(listener, "telnet://"):
			telnet = append(telnet, strings.TrimPrefix(listener, "telnet://"))
		case strings.HasPrefix(listener, "ssh://"):
			ssh = append(ssh, strings.TrimPrefix(listener, "ssh://"))
		case strings.HasPrefix(listener, "telnets://"):
			telnets = append(telnets, strings.TrimPrefix(listener, "telnets://"))
		default:
			t.Fatalf("the started line names %q, which is not a telnet://, ssh:// or telnets:// listener", listener)
		}
	}
	return telnet, ssh, telnets
}

// startTLS starts the program with Telnet over TLS on with the files, at ports the system picks,
// and returns it and the two Telnet over TLS addresses its started line names.
func startTLS(t *testing.T, files tlsFiles, extra ...string) (*run, []string) {
	t.Helper()
	program := startProgram(t, files.options(extra...)...)
	_, _, telnets := threeKinds(t, program.listeners(t))
	loopbackPorts(t, telnets)
	return program, telnets
}

// expectTLSStarts is the edge every Telnet over TLS refusal row ends with: the same program,
// given good files and ports the system picks, listens for Telnet over TLS at both addresses and
// completes a caller's handshake there, so the refusal before it was for what the row changed.
func expectTLSStarts(t *testing.T) {
	t.Helper()
	_, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
	expectTLSServed(t, telnets[0])
}

// defaultTLSPortRow is the row for port 992 by default. The program listens for Telnet over TLS
// at every address where 992 opened just before; where it opened at neither, because something
// else holds it or the system keeps it from an ordinary user, the program refuses to start, while
// the same command with a TLS port the system picks starts.
func defaultTLSPortRow(t *testing.T) {
	t.Helper()
	files := goodTLSFiles(t, tlsP256)
	free := opensAt(t, "992")
	program := startProgram(t, portOption, "0", tlsCertificateOption, files.certificate, tlsKeyOption, files.key)
	if len(free) > 0 {
		_, _, telnets := threeKinds(t, program.listeners(t))
		expectAddresses(t, telnets, free...)
		for _, address := range telnets {
			expectTLSServed(t, address)
		}
		// Stopped here, inside the row's hold on port 992, not at the row's cleanup after it.
		_ = program.command.Process.Kill()
		<-program.exited
		return
	}
	program.expectRefusal(t)
	expectTLSStarts(t)
}

// expectFileRefused checks a program started with Telnet over TLS options refuses to start for
// its files, not as a malformed command line, and that good files then start.
func expectFileRefused(t *testing.T, program *run) {
	t.Helper()
	if reason := program.expectRefusal(t); reason == malformedReason(t) {
		t.Fatalf("the program refused the files as a malformed command line: %q", reason)
	}
	expectTLSStarts(t)
}

// tlsReason is the reason the program gives when it refuses the files, which must differ from a
// malformed command line's: the options were read, and a file refused.
func tlsReason(t *testing.T, files tlsFiles) string {
	t.Helper()
	reason := startProgram(t, files.options()...).expectRefusal(t)
	if reason == malformedReason(t) {
		t.Fatalf("the program refused the files as a malformed command line: %q", reason)
	}
	expectTLSStarts(t)
	return reason
}

// absentPath is a path in a folder of its own at which nothing is.
func absentPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "absent.pem")
}

// The two values of which, as the rows name the files.
const (
	certificateFile = "certificate"
	keyFile         = "key"
)

// replacedFile is the files with the one named by which, certificateFile or keyFile, at path
// instead.
func replacedFile(files tlsFiles, which, path string) tlsFiles {
	if which == certificateFile {
		files.certificate = path
	} else {
		files.key = path
	}
	return files
}

// chosenFile is the path of the file named by which.
func chosenFile(files tlsFiles, which string) string {
	if which == certificateFile {
		return files.certificate
	}
	return files.key
}

// helloCatcher takes a crypto/tls client's first flight and fails every read, so the client
// stops after its ClientHello.
type helloCatcher struct {
	net.Conn
	written []byte
}

func (catcher *helloCatcher) Write(buffer []byte) (int, error) {
	catcher.written = append(catcher.written, buffer...)
	return len(buffer), nil
}

func (*helloCatcher) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// clientHello is the ClientHello a crypto/tls client offering TLS 1.2 up to the version given
// sends first.
func clientHello(t *testing.T, maximum uint16) []byte {
	t.Helper()
	catcher := &helloCatcher{}
	config := &tls.Config{ServerName: "localhost", MinVersion: tls.VersionTLS12, MaxVersion: maximum}
	_ = tls.Client(catcher, config).HandshakeContext(t.Context())
	if len(catcher.written) < 11 || catcher.written[0] != handshakeRecord {
		t.Fatalf("a fault in the test: the client's first flight is % x", catcher.written)
	}
	return catcher.written
}

// tls11Hello is the TLS 1.1 ClientHello s_client sends, caught on a listener of the test's own: a
// crypto/tls client puts supported_versions in every hello, so no hello of its own is TLS 1.1.
func tls11Hello(t *testing.T) []byte {
	t.Helper()
	listening, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on loopback: %v", err)
	}
	defer func() { _ = listening.Close() }()
	client := startSClient(t, listening.Addr().String(), "-tls1_1", "-cipher", "DEFAULT:@SECLEVEL=0")
	defer client.stop()
	accepted, err := listening.Accept()
	if err != nil {
		t.Fatalf("accepting s_client: %v", err)
	}
	defer func() { _ = accepted.Close() }()
	_ = accepted.SetReadDeadline(time.Now().Add(testrun.Patient(testrun.HangBound)))
	header := make([]byte, 5)
	if _, err := io.ReadFull(accepted, header); err != nil || header[0] != handshakeRecord {
		t.Fatalf("a fault in the test: s_client's first record began % x (%v)", header, err)
	}
	body := make([]byte, int(header[3])<<8|int(header[4]))
	if _, err := io.ReadFull(accepted, body); err != nil || len(body) < 6 || body[4] != 3 || body[5] != 2 {
		t.Fatalf("a fault in the test: s_client's ClientHello is not TLS 1.1: % x (%v)", body, err)
	}
	return append(header, body...)
}

// expectAtMostAlertThenEnd reads the raw connection until the engine ends it, which must come by
// the deadline, and checks what arrived is at most one whole alert record: no Telnet byte. It
// returns when the end came.
func expectAtMostAlertThenEnd(t *testing.T, call caller, deadline time.Time) time.Time {
	t.Helper()
	received, err := readAll(call, deadline)
	ended := time.Now()
	if !isEnd(err) {
		t.Fatalf("the caller's read ended with %v, want the engine's close by the deadline; it got % x", err, received)
	}
	types, trailing := recordTypes(received)
	if trailing != 0 || len(types) > 1 || (len(types) == 1 && types[0] != alertRecord) {
		t.Fatalf("the caller received % x, want at most one alert record", received)
	}
	return ended
}

// echoedName is what a caller who agreed to ECHO receives after the prompt for a name typed
// whole and ended by CR: the name, CR LF, then Hello and the name.
func echoedName(name string) []byte {
	return []byte(name + "\r\n" + reply + name + "\r\n")
}

// answeredTLS is a TLS caller over the version given that has answered the eight requests and
// read the greeting and the prompt: the call stands at its name.
func answeredTLS(t *testing.T, address string, version uint16) tlsCaller {
	t.Helper()
	call := dialTLS(t, address, tlsConfig(version))
	call.readExactly(t, opening, time.Now().Add(testrun.Patient(margin)))
	call.send(t, answers)
	call.readExactly(t, []byte(greeting+prompt), time.Now().Add(testrun.Patient(margin)))
	return call
}

// expectClosedInChannel reads inside the channel until it ends, by the deadline, and checks it
// ended with close_notify's end of file and nothing more came.
func (call tlsCaller) expectClosedInChannel(t *testing.T, deadline time.Time) {
	t.Helper()
	received, err := call.readToEnd(deadline)
	if len(received) != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("the caller read %q and %v, want close_notify's end at once", received, err)
	}
}

// tlsVersions are the two the TLS table offers, as QA's caller asks for each.
var tlsVersions = []struct {
	name string
	id   uint16
}{{"TLS 1.3", tls.VersionTLS13}, {"TLS 1.2", tls.VersionTLS12}}

// sClientVersions are the same two, as s_client's options ask for each.
var sClientVersions = []string{"-tls1_3", "-tls1_2"}

// programTableCase is one handshake s_client offers the program, its options as typed after the
// address: taken with the protocol, cipher and key exchange given, or refused with the alert
// given.
type programTableCase struct {
	name                    string
	key                     tlsKeyKind
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

// The TLS table's rows as s_client offers them. A TLS 1.2 key exchange is offered beside an RSA
// certificate, since in TLS 1.2 an ECDSA certificate's own curve must be among the caller's.
var (
	versionCases = []programTableCase{
		{name: "-tls1_3: taken", key: tlsP256, options: "-tls1_3", protocol: versionTLS13},
		{name: "-tls1_2: taken", key: tlsP256, options: "-tls1_2", protocol: versionTLS12},
		{name: "-tls1_1 at security level 0: refused with protocol_version, nothing else written", key: tlsP256,
			options: "-tls1_1 -cipher DEFAULT:@SECLEVEL=0", refused: "protocol_version"},
		{name: "-tls1 at security level 0: refused with protocol_version, nothing else written", key: tlsP256,
			options: "-tls1 -cipher DEFAULT:@SECLEVEL=0", refused: "protocol_version"},
	}
	suiteCases = []programTableCase{
		{name: "TLS 1.3, TLS_AES_128_GCM_SHA256: taken", key: tlsP256, options: "-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256", protocol: versionTLS13, cipher: "TLS_AES_128_GCM_SHA256"},
		{name: "TLS 1.3, TLS_AES_256_GCM_SHA384: taken", key: tlsP256, options: "-tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384", protocol: versionTLS13, cipher: "TLS_AES_256_GCM_SHA384"},
		{name: "TLS 1.3, TLS_CHACHA20_POLY1305_SHA256: taken", key: tlsP256, options: "-tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256", protocol: versionTLS13, cipher: "TLS_CHACHA20_POLY1305_SHA256"},
		{name: "TLS 1.3, TLS_AES_128_CCM_SHA256: refused with handshake_failure", key: tlsP256, options: "-tls1_3 -ciphersuites TLS_AES_128_CCM_SHA256", refused: handshakeFailure},
		{name: "TLS 1.3, TLS_AES_128_CCM_8_SHA256 at security level 0: refused with handshake_failure", key: tlsP256,
			options: "-tls1_3 -ciphersuites TLS_AES_128_CCM_8_SHA256 -cipher DEFAULT:@SECLEVEL=0", refused: handshakeFailure},
		{name: "TLS 1.2, ECDHE-ECDSA-AES128-GCM-SHA256 with an ECDSA certificate: taken", key: tlsP256, options: ecdsaSuiteOffer, protocol: versionTLS12, cipher: "ECDHE-ECDSA-AES128-GCM-SHA256"},
		{name: "TLS 1.2, ECDHE-ECDSA-AES256-GCM-SHA384 with an ECDSA certificate: taken", key: tlsP256, options: "-tls1_2 -cipher ECDHE-ECDSA-AES256-GCM-SHA384", protocol: versionTLS12, cipher: "ECDHE-ECDSA-AES256-GCM-SHA384"},
		{name: "TLS 1.2, ECDHE-ECDSA-CHACHA20-POLY1305 with an ECDSA certificate: taken", key: tlsP256, options: "-tls1_2 -cipher ECDHE-ECDSA-CHACHA20-POLY1305", protocol: versionTLS12, cipher: "ECDHE-ECDSA-CHACHA20-POLY1305"},
		{name: "TLS 1.2, ECDHE-RSA-AES128-GCM-SHA256 with an RSA certificate: taken", key: tlsRSA2048, options: "-tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256", protocol: versionTLS12, cipher: "ECDHE-RSA-AES128-GCM-SHA256"},
		{name: "TLS 1.2, ECDHE-RSA-AES256-GCM-SHA384 with an RSA certificate: taken", key: tlsRSA2048, options: "-tls1_2 -cipher ECDHE-RSA-AES256-GCM-SHA384", protocol: versionTLS12, cipher: "ECDHE-RSA-AES256-GCM-SHA384"},
		{name: "TLS 1.2, ECDHE-RSA-CHACHA20-POLY1305 with an RSA certificate: taken", key: tlsRSA2048, options: "-tls1_2 -cipher ECDHE-RSA-CHACHA20-POLY1305", protocol: versionTLS12, cipher: "ECDHE-RSA-CHACHA20-POLY1305"},
		{name: "TLS 1.2, ECDHE-ECDSA-AES128-GCM-SHA256 with an Ed25519 certificate: taken", key: tlsEd25519, options: ecdsaSuiteOffer, protocol: versionTLS12, cipher: "ECDHE-ECDSA-AES128-GCM-SHA256"},
		{name: "TLS 1.2, CBC ECDHE-ECDSA-AES128-SHA with an ECDSA certificate: refused with handshake_failure", key: tlsP256, options: "-tls1_2 -cipher ECDHE-ECDSA-AES128-SHA", refused: handshakeFailure},
		{name: "TLS 1.2, CBC ECDHE-ECDSA-AES256-SHA with an ECDSA certificate: refused with handshake_failure", key: tlsP256, options: "-tls1_2 -cipher ECDHE-ECDSA-AES256-SHA", refused: handshakeFailure},
		{name: "TLS 1.2, CBC ECDHE-RSA-AES128-SHA with an RSA certificate: refused with handshake_failure", key: tlsRSA2048, options: "-tls1_2 -cipher ECDHE-RSA-AES128-SHA", refused: handshakeFailure},
		{name: "TLS 1.2, CBC ECDHE-RSA-AES256-SHA with an RSA certificate: refused with handshake_failure", key: tlsRSA2048, options: "-tls1_2 -cipher ECDHE-RSA-AES256-SHA", refused: handshakeFailure},
		{name: "TLS 1.2, CBC ECDHE-RSA-AES128-SHA256 with an RSA certificate: refused with handshake_failure", key: tlsRSA2048, options: "-tls1_2 -cipher ECDHE-RSA-AES128-SHA256", refused: handshakeFailure},
		{name: "TLS 1.2, RSA key exchange AES128-GCM-SHA256: refused with handshake_failure", key: tlsRSA2048, options: "-tls1_2 -cipher AES128-GCM-SHA256", refused: handshakeFailure},
		{name: "TLS 1.2, DHE-RSA-AES128-GCM-SHA256: refused with handshake_failure", key: tlsRSA2048, options: "-tls1_2 -cipher DHE-RSA-AES128-GCM-SHA256", refused: handshakeFailure},
		{name: "TLS 1.2, ECDHE-ECDSA-AES128-GCM-SHA256 with an RSA certificate: refused with handshake_failure", key: tlsRSA2048, options: ecdsaSuiteOffer, refused: handshakeFailure},
	}
	groupCases = []programTableCase{
		{name: "TLS 1.3, X25519MLKEM768: taken", key: tlsP256, options: "-tls1_3 -groups X25519MLKEM768", protocol: versionTLS13, group: "X25519MLKEM768"},
		{name: "TLS 1.3, SecP256r1MLKEM768: taken", key: tlsP256, options: "-tls1_3 -groups SecP256r1MLKEM768", protocol: versionTLS13, group: "SecP256r1MLKEM768"},
		{name: "TLS 1.3, SecP384r1MLKEM1024: taken", key: tlsP256, options: "-tls1_3 -groups SecP384r1MLKEM1024", protocol: versionTLS13, group: "SecP384r1MLKEM1024"},
		{name: "TLS 1.3, X25519: taken", key: tlsP256, options: "-tls1_3 -groups X25519", protocol: versionTLS13, group: "X25519"},
		{name: "TLS 1.3, P-256: taken", key: tlsP256, options: "-tls1_3 -groups P-256", protocol: versionTLS13, group: curveP256},
		{name: "TLS 1.3, P-384: taken", key: tlsP256, options: "-tls1_3 -groups P-384", protocol: versionTLS13, group: curveP384},
		{name: "TLS 1.3, P-521: taken", key: tlsP256, options: "-tls1_3 -groups P-521", protocol: versionTLS13, group: curveP521},
		{name: "TLS 1.2, X25519 with an RSA certificate: taken", key: tlsRSA2048, options: "-tls1_2 -groups X25519", protocol: versionTLS12, group: "X25519"},
		{name: "TLS 1.2, P-256 with an RSA certificate: taken", key: tlsRSA2048, options: "-tls1_2 -groups P-256", protocol: versionTLS12, group: curveP256},
		{name: "TLS 1.2, P-384 with an RSA certificate: taken", key: tlsRSA2048, options: "-tls1_2 -groups P-384", protocol: versionTLS12, group: curveP384},
		{name: "TLS 1.2, P-521 with an RSA certificate: taken", key: tlsRSA2048, options: "-tls1_2 -groups P-521", protocol: versionTLS12, group: curveP521},
		{name: "TLS 1.3, X448: refused with handshake_failure", key: tlsP256, options: "-tls1_3 -groups X448", refused: handshakeFailure},
		{name: "TLS 1.3, ffdhe2048: refused with handshake_failure", key: tlsP256, options: "-tls1_3 -groups ffdhe2048", refused: handshakeFailure},
		{name: "TLS 1.3, brainpoolP256r1tls13: refused with handshake_failure", key: tlsP256, options: "-tls1_3 -groups brainpoolP256r1tls13", refused: handshakeFailure},
		{name: "TLS 1.3, pure MLKEM768: refused with handshake_failure", key: tlsP256, options: "-tls1_3 -groups MLKEM768", refused: handshakeFailure},
		{name: "TLS 1.3, pure MLKEM1024: refused with handshake_failure", key: tlsP256, options: "-tls1_3 -groups MLKEM1024", refused: handshakeFailure},
		{name: "TLS 1.2, X448 with an RSA certificate: refused with handshake_failure", key: tlsRSA2048, options: "-tls1_2 -groups X448", refused: handshakeFailure},
		{name: "TLS 1.2, ffdhe2048 with an RSA certificate: refused with handshake_failure", key: tlsRSA2048, options: "-tls1_2 -groups ffdhe2048", refused: handshakeFailure},
	}
)

// runTableCases runs each case against a program of its own, given a certificate of the case's
// key: s_client's view of the handshake must be the case's.
func runTableCases(t *testing.T, cases []programTableCase) {
	t.Helper()
	for _, row := range cases {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			_, telnets := startTLS(t, goodTLSFiles(t, row.key))
			seen := readHandshake(startSClient(t, telnets[0], strings.Fields(row.options)...).handshakeText(t))
			if row.refused != "" {
				expectRefusedWith(t, seen, row.refused)
				return
			}
			expectTaken(t, seen, row.protocol, row.cipher, row.group)
		})
	}
}

// shownCertificate is a certificate s_client prints with -showcerts.
var shownCertificate = regexp.MustCompile(`(?s)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----`)

func TestTLSProgram(t *testing.T) {
	t.Parallel()

	t.Run("When the sysop passes a Telnet over TLS port on the command line as well, the engine shall listen for Telnet over TLS callers on that port in place of port 992.", func(t *testing.T) {
		t.Parallel()
		t.Run("with -tls-port and a free port, it names and serves that port at both addresses, beside Telnet's and SSH's, the three kinds in one started line", func(t *testing.T) {
			t.Parallel()
			files := goodTLSFiles(t, tlsP256)
			key := makeKey(t, "ed25519", "")
			port, listeners := startOnFreedPort(t, []string{ipv4Loopback, ipv6Loopback}, func(port string) []string {
				return []string{portOption, "0", hostKeyOption, key, sshPortOption, "0",
					tlsCertificateOption, files.certificate, tlsKeyOption, files.key, tlsPortOption, port}
			})
			telnet, ssh, telnets := threeKinds(t, listeners)
			expectAddresses(t, telnets, net.JoinHostPort(ipv4Loopback, port), net.JoinHostPort(ipv6Loopback, port))
			loopbackPorts(t, telnet)
			loopbackPorts(t, ssh)
			for _, address := range telnets {
				expectTLSServed(t, address)
			}
			for _, address := range telnet {
				expectServed(t, address)
			}
			for _, address := range ssh {
				expectSSHServed(t, address)
			}
		})
		t.Run("with -tls-port 0, it names and serves a port the system picked at each address", func(t *testing.T) {
			t.Parallel()
			_, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
			for _, address := range telnets {
				expectTLSServed(t, address)
			}
		})
	})

	t.Run("If either file is missing, unreadable or not PEM, or the key is protected by a passphrase, does not match the certificate, or is not RSA of 2048 bits or more, ECDSA P-256 or P-384, or Ed25519, then the engine shall write one `start_failed` line saying which, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		type refusedFiles struct {
			name  string
			files func(t *testing.T) tlsFiles
		}
		onFile := func(which, name string, bad func(t *testing.T, files tlsFiles) string) refusedFiles {
			return refusedFiles{"the " + which + " file " + name, func(t *testing.T) tlsFiles {
				t.Helper()
				files := goodTLSFiles(t, tlsP256)
				return replacedFile(files, which, bad(t, files))
			}}
		}
		var cases []refusedFiles
		for _, which := range []string{certificateFile, keyFile} {
			cases = append(cases,
				onFile(which, "missing", func(t *testing.T, _ tlsFiles) string { t.Helper(); return absentPath(t) }),
				onFile(which, "unreadable", func(t *testing.T, files tlsFiles) string {
					t.Helper()
					path := chosenFile(files, which)
					keepTLSFileFromReading(t, path)
					return path
				}),
				onFile(which, "not PEM", func(t *testing.T, _ tlsFiles) string {
					t.Helper()
					return writeTLSFile(t, []byte(canary+" is not PEM\n"))
				}))
		}
		passphrase := refusedFiles{"a key protected by a passphrase, as PKCS#8", func(t *testing.T) tlsFiles {
			t.Helper()
			files := goodTLSFiles(t, tlsP256)
			files.key = encryptedKey(t, files.key, false)
			return files
		}}
		mismatch := refusedFiles{"a key that does not match, of the same type", func(t *testing.T) tlsFiles {
			t.Helper()
			return tlsFiles{certificate: goodTLSFiles(t, tlsP256).certificate, key: makeTLSKey(t, tlsP256)}
		}}
		wrongType := refusedFiles{"an RSA 1024 key", func(t *testing.T) tlsFiles { t.Helper(); return goodTLSFiles(t, tlsRSA1024) }}
		cases = append(cases, passphrase, mismatch, wrongType,
			refusedFiles{"a key protected by a passphrase, with the old PEM header", func(t *testing.T) tlsFiles {
				t.Helper()
				files := goodTLSFiles(t, tlsRSA2048)
				files.key = encryptedKey(t, files.key, true)
				return files
			}},
			refusedFiles{"a key that does not match, of another type", func(t *testing.T) tlsFiles {
				t.Helper()
				return tlsFiles{certificate: goodTLSFiles(t, tlsP256).certificate, key: makeTLSKey(t, tlsRSA2048)}
			}},
			refusedFiles{"an RSA 2047 key", func(t *testing.T) tlsFiles { t.Helper(); return goodTLSFiles(t, tlsRSA2047) }},
			refusedFiles{"an ECDSA P-521 key", func(t *testing.T) tlsFiles { t.Helper(); return goodTLSFiles(t, tlsP521) }},
			refusedFiles{"an RSA-PSS 2048 key", func(t *testing.T) tlsFiles { t.Helper(); return goodTLSFiles(t, tlsRSAPSS2048) }},
		)
		for _, refused := range cases {
			t.Run(refused.name+": one start_failed line and a non-zero exit, where good files start", func(t *testing.T) {
				t.Parallel()
				tlsReason(t, refused.files(t))
			})
		}
		t.Run("each refusal's reason its own, the certificate file's differing from the key file's for the same refusal", func(t *testing.T) {
			t.Parallel()
			distinct := append(append([]refusedFiles{}, cases[:6]...), passphrase, mismatch, wrongType)
			reasons := map[string]string{}
			var group sync.WaitGroup
			var mutex sync.Mutex
			for _, refused := range distinct {
				files := refused.files(t)
				group.Go(func() {
					reason := startProgram(t, files.options()...).expectRefusal(t)
					mutex.Lock()
					reasons[refused.name] = reason
					mutex.Unlock()
				})
			}
			group.Wait()
			for name, reason := range reasons {
				for other, otherReason := range reasons {
					if name != other && reason == otherReason {
						t.Fatalf("%s and %s gave the same reason, %q", name, other, reason)
					}
				}
			}
		})
		for _, kind := range []tlsKeyKind{tlsRSA2048, tlsRSA4096, tlsP256, tlsP384, tlsEd25519} {
			t.Run("the edge: "+kind.name+" with its own certificate starts, and serves a TLS caller at each address", func(t *testing.T) {
				t.Parallel()
				_, telnets := startTLS(t, goodTLSFiles(t, kind))
				for _, address := range telnets {
					expectTLSServed(t, address)
				}
			})
		}
	})

	t.Run("If a certificate block in the certificate file holds no certificate, the chain's later blocks included, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		notPEMReason := func(t *testing.T) string {
			t.Helper()
			files := goodTLSFiles(t, tlsP256)
			return tlsReason(t, tlsFiles{certificate: writeTLSFile(t, []byte(canary+" is not PEM\n")), key: files.key})
		}
		cases := []struct {
			name        string
			certificate func(t *testing.T, files tlsFiles) string
		}{
			{"the first CERTIFICATE block not a certificate", func(t *testing.T, files tlsFiles) string {
				t.Helper()
				return writePEMBlocks(t, notCertificate(), readPEMBlocks(t, files.certificate)[0])
			}},
			{"the second CERTIFICATE block not a certificate", func(t *testing.T, files tlsFiles) string {
				t.Helper()
				return writePEMBlocks(t, readPEMBlocks(t, files.certificate)[0], notCertificate())
			}},
			{"blocks of other types and no CERTIFICATE block", func(t *testing.T, files tlsFiles) string {
				t.Helper()
				return writePEMBlocks(t, &pem.Block{Type: "EC PARAMETERS", Bytes: []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}},
					&pem.Block{Type: "X509 CRL", Bytes: readPEMBlocks(t, files.certificate)[0].Bytes})
			}},
		}
		for _, row := range cases {
			t.Run(row.name+": one start_failed line, a non-zero exit, the reason the certificate file's not-PEM one", func(t *testing.T) {
				t.Parallel()
				files := goodTLSFiles(t, tlsP256)
				reason := tlsReason(t, tlsFiles{certificate: row.certificate(t, files), key: files.key})
				if want := notPEMReason(t); reason != want {
					t.Fatalf("the reason was %q, want the not-PEM certificate file's, %q", reason, want)
				}
			})
		}
		t.Run("a third CERTIFICATE block not a certificate, after a good chain of two: one start_failed line, a non-zero exit, the not-PEM reason", func(t *testing.T) {
			t.Parallel()
			chain := makeTLSChain(t)
			certificate := writePEMBlocks(t, certificateBlock(chain.leaf), certificateBlock(chain.intermediate), notCertificate())
			reason := tlsReason(t, tlsFiles{certificate: certificate, key: chain.files.key})
			if want := notPEMReason(t); reason != want {
				t.Fatalf("the reason was %q, want the not-PEM certificate file's, %q", reason, want)
			}
		})
		t.Run("the edge: a good chain of two starts, and serves a TLS caller", func(t *testing.T) {
			t.Parallel()
			_, telnets := startTLS(t, makeTLSChain(t).files)
			expectTLSServed(t, telnets[0])
		})
	})

	t.Run("If the certificate file holds a private key, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		otherReasons := func(t *testing.T) []string {
			t.Helper()
			files := goodTLSFiles(t, tlsP256)
			return []string{
				tlsReason(t, tlsFiles{certificate: writeTLSFile(t, []byte(canary+" is not PEM\n")), key: files.key}),
				tlsReason(t, tlsFiles{certificate: files.certificate, key: encryptedKey(t, files.key, false)}),
			}
		}
		cases := []struct {
			name        string
			certificate func(t *testing.T, files tlsFiles) string
		}{
			{"a PRIVATE KEY block after the certificate", func(t *testing.T, files tlsFiles) string {
				t.Helper()
				return joinTLSFiles(t, files.certificate, files.key)
			}},
			{"a PRIVATE KEY block before the certificate", func(t *testing.T, files tlsFiles) string {
				t.Helper()
				return joinTLSFiles(t, files.key, files.certificate)
			}},
			{"an EC PRIVATE KEY block after the certificate", func(t *testing.T, files tlsFiles) string {
				t.Helper()
				folder := t.TempDir()
				runOpenSSL(t, folder, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "key.pem")
				return joinTLSFiles(t, files.certificate, filepath.Join(folder, "key.pem"))
			}},
			{"an RSA PRIVATE KEY block after the certificate", func(t *testing.T, files tlsFiles) string {
				t.Helper()
				folder := t.TempDir()
				runOpenSSL(t, folder, "rsa", "-in", makeTLSKey(t, tlsRSA2048), "-traditional", "-out", "key.pem")
				return joinTLSFiles(t, files.certificate, filepath.Join(folder, "key.pem"))
			}},
			{"an ENCRYPTED PRIVATE KEY block after the certificate", func(t *testing.T, files tlsFiles) string {
				t.Helper()
				return joinTLSFiles(t, files.certificate, encryptedKey(t, files.key, false))
			}},
		}
		for _, row := range cases {
			t.Run(row.name+": one start_failed line, a non-zero exit, a reason of its own", func(t *testing.T) {
				t.Parallel()
				files := goodTLSFiles(t, tlsP256)
				reason := tlsReason(t, tlsFiles{certificate: row.certificate(t, files), key: files.key})
				if slices.Contains(otherReasons(t), reason) {
					t.Fatalf("the reason %q is the same as a not-PEM file's or a passphrase's", reason)
				}
			})
		}
		t.Run("the edge: an EC PARAMETERS block and text around the blocks start, and serve a TLS caller", func(t *testing.T) {
			t.Parallel()
			files := goodTLSFiles(t, tlsP256)
			parameters := &pem.Block{Type: "EC PARAMETERS", Bytes: []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}}
			certificate := withSurroundingText(t, writePEMBlocks(t, parameters, readPEMBlocks(t, files.certificate)[0]))
			_, telnets := startTLS(t, tlsFiles{certificate: certificate, key: withSurroundingText(t, files.key)})
			expectTLSServed(t, telnets[0])
		})
	})

	t.Run("If either file's path names anything but a regular file, or the file is longer than 65,536 bytes, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		for _, which := range []string{certificateFile, keyFile} {
			t.Run("a folder as the "+which+" file: one start_failed line, a non-zero exit, a reason other than a missing file's", func(t *testing.T) {
				t.Parallel()
				files := goodTLSFiles(t, tlsP256)
				reason := tlsReason(t, replacedFile(files, which, t.TempDir()))
				if missing := tlsReason(t, replacedFile(goodTLSFiles(t, tlsP256), which, absentPath(t))); reason == missing {
					t.Fatalf("a folder and a missing file gave the same reason, %q", reason)
				}
			})
			t.Run("the "+which+" file one byte over 65,536, a good file padded with text: one start_failed line, a non-zero exit, that file's not-PEM reason", func(t *testing.T) {
				t.Parallel()
				files := goodTLSFiles(t, tlsP256)
				reason := tlsReason(t, replacedFile(files, which, paddedTo(t, chosenFile(files, which), tlsMostBytes+1)))
				notPEM := tlsReason(t, replacedFile(goodTLSFiles(t, tlsP256), which, writeTLSFile(t, []byte(canary+" is not PEM\n"))))
				if reason != notPEM {
					t.Fatalf("the reason was %q, want the not-PEM %s file's, %q", reason, which, notPEM)
				}
			})
			t.Run("the edge: the "+which+" file exactly 65,536 bytes, a good file padded with text, starts and serves a TLS caller", func(t *testing.T) {
				t.Parallel()
				files := goodTLSFiles(t, tlsP256)
				_, telnets := startTLS(t, replacedFile(files, which, paddedTo(t, chosenFile(files, which), tlsMostBytes)))
				expectTLSServed(t, telnets[0])
			})
		}
	})

	t.Run("The engine shall offer TLS 1.3 and TLS 1.2, and no other version.", func(t *testing.T) {
		t.Parallel()
		runTableCases(t, versionCases)
	})

	t.Run("The engine shall offer, in TLS 1.3, only `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384` and `TLS_CHACHA20_POLY1305_SHA256`, and in TLS 1.2 only ECDHE with an ECDSA or RSA certificate and `AES_128_GCM_SHA256`, `AES_256_GCM_SHA384` or `CHACHA20_POLY1305_SHA256`.", func(t *testing.T) {
		t.Parallel()
		runTableCases(t, suiteCases)
	})

	t.Run("The engine shall offer only the key exchanges X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519, P-256, P-384 and P-521.", func(t *testing.T) {
		t.Parallel()
		runTableCases(t, groupCases)
	})

	t.Run("The engine shall send the certificate file's whole chain, ask for no client certificate, and refuse renegotiation and session resumption.", func(t *testing.T) {
		t.Parallel()
		for _, version := range sClientVersions {
			t.Run(version+": a leaf and an intermediate sent, in the file's order, byte for byte", func(t *testing.T) {
				t.Parallel()
				chain := makeTLSChain(t)
				_, telnets := startTLS(t, chain.files)
				text := startSClient(t, telnets[0], version, "-showcerts").handshakeText(t)
				var shown [][]byte
				for _, match := range shownCertificate.FindAllString(text, -1) {
					if block, _ := pem.Decode([]byte(match)); block != nil {
						shown = append(shown, block.Bytes)
					}
				}
				if len(shown) != 2 || !bytes.Equal(shown[0], chain.leaf) || !bytes.Equal(shown[1], chain.intermediate) {
					t.Fatalf("s_client received %d certificates, want the leaf, then the intermediate:\n%s", len(shown), text)
				}
			})
			t.Run(version+": no CertificateRequest", func(t *testing.T) {
				t.Parallel()
				_, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
				seen := readHandshake(startSClient(t, telnets[0], version).handshakeText(t))
				expectTaken(t, seen, "TLSv1."+strings.TrimPrefix(version, "-tls1_"), "", "")
				if slices.Contains(seen.serverMessages, "CertificateRequest") {
					t.Fatalf("the engine asked for a client certificate:\n%s", seen.text)
				}
			})
			t.Run(version+", with -reconnect: six handshakes, each New, no session ID, and no NewSessionTicket by the greeting", func(t *testing.T) {
				t.Parallel()
				_, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
				client := startSClientCommands(t, telnets[0], version, "-reconnect")
				for range 6 {
					client.waitFor(t, "Cipher is", time.Now().Add(testrun.Patient(testrun.HangBound)))
				}
				// Past the greeting's moment, then ended by its input, so it shows all it received.
				pause(t, negotiationLimit+testrun.Patient(margin))
				text := client.finish(t)
				if count := strings.Count("\n"+text, "\nNew, TLSv1."); count != 6 || strings.Contains(text, "Reused, ") {
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
			_, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
			client := startSClientCommands(t, telnets[0], "-tls1_2")
			client.waitFor(t, "New, TLSv1.2", time.Now().Add(testrun.Patient(testrun.HangBound)))
			client.send(t, "R\n")
			client.waitFor(t, "fatal unexpected_message", time.Now().Add(testrun.Patient(testrun.HangBound)))
			// The connection ends by the engine's close: s_client ends with its input still open.
			timer := time.NewTimer(testrun.Patient(margin))
			defer timer.Stop()
			select {
			case <-client.exited:
			case <-timer.C:
				t.Fatalf("the connection had not ended %v after the refusal:\n%s", testrun.Patient(margin), client.text())
			}
		})
	})

	t.Run("If a Telnet over TLS caller's handshake fails, then the engine shall close the connection, writing no Telnet byte to it.", func(t *testing.T) {
		t.Parallel()
		sent := []struct {
			name  string
			bytes func(t *testing.T) []byte
		}{
			{"plain Telnet bytes", func(*testing.T) []byte { return append(append([]byte{}, answers...), typedName+"\r"...) }},
			{"a TLS 1.1 ClientHello", func(t *testing.T) []byte { t.Helper(); return tls11Hello(t) }},
			{"garbage text", func(*testing.T) []byte { return []byte(canary + " is not TLS\r\n") }},
		}
		for _, first := range sent {
			t.Run(first.name+" sent first: at most one alert record, then the end, at once", func(t *testing.T) {
				t.Parallel()
				_, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
				call := dial(t, telnets[0])
				call.send(t, first.bytes(t))
				expectAtMostAlertThenEnd(t, call, time.Now().Add(testrun.Patient(margin)))
			})
		}
		stalled := []struct {
			name  string
			bytes func(t *testing.T) []byte
		}{
			{"a handshake stalled after part of a ClientHello", func(t *testing.T) []byte {
				t.Helper()
				return clientHello(t, tls.VersionTLS13)[:10]
			}},
			{"a caller that sends nothing", func(*testing.T) []byte { return nil }},
		}
		for _, row := range stalled {
			t.Run(row.name+": closed 70 seconds from accept, with no byte but at most one alert", func(t *testing.T) {
				t.Parallel()
				_, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
				dialed := time.Now()
				call := dial(t, telnets[0])
				if data := row.bytes(t); len(data) > 0 {
					call.send(t, data)
				}
				ended := expectAtMostAlertThenEnd(t, call, call.connected.Add(callCeiling+testrun.Patient(margin)))
				expectWithin(t, "the close", ended, dialed.Add(callCeiling), call.connected.Add(callCeiling+margin))
			})
		}
		t.Run("a handshake stalled after part of a ClientHello does not hold up another TLS caller, served at once", func(t *testing.T) {
			t.Parallel()
			_, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
			stuck := dial(t, telnets[0])
			stuck.send(t, clientHello(t, tls.VersionTLS13)[:10])
			expectTLSServed(t, telnets[0])
		})
		t.Run("a stop signal during a stalled handshake: the connection closed and the program exited at once, and the log holds the started line alone", func(t *testing.T) {
			t.Parallel()
			send := stopSignals()[0].prepare(t)
			program, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
			stuck := dial(t, telnets[0])
			stuck.send(t, clientHello(t, tls.VersionTLS13)[:10])
			garbage := dial(t, telnets[1])
			garbage.send(t, []byte(canary+" is not TLS\r\n"))
			expectAtMostAlertThenEnd(t, garbage, time.Now().Add(testrun.Patient(margin)))
			from, sentBy := send(t, program)
			notAfter := sentBy.Add(testrun.Patient(margin))
			ended := expectAtMostAlertThenEnd(t, stuck, notAfter)
			expectWithin(t, "the close", ended, from, notAfter)
			_, exitedAt := program.exit(t, notAfter)
			expectWithin(t, "the exit", exitedAt, from, notAfter)
			program.expectLog(t, "started")
		})
	})

	t.Run("When a Telnet over TLS caller's handshake completes, the engine shall serve it inside the encrypted channel as it serves a Telnet caller it has just accepted.", func(t *testing.T) {
		t.Parallel()
		for _, version := range tlsVersions {
			t.Run(version.name+": the eight requests, the greeting and prompt once answered, a name with BS and AYT echoed and answered, Hello, then close_notify's end", func(t *testing.T) {
				t.Parallel()
				_, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
				call := answeredTLS(t, telnets[0], version.id)
				call.send(t, bytes.Join([][]byte{[]byte("Cx"), {backspace}, []byte("aller"), {iac, areYouThere}, []byte("\r")}, nil))
				call.readExactly(t, bytes.Join([][]byte{[]byte("Cx\b \baller"), []byte(aytAnswer), echoedName("")[:2], []byte(reply + "Caller\r\n")}, nil),
					time.Now().Add(testrun.Patient(margin)))
				call.expectClosedInChannel(t, time.Now().Add(testrun.Patient(margin)))
			})
			t.Run(version.name+": a caller whose ClientHello comes 2 seconds after it connects and that answers nothing gets the greeting 3 seconds after its last handshake flight began", func(t *testing.T) {
				t.Parallel()
				_, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
				raw := dial(t, telnets[0])
				pause(t, time.Until(raw.connected.Add(2*time.Second)))
				call := handshakeOver(t, raw, tlsConfig(version.id))
				call.readExactly(t, opening, time.Now().Add(testrun.Patient(margin)))
				call.readExactly(t, []byte(greeting), call.lastFlight.Add(negotiationLimit+testrun.Patient(margin)))
				expectWithin(t, "the greeting", time.Now(), call.lastFlight.Add(negotiationLimit), call.lastFlight.Add(negotiationLimit+margin))
			})
			t.Run(version.name+": s_client, answering nothing, gets the greeting and the prompt, and Hello for a name typed on its input", func(t *testing.T) {
				t.Parallel()
				_, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
				client := startSClient(t, telnets[0], "-tls1_"+strings.TrimPrefix(version.name, "TLS 1."))
				client.typeAfterPrompt(t, typedName)
				text := client.finish(t)
				// s_client's lines are read without their line ends.
				if !strings.Contains(text, strings.TrimSpace(greeting)) || !strings.Contains(text, prompt) || !strings.Contains(text, reply+typedName) {
					t.Fatalf("s_client did not show the greeting, the prompt and Hello:\n%s", text)
				}
			})
		}
		t.Run("TLS 1.2: 60 seconds without a name, the connection closed with no alert record before the end", func(t *testing.T) {
			t.Parallel()
			_, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
			call := dialTLS(t, telnets[0], tlsConfig(tls.VersionTLS12))
			call.readExactly(t, opening, time.Now().Add(testrun.Patient(margin)))
			answered := time.Now()
			call.send(t, answers)
			call.readExactly(t, []byte(greeting+prompt), time.Now().Add(testrun.Patient(margin)))
			prompted := time.Now()
			received, err := call.readToEnd(prompted.Add(nameLimit + testrun.Patient(margin)))
			ended := time.Now()
			if len(received) != 0 || !isEnd(err) && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("the silent caller read %q and %v, want the end", received, err)
			}
			expectWithin(t, "the close", ended, answered.Add(nameLimit), prompted.Add(nameLimit+margin))
			types, trailing := recordTypes(call.tap.receivedSoFar())
			if trailing != 0 || len(types) == 0 || types[len(types)-1] == alertRecord {
				t.Fatalf("the records' types were %v with %d bytes trailing, want no alert before the end", types, trailing)
			}
		})
		t.Run("TLS 1.2: after Hello and close_notify, the caller's writes are taken with no reset until the closing wait's 3 seconds end the call", func(t *testing.T) {
			t.Parallel()
			_, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
			call := answeredTLS(t, telnets[0], tls.VersionTLS12)
			typed := time.Now()
			call.send(t, []byte(typedName+"\r"))
			call.readExactly(t, echoedName(typedName), time.Now().Add(testrun.Patient(margin)))
			helloRead := time.Now()
			call.expectClosedInChannel(t, time.Now().Add(testrun.Patient(margin)))
			for {
				_ = call.tls.SetWriteDeadline(time.Now().Add(testrun.Patient(testrun.HangBound)))
				_, err := call.tls.Write([]byte("x"))
				if err != nil {
					if !isReset(err) {
						t.Fatalf("the caller's write failed other than by a reset: %v", err)
					}
					expectWithin(t, "the close", time.Now(), typed.Add(closingWait), helloRead.Add(closingWait+margin))
					return
				}
				if time.Now().After(helloRead.Add(closingWait + testrun.Patient(margin))) {
					t.Fatalf("the engine had not closed the connection %v after Hello", closingWait+testrun.Patient(margin))
				}
				pause(t, 10*time.Millisecond)
			}
		})
	})

	t.Run("When `Hello <name>` is written to a Telnet over TLS caller, the engine shall send TLS's close_notify before it shuts down its sending side of the connection.", func(t *testing.T) {
		t.Parallel()
		for _, version := range sClientVersions {
			t.Run(version+", s_client -msg: Hello, then a close_notify alert, then the end", func(t *testing.T) {
				t.Parallel()
				_, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
				client := startSClient(t, telnets[0], version)
				client.typeAfterPrompt(t, typedName)
				text := client.finish(t)
				hello := strings.Index(text, reply+typedName)
				alert := regexp.MustCompile(`(?m)^<<< TLS 1\.[23], Alert \[length 0002\], warning close_notify`).FindStringIndex(text)
				if hello < 0 || alert == nil || alert[0] < hello {
					t.Fatalf("s_client did not see Hello, then close_notify:\n%s", text)
				}
			})
		}
		t.Run("TLS 1.2, QA's caller: the last record before the TCP end is an alert", func(t *testing.T) {
			t.Parallel()
			_, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
			call := answeredTLS(t, telnets[0], tls.VersionTLS12)
			call.send(t, []byte(typedName+"\r"))
			call.readExactly(t, echoedName(typedName), time.Now().Add(testrun.Patient(margin)))
			call.expectClosedInChannel(t, time.Now().Add(testrun.Patient(margin)))
			if rest, err := readAll(call.raw, time.Now().Add(testrun.Patient(margin))); len(rest) != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("after close_notify the TCP connection gave % x and %v, want end of stream", rest, err)
			}
			types, trailing := recordTypes(call.tap.receivedSoFar())
			if trailing != 0 || len(types) == 0 || types[len(types)-1] != alertRecord {
				t.Fatalf("the records' types were %v with %d bytes trailing, want an alert last", types, trailing)
			}
		})
	})

	t.Run("If a write to a Telnet over TLS caller has failed before its call is closed, then the engine shall send that caller no close_notify, and shall still shut down its sending side of the connection.", func(t *testing.T) {
		t.Parallel()
		t.Run("TLS 1.2: a caller that stops reading and sends AYT until the engine's write fails at the name's 60 seconds, then reads: no alert record, and the stream ends", func(t *testing.T) {
			t.Parallel()
			_, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
			call := answeredTLS(t, telnets[0], tls.VersionTLS12)
			answered := time.Now()
			// Answers to AYT pile up unread until the engine's write waits, and the name's 60
			// seconds end it; the caller stops sending well before, so that what it sent has been
			// read and the engine's close is an orderly one.
			for time.Now().Before(answered.Add(nameLimit / 2)) {
				_ = call.tls.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
				if _, err := call.tls.Write([]byte{iac, areYouThere}); err != nil {
					if errors.Is(err, os.ErrDeadlineExceeded) {
						break
					}
					t.Fatalf("the caller's write failed: %v", err)
				}
			}
			rest, err := readAll(call.raw, answered.Add(nameLimit+testrun.Patient(testrun.HangBound)))
			if !isEnd(err) {
				t.Fatalf("the caller's read ended with %v, want the engine's close", err)
			}
			types, trailing := recordTypes(append(call.tap.receivedSoFar(), rest...))
			if trailing != 0 {
				t.Fatalf("cannot tell: the stream ended %d bytes into a record, so whether an alert followed is lost", trailing)
			}
			for _, kind := range types[1:] {
				if kind == alertRecord {
					t.Fatalf("the caller received an alert record after its call's write failed: %v", types)
				}
			}
		})
	})

	t.Run("If a Telnet over TLS caller sends close_notify or a damaged record, then the engine shall close the connection.", func(t *testing.T) {
		t.Parallel()
		for _, version := range tlsVersions {
			t.Run(version.name+": close_notify mid-name: the stream ends at once, with no Hello", func(t *testing.T) {
				t.Parallel()
				_, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
				call := answeredTLS(t, telnets[0], version.id)
				call.send(t, []byte("Ca"))
				call.readExactly(t, []byte("Ca"), time.Now().Add(testrun.Patient(margin)))
				if err := call.tls.CloseWrite(); err != nil {
					t.Fatalf("the caller's close_notify failed: %v", err)
				}
				received, err := readAll(call.raw, time.Now().Add(testrun.Patient(margin)))
				if !isEnd(err) {
					t.Fatalf("the caller's read ended with %v, want the engine's close at once", err)
				}
				if types, _ := recordTypes(received); len(types) > 1 {
					t.Fatalf("after close_notify the caller received %d records, want at most close_notify's own", len(types))
				}
			})
			t.Run(version.name+": a record with its last byte changed: at most one alert record, then the end, at once", func(t *testing.T) {
				t.Parallel()
				_, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
				call := answeredTLS(t, telnets[0], version.id)
				call.tap.damageNext()
				call.send(t, []byte("C"))
				// In TLS 1.3 an alert is encrypted, so it is told inside the channel: no byte, and
				// at most the engine's alert before the end.
				received, err := call.readToEnd(time.Now().Add(testrun.Patient(margin)))
				ended := isEnd(err) || errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(fmt.Sprint(err), "remote error")
				if len(received) != 0 || !ended {
					t.Fatalf("the caller read %q and %v, want at most an alert, then the end", received, err)
				}
				if _, err := readAll(call.raw, time.Now().Add(testrun.Patient(margin))); !isEnd(err) {
					t.Fatalf("the caller's TCP connection ended with %v, want the engine's close", err)
				}
			})
		}
	})

	t.Run("The engine shall count Telnet over TLS callers among the 100 open connections, with its Telnet and SSH callers.", func(t *testing.T) {
		t.Parallel()
		withAllKinds := func(t *testing.T) (telnet, ssh, telnets []string) {
			t.Helper()
			files := goodTLSFiles(t, tlsP256)
			program := startProgram(t, files.options(hostKeyOption, makeKey(t, "ed25519", ""), sshPortOption, "0")...)
			return threeKinds(t, program.listeners(t))
		}
		t.Run("34 Telnet, 33 SSH and 33 TLS callers: the next of each kind closed at once, the TLS one with no byte written", func(t *testing.T) {
			t.Parallel()
			telnet, ssh, telnets := withAllKinds(t)
			for index := range connectionCap {
				switch index % 3 {
				case 0:
					expectServed(t, telnet[0])
				case 1:
					expectSSHServed(t, ssh[0])
				default:
					expectTLSServed(t, telnets[0])
				}
			}
			if served(t, telnet[0]) {
				t.Fatalf("a Telnet caller was served with %d connections open", connectionCap)
			}
			for _, address := range []string{ssh[0], telnets[0]} {
				call := dial(t, address)
				received, err := readAll(call, call.connected.Add(testrun.Patient(margin)))
				if len(received) != 0 || !isEnd(err) {
					t.Fatalf("a caller at %s with %d connections open got % x and %v, want a close with nothing written", address, connectionCap, received, err)
				}
			}
		})
		t.Run("the edge: 99 open, the 100th a TLS caller, served", func(t *testing.T) {
			t.Parallel()
			telnet, ssh, telnets := withAllKinds(t)
			for index := range connectionCap - 1 {
				switch index % 3 {
				case 0:
					expectServed(t, telnet[0])
				case 1:
					expectSSHServed(t, ssh[0])
				default:
					expectTLSServed(t, telnets[0])
				}
			}
			expectTLSServed(t, telnets[1])
		})
		t.Run("99 open and a 100th TLS caller whose handshake fails: its slot freed, so a TLS caller after it is served", func(t *testing.T) {
			t.Parallel()
			telnet, ssh, telnets := withAllKinds(t)
			for index := range connectionCap - 1 {
				switch index % 3 {
				case 0:
					expectServed(t, telnet[0])
				case 1:
					expectSSHServed(t, ssh[0])
				default:
					expectTLSServed(t, telnets[0])
				}
			}
			garbage := dial(t, telnets[0])
			garbage.send(t, []byte(canary+" is not TLS\r\n"))
			expectAtMostAlertThenEnd(t, garbage, time.Now().Add(testrun.Patient(margin)))
			expectTLSServedOnceFreed(t, telnets[1])
		})
	})

	t.Run("The engine shall not store, log or show anything a caller sends in its handshake, the server name it asks for among them.", func(t *testing.T) {
		t.Parallel()
		t.Run("a server name and an ALPN protocol of canary text, a whole call, then a stop: no canary in the log or in what the caller received", func(t *testing.T) {
			t.Parallel()
			send := stopSignals()[0].prepare(t)
			program, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
			config := tlsConfig(0)
			config.ServerName = canary + ".test"
			config.NextProtos = []string{canary}
			call := dialTLS(t, telnets[0], config)
			call.readExactly(t, opening, time.Now().Add(testrun.Patient(margin)))
			call.send(t, answers)
			call.readExactly(t, []byte(greeting+prompt), time.Now().Add(testrun.Patient(margin)))
			call.send(t, []byte(typedName+"\r"))
			call.readExactly(t, echoedName(typedName), time.Now().Add(testrun.Patient(margin)))
			call.expectClosedInChannel(t, time.Now().Add(testrun.Patient(margin)))
			_, sentBy := send(t, program)
			program.exit(t, sentBy.Add(testrun.Patient(margin)))
			if strings.Contains(program.text(), canary) {
				t.Fatalf("the local log holds what the caller sent in its handshake:\n%s", program.text())
			}
			program.expectLog(t, "started")
		})
	})

	t.Run("The engine shall not write any part of the private key to the local log.", func(t *testing.T) {
		t.Parallel()
		refused := []struct {
			name  string
			files func(t *testing.T) tlsFiles
		}{
			{"a key protected by a passphrase", func(t *testing.T) tlsFiles {
				t.Helper()
				files := goodTLSFiles(t, tlsP256)
				files.key = encryptedKey(t, files.key, false)
				return files
			}},
			{"an RSA 1024 key", func(t *testing.T) tlsFiles { t.Helper(); return goodTLSFiles(t, tlsRSA1024) }},
			{"a key that does not match", func(t *testing.T) tlsFiles {
				t.Helper()
				return tlsFiles{certificate: goodTLSFiles(t, tlsP256).certificate, key: makeTLSKey(t, tlsP256)}
			}},
		}
		for _, row := range refused {
			t.Run(row.name+", refused: the log holds no 8 characters in a row of the key", func(t *testing.T) {
				t.Parallel()
				files := row.files(t)
				program := startProgram(t, files.options()...)
				expectFileRefused(t, program)
				expectNoKeyInLog(t, program.text(), files.key)
			})
		}
		t.Run("a key in the certificate file, refused: the log holds no 8 characters in a row of it", func(t *testing.T) {
			t.Parallel()
			files := goodTLSFiles(t, tlsP256)
			program := startProgram(t, tlsFiles{certificate: joinTLSFiles(t, files.certificate, files.key), key: files.key}.options()...)
			expectFileRefused(t, program)
			expectNoKeyInLog(t, program.text(), files.key)
		})
		t.Run("good files, a whole call and a stop: the log holds no 8 characters in a row of the key", func(t *testing.T) {
			t.Parallel()
			send := stopSignals()[0].prepare(t)
			files := goodTLSFiles(t, tlsP256)
			program, telnets := startTLS(t, files)
			call := answeredTLS(t, telnets[0], 0)
			call.send(t, []byte(typedName+"\r"))
			call.readExactly(t, echoedName(typedName), time.Now().Add(testrun.Patient(margin)))
			_, sentBy := send(t, program)
			program.exit(t, sentBy.Add(testrun.Patient(margin)))
			expectNoKeyInLog(t, program.text(), files.key)
		})
	})

	t.Run("When a Telnet caller sends AO or IP before its name ends, the engine shall send IAC DM, with DM as TCP urgent data on a plain Telnet connection and as an ordinary byte over TLS.", func(t *testing.T) {
		t.Parallel()
		for _, code := range []byte{abortOutput, interruptProcess} {
			t.Run(fmt.Sprintf("over TLS, a, IAC %d, b mid-name, ECHO agreed: a, IAC DM as two ordinary bytes in the channel, then b and the name whole", code), func(t *testing.T) {
				t.Parallel()
				_, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
				call := answeredTLS(t, telnets[0], 0)
				call.send(t, []byte{'a', iac, code})
				call.readExactly(t, []byte{'a', iac, dataMark}, time.Now().Add(testrun.Patient(margin)))
				call.send(t, []byte("b\r"))
				call.readExactly(t, []byte("b\r\n"+reply+"ab\r\n"), time.Now().Add(testrun.Patient(margin)))
				call.expectClosedInChannel(t, time.Now().Add(testrun.Patient(margin)))
			})
		}
		t.Run("the edge, over TLS: AO after the name ends: no IAC DM", func(t *testing.T) {
			t.Parallel()
			_, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
			call := answeredTLS(t, telnets[0], 0)
			call.send(t, []byte{'b', '\r', iac, abortOutput})
			call.readExactly(t, echoedName("b"), time.Now().Add(testrun.Patient(margin)))
			call.expectClosedInChannel(t, time.Now().Add(testrun.Patient(margin)))
		})
	})

	t.Run("If a command-line option is malformed, or the engine fails to listen at both addresses for Telnet or, when SSH or Telnet over TLS is on, for that kind, then the engine shall write one `start_failed` line to the local log saying why, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		withFiles := func(t *testing.T, options ...string) []string {
			t.Helper()
			files := goodTLSFiles(t, tlsP256)
			return append([]string{portOption, "0", tlsCertificateOption, files.certificate, tlsKeyOption, files.key}, options...)
		}
		rows := []struct {
			name    string
			options func(t *testing.T) []string
		}{
			{"-tls-cert without -tls-key", func(t *testing.T) []string {
				t.Helper()
				return []string{portOption, "0", tlsCertificateOption, goodTLSFiles(t, tlsP256).certificate}
			}},
			{"-tls-key without -tls-cert", func(t *testing.T) []string {
				t.Helper()
				return []string{portOption, "0", tlsKeyOption, goodTLSFiles(t, tlsP256).key}
			}},
			{"-tls-port without either file", func(*testing.T) []string { return []string{portOption, "0", tlsPortOption, "0"} }},
			{"-tls-port abc with both files", func(t *testing.T) []string { t.Helper(); return withFiles(t, tlsPortOption, "abc") }},
			{"-tls-port 65536 with both files", func(t *testing.T) []string { t.Helper(); return withFiles(t, tlsPortOption, "65536") }},
			{"-tls-port -1 with both files", func(t *testing.T) []string { t.Helper(); return withFiles(t, tlsPortOption, "-1") }},
			{"-tls-port with no value", func(t *testing.T) []string { t.Helper(); return withFiles(t, tlsPortOption) }},
			{"-tls-cert with no value", func(t *testing.T) []string {
				t.Helper()
				return []string{portOption, "0", tlsKeyOption, goodTLSFiles(t, tlsP256).key, tlsCertificateOption}
			}},
			{"-tls-key with no value", func(t *testing.T) []string {
				t.Helper()
				return []string{portOption, "0", tlsCertificateOption, goodTLSFiles(t, tlsP256).certificate, tlsKeyOption}
			}},
		}
		for _, row := range rows {
			t.Run(row.name+": one start_failed line and a non-zero exit, where good options start", func(t *testing.T) {
				t.Parallel()
				startProgram(t, row.options(t)...).expectRefusal(t)
				expectTLSStarts(t)
			})
		}
		t.Run("the Telnet over TLS port taken at both addresses while Telnet's is free: one start_failed line and a non-zero exit, where a free port starts", func(t *testing.T) {
			t.Parallel()
			port, _, _ := heldPort(t)
			files := goodTLSFiles(t, tlsP256)
			startProgram(t, portOption, "0", tlsCertificateOption, files.certificate, tlsKeyOption, files.key, tlsPortOption, port).expectRefusal(t)
			expectTLSStarts(t)
		})
	})

	t.Run("If the engine fails to listen at one of 127.0.0.1 and ::1, then the engine shall listen at the other alone.", func(t *testing.T) {
		t.Parallel()
		t.Run("the Telnet over TLS port taken at 127.0.0.1: it names and serves Telnet over TLS at ::1 alone", func(t *testing.T) {
			t.Parallel()
			files := goodTLSFiles(t, tlsP256)
			port, listeners := startOnFreedPort(t, []string{ipv6Loopback}, func(port string) []string {
				return []string{portOption, "0", tlsCertificateOption, files.certificate, tlsKeyOption, files.key, tlsPortOption, port}
			})
			_, _, telnets := threeKinds(t, listeners)
			expectAddresses(t, telnets, net.JoinHostPort(ipv6Loopback, port))
			expectTLSServed(t, telnets[0])
		})
	})

	t.Run("The engine shall listen for callers at 127.0.0.1 and at ::1, and at no other address.", func(t *testing.T) {
		t.Parallel()
		t.Run("with Telnet over TLS on, 127.0.0.2 and this machine's other addresses are refused at its ports too", func(t *testing.T) {
			t.Parallel()
			_, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
			ipv4Port, ipv6Port := loopbackPorts(t, telnets)
			for _, address := range telnets {
				expectTLSServed(t, address)
			}
			targets := []string{net.JoinHostPort("127.0.0.2", ipv4Port), net.JoinHostPort("127.0.0.2", ipv6Port)}
			for _, address := range otherAddresses(t) {
				targets = append(targets, net.JoinHostPort(address.String(), ipv4Port), net.JoinHostPort(address.String(), ipv6Port))
			}
			var group sync.WaitGroup
			for _, target := range targets {
				group.Go(func() { expectRefused(t, target) })
			}
			group.Wait()
		})
	})

	t.Run("When it has started listening, the engine shall write one `started` line to the local log naming the kind, address and port of everywhere it listens.", func(t *testing.T) {
		t.Parallel()
		t.Run("with SSH and Telnet over TLS on: one started line naming each listener as a URL, telnets:// at both addresses, each served by its kind", func(t *testing.T) {
			t.Parallel()
			files := goodTLSFiles(t, tlsP256)
			program := startProgram(t, files.options(hostKeyOption, makeKey(t, "ed25519", ""), sshPortOption, "0")...)
			telnet, ssh, telnets := threeKinds(t, program.listeners(t))
			for _, kind := range [][]string{telnet, ssh, telnets} {
				loopbackPorts(t, kind)
			}
			for _, address := range telnets {
				expectTLSServed(t, address)
			}
			expectServed(t, telnet[0])
			expectSSHServed(t, ssh[0])
		})
	})

	t.Run("When it receives a stop signal, the engine shall close every open connection at once and exit.", func(t *testing.T) {
		t.Parallel()
		signal := stopSignals()[0]
		t.Run(signal.name+": a silent TLS caller that has read the opening is closed, and the program exits, at once", func(t *testing.T) {
			t.Parallel()
			send := signal.prepare(t)
			program, telnets := startTLS(t, goodTLSFiles(t, tlsP256))
			silent := expectTLSServed(t, telnets[0])
			from, sentBy := send(t, program)
			notAfter := sentBy.Add(testrun.Patient(margin))
			if _, err := readAll(silent.raw, notAfter); !isEnd(err) {
				t.Fatalf("the silent TLS caller's read ended with %v, want the engine's close", err)
			}
			_, exitedAt := program.exit(t, notAfter)
			expectWithin(t, "the exit", exitedAt, from, notAfter)
		})
	})

	t.Run("If the database does not answer, or answers that it is starting up, shutting down or recovering, that it has no connection free, or that it is read-only, then the engine shall write one `waiting` line saying which, listen nowhere, and try again every 10 seconds.", func(t *testing.T) {
		t.Parallel()
		t.Run("with Telnet over TLS on, a database that closes each connection: one waiting line, and the program listens nowhere", func(t *testing.T) {
			t.Parallel()
			database := startAcceptor(t)
			sharedServer(t)
			contents := sharedBoard.file()
			contents.Port = database.port(t)
			program := startWithFile(t, contents.write(t), nil, goodTLSFiles(t, tlsP256).options()...)
			program.expectLine(t, 0, "waiting", time.Now().Add(testrun.Patient(waitLineLimit)))
			expectNotListening(t, program)
		})
	})

	t.Run("If 25 seconds pass after it sent its last take or renewal that succeeded, or a renewal finds the lease holder is not its own, then the engine shall close every open connection and every listener, write one `lease_lost` line, and try to take the lease again every 10 seconds.", func(t *testing.T) {
		t.Parallel()
		t.Run("with Telnet over TLS on, another run's holder written: lease_lost, the TLS caller's connection and the TLS listeners closed", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			program := startWithFile(t, created.file().write(t), nil, goodTLSFiles(t, tlsP256).options()...)
			_, _, telnets := threeKinds(t, program.listeners(t))
			call := expectTLSServed(t, telnets[0])
			changed := time.Now()
			created.setRow(t, foreignHolder, "now() + interval '1 hour'")
			_, lost := program.expectLine(t, 1, "lease_lost", changed.Add(renewEvery+testrun.Patient(leaseMargin)))
			if _, err := readAll(call.raw, lost.Add(testrun.Patient(margin))); !isEnd(err) {
				t.Fatalf("the TLS caller's read ended with %v, want the engine's close at lease_lost", err)
			}
			for _, address := range telnets {
				expectRefused(t, address)
			}
		})
	})
}
