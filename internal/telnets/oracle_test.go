// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package telnets_test

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// sClient is one run of OpenSSL's s_client, the oracle for the TLS table: run with -msg, so every
// record it sends and receives is named, and -ign_eof, so it reads on after its input ends.
type sClient struct {
	command *exec.Cmd
	input   io.WriteCloser
	mutex   sync.Mutex
	output  []string
	// started is when it was started, and arrived when each line of output came, for a row's
	// failure message.
	started time.Time
	arrived []time.Time
	// lines receives each line it prints as it arrives.
	lines  chan string
	exited chan struct{}
}

// startSClient connects s_client to the address with the options given, killed when the test
// ends.
func startSClient(t *testing.T, address string, options ...string) *sClient {
	t.Helper()
	return runSClient(t, address, append([]string{"-ign_eof"}, options...))
}

// startSClientCommands is startSClient without -ign_eof, under which s_client reads no command
// such as R from its input: it sends the letter as data instead. It ends when its input does.
func startSClientCommands(t *testing.T, address string, options ...string) *sClient {
	t.Helper()
	return runSClient(t, address, options)
}

func runSClient(t *testing.T, address string, options []string) *sClient {
	t.Helper()
	if opensslFailure != nil {
		t.Fatalf("openssl is not on this machine's PATH, and these rows need it: %v", opensslFailure)
	}
	arguments := append([]string{"s_client", "-connect", address, "-msg"}, options...)
	command := exec.CommandContext(t.Context(), opensslPath, arguments...)
	command.WaitDelay = testrun.Patient(testrun.HangBound)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	command.Stdout = writer
	command.Stderr = writer
	started := time.Now()
	if err := command.Start(); err != nil {
		t.Fatalf("starting s_client: %v", err)
	}
	client := &sClient{command: command, input: input, started: started, lines: make(chan string, 1024), exited: make(chan struct{})}
	go func() {
		_ = command.Wait()
		_ = writer.Close()
	}()
	go func() {
		defer close(client.exited)
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimRight(scanner.Text(), "\r")
			client.mutex.Lock()
			client.output = append(client.output, line)
			client.arrived = append(client.arrived, time.Now())
			client.mutex.Unlock()
			select {
			case client.lines <- line:
			default:
			}
		}
		_, _ = io.Copy(io.Discard, reader)
	}()
	t.Cleanup(func() {
		_ = input.Close()
		select {
		case <-client.exited:
		default:
			_ = command.Process.Kill()
			<-client.exited
		}
	})
	return client
}

// timeline is when s_client was started, whether it has ended, and each line it has printed with
// when it came, every time from since, for a row's failure message.
func (client *sClient) timeline(since time.Time) string {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	ended := "still running"
	select {
	case <-client.exited:
		ended = "ended"
	default:
	}
	report := []string{"s_client started at " + offset(client.started, since) + ", " + ended + "; what it printed:"}
	for index, line := range client.output {
		report = append(report, offset(client.arrived[index], since)+"  "+line)
	}
	return strings.Join(report, "\n")
}

// offset is when, from since, in seconds to the millisecond, signed.
func offset(when, since time.Time) string {
	return fmt.Sprintf("%+.3fs", when.Sub(since).Seconds())
}

// text is everything s_client has printed so far.
func (client *sClient) text() string {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	return strings.Join(client.output, "\n")
}

// waitFor waits, by the deadline, for a line s_client prints that starts with the prefix, and
// returns it.
func (client *sClient) waitFor(t *testing.T, prefix string, deadline time.Time) string {
	t.Helper()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	for {
		select {
		case line := <-client.lines:
			if strings.HasPrefix(line, prefix) {
				return line
			}
		case <-client.exited:
			for {
				select {
				case line := <-client.lines:
					if strings.HasPrefix(line, prefix) {
						return line
					}
					continue
				default:
				}
				break
			}
			t.Fatalf("s_client ended before it printed %q:\n%s", prefix, client.text())
		case <-timer.C:
			t.Fatalf("s_client had not printed %q by the deadline:\n%s", prefix, client.text())
		}
	}
}

// send writes to s_client's standard input.
func (client *sClient) send(t *testing.T, text string) {
	t.Helper()
	if _, err := io.WriteString(client.input, text); err != nil {
		t.Fatalf("writing to s_client: %v", err)
	}
}

// finish closes s_client's input and waits, by the hang bound, for it to end, which it does when
// the other end closes, and returns everything it printed.
func (client *sClient) finish(t *testing.T) string {
	t.Helper()
	_ = client.input.Close()
	timer := time.NewTimer(testrun.Patient(testrun.HangBound))
	defer timer.Stop()
	select {
	case <-client.exited:
	case <-timer.C:
		t.Fatalf("s_client had not ended within %v:\n%s", testrun.Patient(testrun.HangBound), client.text())
	}
	return client.text()
}

// handshakeSeen is what s_client printed of one handshake.
type handshakeSeen struct {
	text string
	// protocol and cipher are from its "New, …, Cipher is …" line, (NONE) for both when none
	// was agreed.
	protocol, cipher string
	// group is the key exchange agreed, by the names the TLS table uses.
	group string
	// serverAlerts and clientAlerts are each alert received and sent, as "fatal name" or
	// "warning name".
	serverAlerts, clientAlerts []string
	// serverMessages are the handshake messages received, by name.
	serverMessages []string
	connected      bool
}

// The curves by the names the TLS table uses, which TLS 1.3's s_client prints and TLS 1.2's
// OpenSSL name is read into.
const (
	curveP256 = "P-256"
	curveP384 = "P-384"
	curveP521 = "P-521"
)

var (
	newLine          = regexp.MustCompile(`(?m)^New, (TLSv1(?:\.[0-3])?|\(NONE\)), Cipher is (\S+)`)
	negotiatedGroup  = regexp.MustCompile(`(?m)^Negotiated TLS1\.3 group: (\S+)`)
	temporaryKey     = regexp.MustCompile(`(?m)^(?:Peer|Server) Temp Key: (X25519|X448|ECDH, (\S+)),`)
	receivedAlert    = regexp.MustCompile(`(?m)^<<< TLS [0-9.]+, Alert \[length 0002\], (fatal|warning) (\S+)`)
	sentAlert        = regexp.MustCompile(`(?m)^>>> TLS [0-9.]+, Alert \[length 0002\], (fatal|warning) (\S+)`)
	receivedMessage  = regexp.MustCompile(`(?m)^<<< TLS [0-9.]+, Handshake \[length [0-9a-f]+\], (\S+)`)
	opensslCurveName = map[string]string{"prime256v1": curveP256, "secp384r1": curveP384, "secp521r1": curveP521}
)

// readHandshake reads s_client's output, written with -msg: the protocol and cipher it agreed,
// the key exchange, and every alert and handshake message, as OpenSSL 3.5 words them in TLS 1.3
// and TLS 1.2 alike.
func readHandshake(text string) handshakeSeen {
	seen := handshakeSeen{text: text, connected: strings.Contains(text, "CONNECTED(")}
	if match := newLine.FindStringSubmatch(text); match != nil {
		seen.protocol, seen.cipher = match[1], match[2]
	}
	if match := negotiatedGroup.FindStringSubmatch(text); match != nil && match[1] != "<NULL>" {
		seen.group = match[1]
	} else if match := temporaryKey.FindStringSubmatch(text); match != nil {
		seen.group = match[1]
		if match[2] != "" {
			seen.group = opensslCurveName[match[2]]
			if seen.group == "" {
				seen.group = match[2]
			}
		}
	}
	// The handshake's records end where s_client sums it up: what follows is the call, and how
	// the connection ended, which a row about the handshake does not judge.
	handshakeText := text
	if summary := newLine.FindStringIndex(text); summary != nil {
		handshakeText = text[:summary[0]]
	}
	for _, match := range receivedAlert.FindAllStringSubmatch(handshakeText, -1) {
		seen.serverAlerts = append(seen.serverAlerts, match[1]+" "+match[2])
	}
	for _, match := range sentAlert.FindAllStringSubmatch(handshakeText, -1) {
		seen.clientAlerts = append(seen.clientAlerts, match[1]+" "+match[2])
	}
	for _, match := range receivedMessage.FindAllStringSubmatch(handshakeText, -1) {
		seen.serverMessages = append(seen.serverMessages, match[1])
	}
	return seen
}

// expectTaken checks s_client agreed the protocol, the cipher and, when one is named, the key
// exchange, with no fatal alert either way during the handshake.
func expectTaken(t *testing.T, seen handshakeSeen, protocol, cipher, group string) {
	t.Helper()
	if seen.protocol != protocol || (cipher != "" && seen.cipher != cipher) || (group != "" && seen.group != group) {
		t.Fatalf("s_client agreed %s, %s and %q, want %s, %s and %q:\n%s", seen.protocol, seen.cipher, seen.group, protocol, cipher, group, seen.text)
	}
	for _, alert := range append(append([]string{}, seen.serverAlerts...), seen.clientAlerts...) {
		if strings.HasPrefix(alert, "fatal") {
			t.Fatalf("s_client's handshake met the alert %q:\n%s", alert, seen.text)
		}
	}
}

// expectRefusedWith checks the engine refused the case with the one fatal alert given and wrote
// no handshake message. A case s_client could not offer, or refused itself, is a fault in the
// test: the engine was never asked.
func expectRefusedWith(t *testing.T, seen handshakeSeen, alert string) {
	t.Helper()
	if !seen.connected {
		t.Fatalf("a fault in the test: s_client never connected, so it could not offer the case:\n%s", seen.text)
	}
	for _, sent := range seen.clientAlerts {
		if strings.HasPrefix(sent, "fatal") {
			t.Fatalf("a fault in the test: s_client refused the case itself, with %q:\n%s", sent, seen.text)
		}
	}
	if len(seen.serverAlerts) != 1 || seen.serverAlerts[0] != "fatal "+alert {
		t.Fatalf("the engine sent the alerts %q, want fatal %s alone:\n%s", seen.serverAlerts, alert, seen.text)
	}
	if len(seen.serverMessages) != 0 || seen.protocol != "(NONE)" {
		t.Fatalf("the engine sent %q and agreed %s where it was to refuse:\n%s", seen.serverMessages, seen.protocol, seen.text)
	}
}
