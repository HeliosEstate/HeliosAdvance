// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package ssh_test

import (
	"context"
	"errors"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/ssh"
)

// The page's limits and texts, as the lines state them; never the package's constants.
const (
	greeting     = "Hello Helios Advance BBS!\r\n"
	prompt       = "What is your name? "
	versionLine  = "SSH-2.0-HeliosAdvance\r\n"
	closingWait  = 3 * time.Second
	ceilingLimit = 70 * time.Second
	// margin is how late past a limit an event may come: Part 1's, measured on every runner.
	margin = 750 * time.Millisecond
	// quietFor is how long a row waits to see that nothing comes.
	quietFor = 300 * time.Millisecond
	// connectionCap is the open connections the engine serves at once, across every kind.
	connectionCap = 100
)

// Names the rows send: a name typed and ended, channel types the engine refuses, and a request
// or channel name no one defines.
const (
	typedBob           = "bob\r"
	directChannel      = "direct-tcpip"
	streamLocalChannel = "direct-streamlocal@openssh.com"
	x11Channel         = "x11"
	unknownName        = "helios-unknown@example.com"
	ed25519Name        = "ssh-ed25519"
)

// early is how far before its deadline a runner's clock may wake a wait, Part 1's measure.
const early = 20 * time.Millisecond

// raceStretch is how much longer a wait may take under the race detector, which slows the engine
// and the test by an amount nobody controls: generous, since a stretched wait still fails a
// hang, and no upper bound on time is judged there.
const raceStretch = 4

// patient stretches a wait under the race detector; without it the wait is unchanged.
func patient(wait time.Duration) time.Duration {
	if raceBuild {
		return raceStretch * wait
	}
	return wait
}

// expectWithin checks a moment falls in its window and logs how far into it it came. Under the
// race detector only the window's opening is judged: the race detector slows the engine by an
// amount nobody controls, so lateness there is logged, never failed.
func expectWithin(t *testing.T, what string, moment, notBefore, notAfter time.Time) {
	t.Helper()
	t.Logf("%s came %v into its window of %v", what, moment.Sub(notBefore), notAfter.Sub(notBefore))
	if moment.Before(notBefore.Add(-early)) {
		t.Fatalf("%s came %v too soon", what, notBefore.Sub(moment))
	}
	if moment.After(notAfter) {
		if raceBuild {
			t.Logf("under the race detector, timing is not judged: %s came %v late", what, moment.Sub(notAfter))
		} else {
			t.Fatalf("%s came %v too late", what, moment.Sub(notAfter))
		}
	}
}

// isEnd is a read the engine ended: end of stream, or a reset.
func isEnd(err error) bool {
	return errors.Is(err, io.EOF) || isReset(err)
}

// isReset is a connection the engine closed with bytes of the caller's still unread.
func isReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.Errno(10053)) || errors.Is(err, syscall.Errno(10054))
}

// makeKey runs ssh-keygen, the oracle's own tool, for a key of the given type with the given
// passphrase, and returns the private key file's path.
func makeKey(t *testing.T, keyType, passphrase string, extra ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "host_key")
	makeKeyAt(t, path, keyType, passphrase, append([]string{"-C", ""}, extra...)...)
	return path
}

// makeKeyAt is makeKey at a path of the row's choosing, its comment among extra.
func makeKeyAt(t *testing.T, path, keyType, passphrase string, extra ...string) {
	t.Helper()
	arguments := append([]string{"-q", "-t", keyType, "-N", passphrase, "-f", path}, extra...)
	if output, err := exec.CommandContext(t.Context(), "ssh-keygen", arguments...).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen %v: %v %s", arguments, err, output)
	}
}

// readKey reads an Ed25519 key ssh-keygen made, failing the row if the package refuses it.
func readKey(t *testing.T) *ssh.HostKey {
	t.Helper()
	key, err := ssh.ReadHostKey(makeKey(t, "ed25519", ""))
	if err != nil {
		t.Fatalf("ReadHostKey refused a key ssh-keygen made: %v", err)
	}
	return key
}

// acceptResult is what Accept returned on the server end, and when.
type acceptResult struct {
	channel  *ssh.Channel
	err      error
	returned time.Time
}

// acceptPair listens on loopback, runs Accept on the accepted end under ctx, and returns the
// address to dial and the result to come.
func acceptPair(t *testing.T, ctx context.Context, key *ssh.HostKey) (string, <-chan acceptResult, <-chan *net.TCPConn) {
	t.Helper()
	socket := listenLoopback(t) //nolint:contextcheck // the row's own context listens: Accept's may have ended already
	results := make(chan acceptResult, 1)
	servers := make(chan *net.TCPConn, 1)
	go func() {
		connection, err := socket.AcceptTCP()
		if err != nil {
			results <- acceptResult{err: err}
			return
		}
		t.Cleanup(func() { _ = connection.Close() })
		servers <- connection
		channel, err := ssh.Accept(ctx, connection, key)
		results <- acceptResult{channel: channel, err: err, returned: time.Now()}
	}()
	return socket.Addr().String(), results, servers
}

// listenLoopback listens on 127.0.0.1 at a port the system picks, closed when the row ends; the
// row's own context, not the one Accept is given, which may have ended already.
func listenLoopback(t *testing.T) *net.TCPListener {
	t.Helper()
	opened, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	socket, ok := opened.(*net.TCPListener)
	if !ok {
		t.Fatalf("the listening socket is a %T", opened)
	}
	t.Cleanup(func() { _ = socket.Close() })
	return socket
}

func waitAccept(t *testing.T, results <-chan acceptResult, limit time.Duration) acceptResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(limit):
		t.Fatalf("Accept had not returned after %v", limit)
		return acceptResult{}
	}
}
