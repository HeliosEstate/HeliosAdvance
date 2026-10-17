// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The failed accept: the Listener runs in a child process, this test binary run again, under a
// limit on open descriptors low enough that accepting a caller fails while callers are open. Only
// Linux lowers the limit through the shell this way, so the test is named for it.
package listener_test

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/listener"
)

// childArgument marks the run of this test binary that is the child holding the Listener: an
// argument after the test flags, which the testing package leaves alone.
const childArgument = "accept-fails-child"

// descriptorLimit is far below the connection cap, so a caller the engine leaves waiting is a
// failed accept and never the cap, and far above what the child holds before any caller comes.
const descriptorLimit = "32"

// failedAcceptLimit is the page's limit on accepting again after a failed accept.
const failedAcceptLimit = time.Second

func TestLinuxAcceptFails(t *testing.T) {
	t.Parallel()
	if slices.Contains(os.Args[1:], childArgument) {
		holdListener(t)
		return
	}
	t.Run("If accepting a caller fails, then the engine shall keep serving its open connections and accept again within 1 second.", func(t *testing.T) {
		t.Parallel()
		t.Run("callers fill the descriptors: the open ones are served, and a waiting caller is accepted once one closes", func(t *testing.T) {
			t.Parallel()
			address := startChild(t)

			// Accepting has failed once a caller is left waiting: the engine neither serves it
			// nor closes it.
			var held []caller
			var waiting caller
			for waiting.connection == nil {
				if len(held) == connectionCap {
					t.Fatalf("%d callers were served and accepting never failed", len(held))
				}
				call := dial(t, address)
				_ = call.connection.SetReadDeadline(call.connected.Add(margin))
				received := make([]byte, len(opening))
				got, err := io.ReadFull(call.connection, received)
				switch {
				case err == nil && slices.Equal(received, opening):
					held = append(held, call)
				case got == 0 && errors.Is(err, os.ErrDeadlineExceeded):
					waiting = call
				default:
					t.Fatalf("caller %d was neither served nor left waiting: % x, %v", len(held)+1, received[:got], err)
				}
			}
			if len(held) == 0 {
				t.Fatalf("no caller was served before accepting failed")
			}
			t.Logf("%d callers were served before accepting failed", len(held))

			// The held callers stay silent, so the engine itself ends each call: the greeting
			// at 3 seconds, its close 3 seconds after. Accepting fails all that while, long
			// enough that a pause left to grow past 1 second would show.
			streams := make([]*recording, len(held))
			for index, call := range held {
				streams[index] = call.record(call.connected.Add(negotiationLimit + 2*margin))
			}
			for index, call := range held {
				streams[index].expectStream(t, []byte(greeting))
				expectWithin(t, "a held caller's greeting", streams[index].greetingAt(t),
					call.dialed.Add(negotiationLimit), call.connected.Add(negotiationLimit+margin))
			}
			freed := held[0].awaitReset(t, streams[0].ended.Add(closingWaitLimit+margin))

			_ = waiting.connection.SetReadDeadline(freed.Add(failedAcceptLimit + margin))
			received := make([]byte, len(opening))
			got, err := io.ReadFull(waiting.connection, received)
			if err != nil || !slices.Equal(received, opening) {
				t.Fatalf("the waiting caller got % x and %v by 1 second after a descriptor was freed, want % x",
					received[:got], err, opening)
			}
			expectWithin(t, "the waiting caller's opening", time.Now(), freed, freed.Add(failedAcceptLimit+margin))
		})
	})
}

// startChild runs this test binary again as the child, under the descriptor limit, and returns
// the address its Listener accepts on. The shell sets both the soft and the hard limit, since a
// Go program raises its soft limit to the hard one as it starts.
func startChild(t *testing.T) string {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatalf("finding the test binary: %v", err)
	}
	child := exec.CommandContext(t.Context(), "sh", "-c", `ulimit -n "$1" && shift && exec "$@"`,
		"sh", descriptorLimit, binary, "-test.run=^TestLinuxAcceptFails$", "-test.count=1", childArgument)
	child.WaitDelay = 5 * time.Second
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatalf("the child's standard input: %v", err)
	}
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatalf("the child's standard output: %v", err)
	}
	if err := child.Start(); err != nil {
		t.Fatalf("starting the child: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = child.Wait()
	})

	lines := make(chan string)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			case <-t.Context().Done():
				return
			}
		}
	}()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	// The limits are checked before anything the Listener did, so a row red against unbuilt code
	// also shows the child ran under the limit.
	var limits string
	checkLimits := func() {
		if limits != descriptorLimit+" "+descriptorLimit {
			t.Fatalf("the child's open-file limits were %q, want %s for both", limits, descriptorLimit)
		}
	}
	for {
		select {
		case line, open := <-lines:
			if !open {
				t.Fatalf("the child ended before its Listener accepted")
			}
			if value, found := strings.CutPrefix(line, "limits="); found {
				limits = value
			}
			if value, found := strings.CutPrefix(line, "start_failed="); found {
				checkLimits()
				t.Fatalf("the child ran under the limit, and its Start refused: %s", value)
			}
			if value, found := strings.CutPrefix(line, "address="); found {
				checkLimits()
				return value
			}
		case <-timer.C:
			t.Fatalf("the child named no address within 10 seconds")
		}
	}
}

// holdListener is the child's part: it starts the Listener on a loopback socket, names its
// limits and its address on standard output, and holds the Listener until standard input ends.
func holdListener(t *testing.T) {
	t.Helper()
	limits, err := os.ReadFile("/proc/self/limits")
	if err != nil {
		t.Fatalf("reading the child's limits: %v", err)
	}
	for line := range strings.SplitSeq(string(limits), "\n") {
		if rest, found := strings.CutPrefix(line, "Max open files"); found {
			fields := strings.Fields(rest)
			if len(fields) >= 2 {
				announce(t, "limits="+fields[0]+" "+fields[1])
			}
		}
	}
	opened, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on loopback: %v", err)
	}
	socket, isTCP := opened.(*net.TCPListener)
	if !isTCP {
		t.Fatalf("the listening socket is a %T", opened)
	}
	engine, err := listener.Start([]*net.TCPListener{socket})
	if err != nil {
		_ = socket.Close()
		announce(t, "start_failed="+err.Error())
		return
	}
	defer engine.Stop()
	announce(t, "address="+socket.Addr().String())
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func announce(t *testing.T, line string) {
	t.Helper()
	if _, err := os.Stdout.WriteString(line + "\n"); err != nil {
		t.Fatalf("writing to the parent: %v", err)
	}
}
