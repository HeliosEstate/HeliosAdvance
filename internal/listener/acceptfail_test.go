// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The failed accept: the Listener runs in a child process, this test binary run again, under a
// limit on open descriptors low enough that accepting a caller fails while callers are open. Only
// Linux lowers the limit through the shell this way, so the test is named for it.
package listener_test

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
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
const descriptorLimit = 32

// failedAcceptLimit is the page's limit on accepting again after a failed accept.
const failedAcceptLimit = time.Second

// acceptMargin is how late past failedAcceptLimit a waiting caller may be accepted. It is
// narrower than margin because nothing between the free and the accept waits on the engine's
// other work: on 2026-10-16 the runners woke a deadline at most 1.2 ms late, and on 2026-10-17
// the reference took at most a few milliseconds from the free to the accept beyond its own
// pause, under the race detector with the listener package running whole. A pause of 1.5 seconds
// is then in reach, which at margin it would not be.
const acceptMargin = 250 * time.Millisecond

// freedDescriptors is how many descriptors a row frees for its two waiting callers. Linux takes a
// descriptor for an accept call before it looks for a waiting connection, so the accept that
// follows one socket's success can hold the last free descriptor for a moment, and the other
// socket's retry in that moment fails; on 2026-10-17 that failed one row in five with two. The
// third leaves a descriptor for the other socket however the two accepts meet.
const freedDescriptors = 3

// The moments, after accepting starts to fail, at which a row frees its descriptors: every
// freeStep from firstFree, freeCount of them, each row in a child of its own.
//
// Why so many: a single free tells nothing of a pause that is too long, because it can fall just
// before a retry. Each row's waiting caller is late when its free falls in the part of a gap
// between retries more than failedAcceptLimit plus acceptMargin, 1.25 s, before the gap ends. A
// gap of length G has a late part G - 1.25 s long; the frees are freeStep, 125 ms, apart across
// 2.875 s, so every gap of 1.375 s or more that lies in that span holds a free in its late part,
// whatever the phase of the engine's timer, and is caught every time. A gap between 1.25 s and
// 1.375 s is caught with probability (G - 1.25 s) / 125 ms. A 1.5-second pause has a late part of
// 250 ms and a 2-second pause one of 750 ms: both are caught every time.
const (
	firstFree = 300 * time.Millisecond
	freeStep  = 125 * time.Millisecond
	freeCount = 24
)

func TestLinuxAcceptFails(t *testing.T) {
	t.Parallel()
	if slices.Contains(os.Args[1:], childArgument) {
		holdListener(t)
		return
	}
	t.Run("If accepting a caller fails, then the engine shall keep serving its open connections and accept again within 1 second.", func(t *testing.T) {
		t.Parallel()
		for index := range freeCount {
			offset := firstFree + time.Duration(index)*freeStep
			t.Run(fmt.Sprintf("two sockets fail, three descriptors freed %v into the failed spell", offset), func(t *testing.T) {
				t.Parallel()
				failedSpell(t, offset)
			})
		}
	})
}

// waitingResult is when a waiting caller's opening came, or why it did not.
type waitingResult struct {
	arrived  time.Time
	received []byte
	err      error
}

// failedSpell fills the child's descriptors with served callers on its two sockets, leaves one
// caller waiting on each, frees descriptors offset into the failed spell, and checks the
// held callers were served throughout and each waiting caller was accepted in time. Each socket
// has a waiting caller, so the accept that failed on each is the one tried again.
func failedSpell(t *testing.T, offset time.Duration) {
	t.Helper()
	child := startChild(t)

	held := make([]caller, child.free)
	streams := make([]*recording, len(held))
	for index := range held {
		held[index] = dial(t, child.addresses[index%len(child.addresses)])
		held[index].readOpening(t, held[index].connected.Add(progressLimit))
		// Recorded from its opening on, so a greeting is timed when it came, however long the
		// rest took to set up.
		if index >= freedDescriptors {
			streams[index] = held[index].record(held[index].connected.Add(negotiationLimit + 2*patient(wideMargin)))
		}
	}

	var waiting []caller
	for _, address := range child.addresses {
		waiting = append(waiting, dial(t, address))
	}
	spell := time.Now()
	results := make([]chan waitingResult, len(waiting))
	for index, call := range waiting {
		results[index] = make(chan waitingResult, 1)
		_ = call.connection.SetReadDeadline(spell.Add(offset + failedAcceptLimit + patient(margin)))
		go func() {
			received := make([]byte, len(opening))
			got, err := io.ReadFull(call.connection, received)
			results[index] <- waitingResult{arrived: time.Now(), received: received[:got], err: err}
		}()
	}

	// The waiting callers' time runs from the moment the descriptors were freed, which can come
	// after the planned one on a loaded runner.
	wait(t, spell.Add(offset))
	freed := time.Now()
	for _, call := range held[:freedDescriptors] {
		_ = call.connection.Close()
	}
	for _, call := range waiting {
		_ = call.connection.SetReadDeadline(freed.Add(failedAcceptLimit + patient(acceptMargin)))
	}
	t.Logf("the descriptors were freed %v after the planned moment", freed.Sub(spell.Add(offset)))

	// The held callers first: a fault that frees descriptors by closing open connections lets
	// the waiting callers in, and is told here for what it is.
	for index, call := range held[freedDescriptors:] {
		stream := streams[index+freedDescriptors]
		<-stream.done
		// A silent caller gets the greeting and the prompt at 3 seconds, then waits for its name,
		// so its recording ends at its own deadline with nothing more.
		if !slices.Equal(stream.received, asked) || !errors.Is(stream.end, os.ErrDeadlineExceeded) {
			t.Fatalf("held caller %d was not served through the failed spell: it got % x and %v, want the greeting and the prompt, then nothing",
				index+freedDescriptors+1, stream.received, stream.end)
		}
		// The faults this line catches show in what a held caller gets, not when, so its
		// greeting has the wider window.
		expectWithin(t, "a held caller's greeting", stream.arrivedAt(t, 0),
			call.dialed.Add(negotiationLimit), call.connected.Add(negotiationLimit+wideMargin))
	}

	for index, result := range results {
		got := <-result
		if got.err != nil || !slices.Equal(got.received, opening) {
			t.Fatalf("the waiting caller on socket %d got % x and %v by 1 second and %v after %d descriptors were freed %v into the failed spell, want % x",
				index+1, got.received, got.err, patient(acceptMargin), freedDescriptors, offset, opening)
		}
		if got.arrived.Before(freed.Add(-early)) {
			t.Fatalf("the waiting caller on socket %d was served %v before any descriptor was freed: accepting had not failed",
				index+1, freed.Sub(got.arrived))
		}
		expectWithin(t, fmt.Sprintf("the waiting caller's opening on socket %d", index+1), got.arrived,
			freed, freed.Add(failedAcceptLimit+acceptMargin))
	}
}

// childListener is what the child named: the descriptors it has free under the limit and the
// addresses of its two listening sockets.
type childListener struct {
	free      int
	addresses []string
	processID int
}

// startChild runs this test binary again as the child, under the descriptor limit. The shell
// sets both the soft and the hard limit, since a Go program raises its soft limit to the hard one
// as it starts.
func startChild(t *testing.T) childListener {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatalf("finding the test binary: %v", err)
	}
	arguments := []string{"sh", strconv.Itoa(descriptorLimit), binary, "-test.run=^TestLinuxAcceptFails$", "-test.count=1"}
	// Under go test -cover the child writes its counters where this binary's own counters go, so
	// the lines only the child runs count as reached; that needs the child to end on its own, not
	// be killed.
	if directory := flag.Lookup("test.gocoverdir"); directory != nil && directory.Value.String() != "" {
		arguments = append(arguments, "-test.gocoverdir="+directory.Value.String())
	}
	child := exec.CommandContext(t.Context(), "sh", append([]string{"-c", `ulimit -n "$1" && shift && exec "$@"`},
		append(arguments, childArgument)...)...)
	child.WaitDelay = patient(5 * time.Second)
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatalf("the child's standard input: %v", err)
	}
	child.Cancel = stdin.Close
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
	timer := time.NewTimer(patient(30 * time.Second))
	defer timer.Stop()
	// The limits are checked before anything the Listener did, so a row red against unbuilt code
	// also shows the child ran under the limit.
	var limits string
	want := strconv.Itoa(descriptorLimit) + " " + strconv.Itoa(descriptorLimit)
	checkLimits := func() {
		if limits != want {
			t.Fatalf("the child's open-file limits were %q, want %d for both", limits, descriptorLimit)
		}
	}
	// The shell runs the binary with exec, so the shell's process is the child's own.
	named := childListener{processID: child.Process.Pid}
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
			if value, found := strings.CutPrefix(line, "free="); found {
				named.free, err = strconv.Atoi(value)
				if err != nil {
					t.Fatalf("the child named its free descriptors as %q", value)
				}
			}
			if value, found := strings.CutPrefix(line, "addresses="); found {
				checkLimits()
				named.addresses = strings.Fields(value)
				if len(named.addresses) != 2 || named.free <= freedDescriptors || named.free >= connectionCap {
					t.Fatalf("the child named %d free descriptors and the addresses %q", named.free, value)
				}
				return named
			}
		case <-timer.C:
			t.Fatalf("the child named no address within %v", patient(30*time.Second))
		}
	}
}

// holdListener is the child's part: it makes and starts the Listener on two loopback sockets,
// names its limits, its free descriptors and its addresses on standard output, and holds the
// Listener until standard input ends.
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
	var sockets []*net.TCPListener
	var addresses []string
	for range 2 {
		opened, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listening on loopback: %v", err)
		}
		socket, isTCP := opened.(*net.TCPListener)
		if !isTCP {
			t.Fatalf("the listening socket is a %T", opened)
		}
		sockets = append(sockets, socket)
		addresses = append(addresses, socket.Addr().String())
	}
	engine, err := listener.New(sockets, openTelnet, listener.NewCount())
	if err != nil {
		for _, socket := range sockets {
			_ = socket.Close()
		}
		announce(t, "start_failed="+err.Error())
		return
	}
	defer engine.Stop()
	engine.Start()
	// The limit caps a descriptor's number, not how many are open, so only those numbered below
	// it take a place: a runner can hand the child higher ones, as GitHub's Linux runners do.
	// The listing holds the descriptor it was read through, which is closed again after.
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("listing the child's descriptors: %v", err)
	}
	held := 0
	for _, entry := range entries {
		if number, err := strconv.Atoi(entry.Name()); err == nil && number < descriptorLimit {
			held++
		}
	}
	announce(t, "free="+strconv.Itoa(descriptorLimit-(held-1)))
	announce(t, "addresses="+strings.Join(addresses, " "))
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func announce(t *testing.T, line string) {
	t.Helper()
	if _, err := os.Stdout.WriteString(line + "\n"); err != nil {
		t.Fatalf("writing to the parent: %v", err)
	}
}
