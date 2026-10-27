// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The pause after a failed accept, told by the processor time the Listener's process spends: the
// Listener runs in a child process under a descriptor limit, as in the failed-accept rows, and an
// accept loop that tries again with no pause spends a whole processor while accepting keeps
// failing. Only Linux gives a process's times this way, so the test is named for it.
package listener_test

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// pauseSpell is how long the row lets accepting keep failing before it reads the child's time.
const pauseSpell = 2 * time.Second

// busyTicks is the most processor time, in the kernel's clock ticks of 10 ms, the child may spend
// across pauseSpell. On 2026-10-22 a Listener that paused spent at most 1 tick in every spell,
// under the race detector with the listener package running whole, on both Linux runners and on
// an 8-processor machine; one accept loop that never paused spent about 220. The limit sits far
// from both.
const busyTicks = 20

func TestLinuxAcceptPause(t *testing.T) {
	t.Parallel()
	t.Run("If accepting a caller fails, then the engine shall wait at least 5 milliseconds before it accepts again.", func(t *testing.T) {
		t.Parallel()
		t.Run("both sockets fail, one that has accepted and one that never has: little processor time across 2 seconds", func(t *testing.T) {
			t.Parallel()
			pausedSpell(t)
		})
	})
}

// pausedSpell fills the child's free descriptors with callers on its first socket and leaves one
// caller waiting on the second. Linux takes a descriptor for an accept call before it looks for a
// waiting connection, so the first socket fails too once the descriptors are used up, though no
// caller waits there. Each socket's accept loop keeps its own pause, so the row reaches the pause
// after an accept on the first socket and the first pause on the second, which has never accepted.
func pausedSpell(t *testing.T) {
	t.Helper()
	child := startChild(t)
	held := make([]caller, child.free)
	for index := range held {
		held[index] = dial(t, child.addresses[0])
		held[index].readOpening(t, held[index].connected.Add(progressLimit))
	}
	waiting := dial(t, child.addresses[1])
	before := processorTicks(t, child.processID)
	wait(t, time.Now().Add(pauseSpell))
	spent := processorTicks(t, child.processID) - before

	// A waiting caller the engine served shows the descriptors were not used up, so nothing was
	// measured but an idle Listener.
	_ = waiting.connection.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if got, err := waiting.connection.Read(make([]byte, 1)); got > 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the waiting caller got %d bytes and %v during the spell: accepting had not failed", got, err)
	}
	if spent > busyTicks {
		t.Fatalf("the child spent %d clock ticks of processor time across %v of failed accepts, want at most %d: an accept loop did not pause",
			spent, pauseSpell, busyTicks)
	}
}

// processorTicks is the user and system time of all the child's threads, in clock ticks, from
// fields 14 and 15 of its stat file; the fields are counted after the command's closing
// parenthesis, since the command may hold spaces.
func processorTicks(t *testing.T, processID int) int {
	t.Helper()
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(processID) + "/stat")
	if err != nil {
		t.Fatalf("reading the child's times: %v", err)
	}
	text := string(stat)
	fields := strings.Fields(text[strings.LastIndexByte(text, ')')+1:])
	if len(fields) < 13 {
		t.Fatalf("the child's stat file has %d fields after the command", len(fields))
	}
	user, userErr := strconv.Atoi(fields[11])
	system, systemErr := strconv.Atoi(fields[12])
	if userErr != nil || systemErr != nil {
		t.Fatalf("the child's times read %q and %q", fields[11], fields[12])
	}
	return user + system
}
