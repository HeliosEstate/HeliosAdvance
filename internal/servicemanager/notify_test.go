// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package servicemanager_test

import (
	"context"
	"flag"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/servicemanager"
	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// notifyChild marks the test binary run again to send the ready message; the argument after it
// is how many times to call NotifySystemdReady.
const notifyChild = "notify-child"

// notifyChildCalls says whether this process is such a child, and how many calls it makes.
func notifyChildCalls(t *testing.T) (calls int, isChild bool) {
	t.Helper()
	position := slices.Index(os.Args, notifyChild)
	if position < 0 {
		return 0, false
	}
	if position+1 >= len(os.Args) {
		t.Fatal("a notify child was started without its count of calls")
	}
	calls, err := strconv.Atoi(os.Args[position+1])
	if err != nil {
		t.Fatalf("a notify child's count of calls: %v", err)
	}
	return calls, true
}

// sendAsChild is the child's whole run: it calls NotifySystemdReady as often as it was told, and
// ends.
func sendAsChild(calls int) {
	for range calls {
		servicemanager.NotifySystemdReady()
	}
}

// notifySocket is what a child's NOTIFY_SOCKET holds: unset, or set to its value, empty included.
type notifySocket struct {
	set   bool
	value string
}

// runNotifyChild runs the test binary again as a child that calls NotifySystemdReady calls times,
// in the folder given (or this one when empty), with NOTIFY_SOCKET as given, and waits for it to
// end, up to the hang bound. Its environment is this process's with NOTIFY_SOCKET replaced, built
// from the whole environment, since the engine's rules let no code read a variable by name.
func runNotifyChild(t *testing.T, testName string, socket notifySocket, folder string, calls int) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatalf("finding the test binary: %v", err)
	}
	arguments := []string{"-test.run=^" + testName + "$", "-test.count=1"}
	// Under go test -cover the child writes its counters where this binary's own go, so the
	// lines only the child runs count as reached.
	if directory := flag.Lookup("test.gocoverdir"); directory != nil && directory.Value.String() != "" {
		arguments = append(arguments, "-test.gocoverdir="+directory.Value.String())
	}
	arguments = append(arguments, notifyChild, strconv.Itoa(calls))
	bound := testrun.Patient(testrun.HangBound)
	ctx, cancel := context.WithTimeout(t.Context(), bound)
	defer cancel()
	child := exec.CommandContext(ctx, binary, arguments...)
	child.Dir = folder
	child.WaitDelay = bound
	child.Env = slices.DeleteFunc(os.Environ(), func(variable string) bool {
		return strings.HasPrefix(variable, "NOTIFY_SOCKET=")
	})
	if socket.set {
		child.Env = append(child.Env, "NOTIFY_SOCKET="+socket.value)
	}
	// The race detector holds a process a second at its end by default.
	if testrun.Race {
		child.Env = append(child.Env, "GORACE=atexit_sleep_ms=0")
	}
	output, err := child.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("the notify child had not ended within %v: %s", bound, output)
	}
	if err != nil {
		t.Fatalf("the notify child failed: %v: %s", err, output)
	}
}
