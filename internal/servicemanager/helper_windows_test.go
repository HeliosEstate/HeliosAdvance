// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package servicemanager_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/servicemanager"
)

// The helper is this test binary, started by Windows' service manager with serviceChild and the
// test's loopback port. It is a caller of the package's contract, run as a real service, and it
// tells the test over that connection what the contract handed it, and does what the test says.
// The test reads the service's state from sc.exe, so the helper reports only what sc.exe cannot
// see. What it writes to the test, one line each:
//
//	started <true|false> <error>    what StartedByWindowsServiceManager returned
//	run <n>                         run was called, for the nth time
//	readied                         ready returned, once per "ready" the test sent
//	stop-ended                      run's stop context ended
//	returned <code> <error> <runs>  what RunWindowsService returned, and how often run was called
//	alive                           a call to ready kept from run, made after RunWindowsService
//	                                returned, has itself returned
//
// What the test writes to it: "ready" to call ready, "return <code>" to make run return that code.
const (
	// helperDialBound bounds the helper's connection to the test, which already listens when it
	// starts the service: a helper that cannot reach it ends, and the row fails on its wait.
	helperDialBound = 10 * time.Second
	// mostCommand bounds a line the test writes: "return" and a code.
	mostCommand = 64
)

// serviceChildPort says whether this process is the helper, and the test's port it reports to.
func serviceChildPort(t *testing.T) (port int, isChild bool) {
	t.Helper()
	position := slices.Index(os.Args, serviceChild)
	if position < 0 {
		return 0, false
	}
	if position+1 >= len(os.Args) {
		t.Fatal("the helper was started without the test's port")
	}
	port, err := strconv.Atoi(os.Args[position+1])
	if err != nil {
		t.Fatalf("the helper's port: %v", err)
	}
	return port, true
}

// serveAsHelper is the helper's whole run.
func serveAsHelper(port int) {
	// Asked first, before anything that can fail, as the contract asks of its callers.
	started, startedErr := servicemanager.StartedByWindowsServiceManager()
	var dialer net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), helperDialBound)
	defer cancel()
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return
	}
	defer func() { _ = connection.Close() }()
	helper := &helper{connection: connection, commands: make(chan string)}
	go helper.read()
	helper.write("started %t %s", started, errorName(startedErr))
	code, runErr := servicemanager.RunWindowsService(helper.run)
	helper.write("returned %d %s %d", code, errorName(runErr), helper.runs)
	// The contract says a call to ready after run has returned does nothing: the call must come
	// back, without a panic or a hang, for "alive" to reach the test.
	if helper.kept != nil {
		helper.kept()
		helper.write("alive")
	}
}

// helper is the run the contract hands RunWindowsService, and the test's connection.
type helper struct {
	connection net.Conn
	commands   chan string
	writing    sync.Mutex
	// runs and kept are written by run and read once RunWindowsService has returned, after run
	// has returned.
	runs int
	kept servicemanager.Ready
}

// run reports each call, does what the test says, and reports when stop ends.
func (helper *helper) run(stop context.Context, ready servicemanager.Ready) int {
	helper.runs++
	helper.kept = ready
	helper.write("run %d", helper.runs)
	stopEnded := stop.Done()
	for {
		select {
		case <-stopEnded:
			helper.write("stop-ended")
			stopEnded = nil
		case command, open := <-helper.commands:
			if !open {
				// The test has gone: nothing is left to report to.
				return 2
			}
			if command == "ready" {
				ready()
				helper.write("readied")
				continue
			}
			if text, found := strings.CutPrefix(command, "return "); found {
				if code, err := strconv.Atoi(text); err == nil {
					return code
				}
			}
			helper.write("unknown %q", command)
		}
	}
}

// read hands each line the test writes to run, and closes commands when the connection ends.
func (helper *helper) read() {
	defer close(helper.commands)
	lines := bufio.NewScanner(helper.connection)
	lines.Buffer(make([]byte, mostCommand), mostCommand)
	for lines.Scan() {
		helper.commands <- lines.Text()
	}
}

// write sends one line to the test. A write that fails is left to the test, whose wait for the
// line then fails the row.
func (helper *helper) write(format string, arguments ...any) {
	helper.writing.Lock()
	defer helper.writing.Unlock()
	_, _ = fmt.Fprintf(helper.connection, format+"\n", arguments...)
}

// errorName names an error by the contract's error it is, so the test matches it as errors.Is
// would.
func errorName(err error) string {
	switch {
	case err == nil:
		return "nil"
	case errors.Is(err, servicemanager.ErrStartedHowUnknown):
		return "ErrStartedHowUnknown"
	case errors.Is(err, servicemanager.ErrServiceManagerConnect):
		return "ErrServiceManagerConnect"
	default:
		return "other"
	}
}
