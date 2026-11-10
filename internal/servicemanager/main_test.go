// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests of the service manager's contract, through its exported names: whether Windows' service
// manager started the process, running under it as a Windows service registered with sc.exe and
// read with sc.exe query, and systemd's ready message on a socket the test binds. The service is
// this test binary run again by the service manager, and a first call to the ready message is
// the process's own, so those rows run the test binary again too.
package servicemanager_test

import (
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// serviceChild marks the test binary started by Windows' service manager as the helper of the
// Windows service rows; the argument after it is the test's port.
const serviceChild = "service-child"

func TestMain(tests *testing.M) {
	// A child, the ready message's or the service's helper, runs its part and ends: the parent's
	// run folder already holds it.
	if slices.Contains(os.Args[1:], notifyChild) || slices.Contains(os.Args[1:], serviceChild) {
		os.Exit(tests.Run())
	}
	runFolder, swept, err := testrun.Enter()
	if swept != nil {
		fmt.Fprintf(os.Stderr, "what dead runs left: %v\n", swept)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "the run's own folder: %v\n", err)
		if err := testrun.Leave(runFolder); err != nil {
			fmt.Fprintf(os.Stderr, "removing the run's own folder: %v\n", err)
		}
		os.Exit(1)
	}
	code := tests.Run()
	// Logged, not failed: whether Windows has let go of every file by now is its timing, and the
	// next run takes what is left.
	if err := testrun.Leave(runFolder); err != nil {
		fmt.Fprintf(os.Stderr, "removing the run's own folder: %v\n", err)
	}
	os.Exit(code)
}
