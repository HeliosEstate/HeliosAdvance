// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The run's start for the bootstrap folder's tests: its own folder, and the bootstrap file oracle
// built there from oracle/bootstrap-file with Free Pascal and self-tested, once for the run. Every
// bootstrap file a row opens, good or broken, is the oracle's.
package bootstrap_test

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/bootstrap"
	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// errorIndex is err's place in openErrors, which a child reports its Open's refusal by; -1 for
// an error that is none of them.
func errorIndex(err error) int {
	for index, each := range openErrors {
		if errors.Is(err, each) {
			return index
		}
	}
	return -1
}

// oraclePath is the built oracle, and oracleFailure why it could not be built or failed its
// self-test: a missing oracle fails every row that needs it, never skips it.
var (
	oraclePath    string
	oracleFailure error
)

// openChildFlag makes this test binary a child that opens one folder and says how Open ended,
// for a row that needs Open run by a process with a capability the test's own process lacks.
const openChildFlag = "bootstrap-open-child"

var openChild = flag.String(openChildFlag, "", "open this bootstrap folder, print how Open ended, and exit")

func TestMain(tests *testing.M) {
	flag.Parse()
	if *openChild != "" {
		contents, err := bootstrap.Open(*openChild)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stdout, "refused", errorIndex(err))
			_, _ = fmt.Fprintln(os.Stdout, childReport(*openChild))
		} else {
			_, _ = fmt.Fprintln(os.Stdout, "opened", len(contents))
		}
		os.Exit(0)
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
	oraclePath, oracleFailure = testrun.BuildBootstrapOracle(runFolder, filepath.Join("..", "..", "oracle", "bootstrap-file"))
	code := tests.Run()
	// Logged, not failed: whether Windows has let go of every file by now is its timing.
	if err := testrun.Leave(runFolder); err != nil {
		fmt.Fprintf(os.Stderr, "removing the run's own folder: %v\n", err)
	}
	os.Exit(code)
}

// childReport is what a child that Open refused can say of itself, for a row's failure message:
// the capabilities in effect, on Linux, and how its own read of the key file ended. A child meant
// to hold the capability to read any file that cannot read the key file did not hold it, and
// then its Open proves nothing; this says so.
func childReport(folder string) string {
	capabilities := "unknown"
	if status, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if value, found := strings.CutPrefix(line, "CapEff:"); found {
				capabilities = strings.TrimSpace(value)
			}
		}
	}
	read := "read"
	if _, err := os.ReadFile(filepath.Join(folder, keyFileName)); err != nil {
		read = err.Error()
	}
	return fmt.Sprintf("the child: effective capabilities %s; its own read of the key file: %s", capabilities, read)
}
