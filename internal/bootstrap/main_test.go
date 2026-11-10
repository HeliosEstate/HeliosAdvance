// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The run's start for the bootstrap folder's tests: its own folder, and the bootstrap file oracle
// built there from oracle/bootstrap-file with Free Pascal and self-tested, once for the run. Every
// bootstrap file a row opens, good or broken, is the oracle's. A read-bound row's child under
// strace, on Linux, has neither: it only opens the folder its parent made, so it makes nothing on
// disk and needs no oracle.
package bootstrap_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// errorIndex is err's place in openErrors; -1 for an error that is none of them.
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

func TestMain(tests *testing.M) {
	if _, child := childFolder(); child {
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
	oraclePath, oracleFailure = testrun.BuildBootstrapOracle(runFolder, filepath.Join("..", "..", "oracle", "bootstrap-file"))
	code := tests.Run()
	// Logged, not failed: whether Windows has let go of every file by now is its timing.
	if err := testrun.Leave(runFolder); err != nil {
		fmt.Fprintf(os.Stderr, "removing the run's own folder: %v\n", err)
	}
	os.Exit(code)
}
