// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The run's start for the bootstrap folder's tests: its own folder, and the bootstrap file oracle
// built there from oracle/bootstrap-file with Free Pascal and self-tested, once for the run. Every
// bootstrap file a row opens, good or broken, is the oracle's.
package bootstrap_test

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	oraclePath, oracleFailure = buildOracle(runFolder)
	code := tests.Run()
	// Logged, not failed: whether Windows has let go of every file by now is its timing.
	if err := testrun.Leave(runFolder); err != nil {
		fmt.Fprintf(os.Stderr, "removing the run's own folder: %v\n", err)
	}
	os.Exit(code)
}

// buildOracle copies the oracle's Pascal source into the run's folder, builds it there as its
// README says, and runs its self-test, the published AES and GCM vectors: an oracle whose cipher
// does not match the standard makes no file a row trusts.
func buildOracle(runFolder string) (string, error) {
	source := filepath.Join("..", "..", "oracle", "bootstrap-file")
	folder := filepath.Join(runFolder, "oracle")
	if err := os.Mkdir(folder, 0o700); err != nil {
		return "", err
	}
	names, err := filepath.Glob(filepath.Join(source, "*.pas"))
	if err != nil || len(names) == 0 {
		return "", fmt.Errorf("no Pascal source in %s: %w", source, errors.Join(err, os.ErrNotExist))
	}
	for _, name := range names {
		text, err := os.ReadFile(name)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(folder, filepath.Base(name)), text, 0o600); err != nil {
			return "", err
		}
	}
	program := "bootstrap-file"
	if runtime.GOOS == "windows" {
		program += ".exe"
	}
	if _, err := exec.LookPath("fpc"); err != nil {
		return "", fmt.Errorf("the Free Pascal compiler, fpc, is not on the PATH: %w", err)
	}
	build := exec.CommandContext(context.Background(), "fpc", "-O2", "-Sew", "-o"+program, "bootstrapfile.pas")
	build.Dir = folder
	if output, err := build.CombinedOutput(); err != nil {
		return "", fmt.Errorf("fpc: %w: %s", err, strings.TrimSpace(string(output)))
	}
	path := filepath.Join(folder, program)
	selftest := exec.CommandContext(context.Background(), path, "selftest")
	if output, err := selftest.CombinedOutput(); err != nil {
		return "", fmt.Errorf("the oracle's self-test: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return path, nil
}
