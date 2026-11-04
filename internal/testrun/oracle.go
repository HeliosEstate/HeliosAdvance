// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package testrun

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// oracleStepHangs is how many hang bounds the oracle's build, and then its self-test, may each
// take before a run calls it hung: neither has a time of its own, and a hung one would hold the
// whole test binary until go test's own timeout, ten minutes, which names no cause. The build and
// the self-test together stay well inside it. Not stretched under the race detector, which
// neither runs under; never a time a row judges.
const oracleStepHangs = 12

// BuildBootstrapOracle builds the bootstrap file oracle with Free Pascal from its source in the
// folder source, as its README says, into a folder of its own in the run's folder, units and
// program both, so the source folder is only read; then it runs the oracle's self-test, the
// published AES and GCM vectors: an oracle whose cipher does not match the standard makes no file
// a row trusts. It returns the built oracle's path. A TestMain calls it after Enter, with the
// folder Enter made.
func BuildBootstrapOracle(runFolder, source string) (string, error) {
	folder, err := os.MkdirTemp(runFolder, "bootstrap-oracle-")
	if err != nil {
		return "", err
	}
	// Each step runs in the oracle's folder, so a relative name would be read from there.
	if folder, err = filepath.Abs(folder); err != nil {
		return "", err
	}
	main, err := filepath.Abs(filepath.Join(source, "bootstrapfile.pas"))
	if err != nil {
		return "", err
	}
	program := filepath.Join(folder, "bootstrap-file")
	if runtime.GOOS == "windows" {
		program += ".exe"
	}
	if _, err := exec.LookPath("fpc"); err != nil {
		return "", fmt.Errorf("the Free Pascal compiler, fpc, is not on the PATH: %w", err)
	}
	if err := runOracleStep("the oracle's build by fpc", folder, "fpc", "-O2", "-Sew", "-FE"+folder, "-FU"+folder,
		"-o"+program, main); err != nil {
		return "", err
	}
	if err := runOracleStep("the oracle's self-test", folder, program, "selftest"); err != nil {
		return "", err
	}
	return program, nil
}

// runOracleStep runs one step of the oracle's build in folder, within its own bound, and says
// whether it failed or hung. A step that ended well is clean even when what it started still
// held its output when the wait for that ran out.
func runOracleStep(step, folder, name string, arguments ...string) error {
	bound := oracleStepHangs * HangBound
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()
	command := exec.CommandContext(ctx, name, arguments...)
	command.Dir = folder
	// Ending a step does not end what it started, such as the compiler's own compiler and linker,
	// which would hold the output open; after this, the output is closed and the wait ends.
	command.WaitDelay = HangBound
	output, err := command.CombinedOutput()
	if err == nil || errors.Is(err, exec.ErrWaitDelay) {
		return nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%s hung: it had not ended after %v: %s", step, bound, strings.TrimSpace(string(output)))
	}
	return fmt.Errorf("%s: %w: %s", step, err, strings.TrimSpace(string(output)))
}
