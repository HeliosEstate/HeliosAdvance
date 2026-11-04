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
// whole test binary until go test's own timeout, which names no cause. Generous, since it costs
// time only when something is already stuck; never a time a row judges.
const oracleStepHangs = 12

// BuildBootstrapOracle copies the bootstrap file oracle's Pascal source from the folder source
// into a folder of its own in the run's folder, builds it there with Free Pascal as its README
// says, and runs its self-test, the published AES and GCM vectors: an oracle whose cipher does not
// match the standard makes no file a row trusts. It returns the built oracle's path. A TestMain
// calls it after Enter, with the folder Enter made.
func BuildBootstrapOracle(runFolder, source string) (string, error) {
	folder, err := os.MkdirTemp(runFolder, "bootstrap-oracle-")
	if err != nil {
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
	if err := runOracleStep("the oracle's build by fpc", folder, "fpc", "-O2", "-Sew", "-o"+program, "bootstrapfile.pas"); err != nil {
		return "", err
	}
	path := filepath.Join(folder, program)
	if err := runOracleStep("the oracle's self-test", folder, path, "selftest"); err != nil {
		return "", err
	}
	return path, nil
}

// runOracleStep runs one step of the oracle's build in folder, within its own bound, and says
// whether it failed or hung.
func runOracleStep(step, folder, name string, arguments ...string) error {
	bound := Patient(oracleStepHangs * HangBound)
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()
	command := exec.CommandContext(ctx, name, arguments...)
	command.Dir = folder
	// Ending the step does not end what it started, such as the compiler's own compiler and
	// linker, which would hold the output open.
	command.WaitDelay = Patient(HangBound)
	output, err := command.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%s hung: it had not ended after %v: %s", step, bound, strings.TrimSpace(string(output)))
	}
	if err != nil {
		return fmt.Errorf("%s: %w: %s", step, err, strings.TrimSpace(string(output)))
	}
	return nil
}
