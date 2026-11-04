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
	"time"
)

// bootstrapOracleBound is how long the bootstrap file oracle's build and its self-test may take
// together before a run calls them hung: neither has a time of its own, and a hung one would hold
// the whole test binary until go test's own timeout, which names no cause. Generous, since it
// costs time only when something is already stuck; never a time a row judges.
const bootstrapOracleBound = 2 * time.Minute

// BuildBootstrapOracle copies the bootstrap file oracle's Pascal source from the folder source
// into the run's folder, builds it there with Free Pascal as its README says, and runs its
// self-test, the published AES and GCM vectors: an oracle whose cipher does not match the
// standard makes no file a row trusts. It returns the built oracle's path. A TestMain calls it
// once, after Enter, with the folder Enter made.
func BuildBootstrapOracle(runFolder, source string) (string, error) {
	folder := filepath.Join(runFolder, "bootstrap-oracle")
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
	ctx, cancel := context.WithTimeout(context.Background(), bootstrapOracleBound)
	defer cancel()
	build := exec.CommandContext(ctx, "fpc", "-O2", "-Sew", "-o"+program, "bootstrapfile.pas")
	build.Dir = folder
	if output, err := build.CombinedOutput(); err != nil {
		return "", fmt.Errorf("fpc, bounded at %v: %w: %s", bootstrapOracleBound, err, strings.TrimSpace(string(output)))
	}
	path := filepath.Join(folder, program)
	if output, err := exec.CommandContext(ctx, path, "selftest").CombinedOutput(); err != nil {
		return "", fmt.Errorf("the oracle's self-test, bounded at %v: %w: %s", bootstrapOracleBound, err,
			strings.TrimSpace(string(output)))
	}
	return path, nil
}
