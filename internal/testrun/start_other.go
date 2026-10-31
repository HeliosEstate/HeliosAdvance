// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows && !linux

package testrun

import (
	"errors"
	"io/fs"
)

// processStart cannot tell a process's start on a system the engine does not ship to, so a sweep
// there leaves every run's folder alone.
func processStart(int) (int64, error) {
	return 0, errors.ErrUnsupported
}

func processGone(error) bool {
	return false
}

// mine cannot tell a folder's owner on a system the engine does not ship to; a sweep there
// takes no folder anyway.
func mine(fs.FileInfo) bool {
	return true
}

// serverRunsIn is not checked on a system the engine does not ship to.
func serverRunsIn(string) (bool, error) {
	return true, nil
}
