// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows && !linux

package testrun

import "errors"

// processStart cannot tell a process's start on a system the engine does not ship to, so a sweep
// there leaves every run's folder alone.
func processStart(int) (int64, error) {
	return 0, errors.ErrUnsupported
}

func processGone(error) bool {
	return false
}
