// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package testrun

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// stopPrograms ends every process whose program file is in the run's folder: an engine a killed
// run started keeps its lease and listens until something ends it.
func stopPrograms(folder string) error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	var failures []error
	for _, entry := range entries {
		processID, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		// Another user's process cannot be read, and one that has just ended has no program
		// file left: neither is the run's.
		program, err := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		if err != nil || !strings.HasPrefix(program, folder+string(filepath.Separator)) {
			continue
		}
		// A process that ended between the read and the kill is what the kill was for.
		if err := syscall.Kill(processID, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			failures = append(failures, fmt.Errorf("ending %s: %w", program, err))
		}
	}
	return errors.Join(failures...)
}
