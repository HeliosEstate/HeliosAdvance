// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package testrun

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const (
	// endWaitMilliseconds is how long a dead run's program may take to end once told to: until it
	// has, its executable keeps the run's folder from being removed. Windows announces the end,
	// so this bounds a hang only.
	endWaitMilliseconds = 10_000
	// mostProcesses bounds the list of process numbers Windows is asked for.
	mostProcesses = 1 << 16
	// processIDBytes is the size of one process number in that list.
	processIDBytes = 4
)

// stopPrograms ends every process whose program file is in the run's folder, as on Linux: an
// engine a killed run started keeps its lease and listens until something ends it. Windows names
// a program by the path it was started from, which the run built from this same folder name.
func stopPrograms(folder string) error {
	processIDs := make([]uint32, mostProcesses)
	var written uint32
	if err := windows.EnumProcesses(processIDs, &written); err != nil {
		return err
	}
	count := int(written) / processIDBytes
	if count == mostProcesses {
		return fmt.Errorf("%d processes or more are running, too many to look through", mostProcesses)
	}
	prefix := folder + string(filepath.Separator)
	name := make([]uint16, windows.MAX_LONG_PATH)
	var failures []error
	for _, processID := range processIDs[:count] {
		failures = append(failures, stopIfUnder(processID, prefix, name))
	}
	return errors.Join(failures...)
}

// stopIfUnder ends the process if its program file is under the prefix, and waits for it to end.
func stopIfUnder(processID uint32, prefix string, name []uint16) (err error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, processID)
	if err != nil {
		// Another user's process, a protected one, or one that has just ended: none is the run's.
		return nil
	}
	defer func() { err = errors.Join(err, windows.CloseHandle(handle)) }()
	size := uint32(windows.MAX_LONG_PATH)
	if err := windows.QueryFullProcessImageName(handle, 0, &name[0], &size); err != nil {
		return nil
	}
	program := windows.UTF16ToString(name[:size])
	// Windows compares names ignoring case.
	if len(program) <= len(prefix) || !strings.EqualFold(program[:len(prefix)], prefix) {
		return nil
	}
	// A program already ending refuses to be ended again, and the wait below tells that apart.
	terminated := windows.TerminateProcess(handle, 1)
	event, err := windows.WaitForSingleObject(handle, endWaitMilliseconds)
	if err != nil {
		return fmt.Errorf("waiting for %s to end: %w", program, err)
	}
	if event != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("%s had not ended %d ms after it was told to: %w", program, endWaitMilliseconds, terminated)
	}
	return nil
}
