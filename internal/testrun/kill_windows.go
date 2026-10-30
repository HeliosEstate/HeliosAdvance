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
	mostProcesses = 1 << 18
	// processIDBytes is the size of one process number in that list.
	processIDBytes = 4
)

// stopPrograms ends every process whose program file is in the run's folder, as on Linux: an
// engine a killed run started keeps its lease and listens until something ends it.
func stopPrograms(folder string) error {
	prefixes := []string{folder + string(filepath.Separator)}
	// A temporary folder may be named in its short form, and a program by its long one.
	if long, err := longPath(folder); err == nil && !strings.EqualFold(long, folder) {
		prefixes = append(prefixes, long+string(filepath.Separator))
	}
	processIDs, err := processes()
	if err != nil {
		return err
	}
	name := make([]uint16, windows.MAX_LONG_PATH)
	var failures []error
	for _, processID := range processIDs {
		failures = append(failures, stopIfUnder(processID, prefixes, name))
	}
	return errors.Join(failures...)
}

// processes is the number of every running process.
func processes() ([]uint32, error) {
	for size := 1024; size <= mostProcesses; size *= 2 {
		processIDs := make([]uint32, size)
		var written uint32
		if err := windows.EnumProcesses(processIDs, &written); err != nil {
			return nil, err
		}
		// A list that fills the buffer may have been cut short, so it is asked for again larger.
		if count := int(written) / processIDBytes; count < size {
			return processIDs[:count], nil
		}
	}
	return nil, fmt.Errorf("more than %d processes are running", mostProcesses)
}

// stopIfUnder ends the process if its program file is under one of the prefixes, and waits for
// it to end.
func stopIfUnder(processID uint32, prefixes []string, name []uint16) (err error) {
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
	if !under(program, prefixes) {
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

// under is whether the program file is in a folder one of the prefixes names, in Windows' way of
// comparing names, which ignores case.
func under(program string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if len(program) > len(prefix) && strings.EqualFold(program[:len(prefix)], prefix) {
			return true
		}
	}
	return false
}

// longPath is the folder's name with every short form expanded.
func longPath(folder string) (string, error) {
	short, err := windows.UTF16PtrFromString(folder)
	if err != nil {
		return "", err
	}
	long := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(short, &long[0], windows.MAX_LONG_PATH)
	if err != nil {
		return "", err
	}
	if int(n) > len(long) {
		return "", errors.New("the folder's long name is longer than Windows allows")
	}
	return windows.UTF16ToString(long[:n]), nil
}
