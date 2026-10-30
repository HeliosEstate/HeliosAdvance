// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package testrun

import (
	"errors"
	"math"

	"golang.org/x/sys/windows"
)

// stillActive is the exit code Windows gives a process that has not exited.
const stillActive = 259

var errProcessExited = errors.New("the process has exited")

// processStart is when the process with the number started, as Windows counts it.
func processStart(processID int) (started int64, err error) {
	if processID < 0 || processID > math.MaxUint32 {
		return 0, windows.ERROR_INVALID_PARAMETER
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(processID))
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, windows.CloseHandle(handle)) }()
	// A process that has exited keeps its number while anything holds it open, so ending is
	// read from its exit code, not only from its number being free.
	var code uint32
	if err := windows.GetExitCodeProcess(handle, &code); err != nil {
		return 0, err
	}
	if code != stillActive {
		return 0, errProcessExited
	}
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return 0, err
	}
	return creation.Nanoseconds(), nil
}

// processGone is whether an error from processStart says the process has ended, not that it
// could not be told: OpenProcess answers ERROR_INVALID_PARAMETER for a number no process has.
func processGone(err error) bool {
	return errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, errProcessExited)
}
