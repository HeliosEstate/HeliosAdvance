// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package testrun

import (
	"errors"
	"math"
	"syscall"
)

const (
	processQueryLimitedInformation = 0x1000
	stillActive                    = 259
	// OpenProcess answers this for a number no process has, where Linux would say none exists.
	errorInvalidParameter syscall.Errno = 87
)

var errProcessExited = errors.New("the process has exited")

// processStart is when the process with the number started, as Windows counts it.
func processStart(processID int) (started int64, err error) {
	if processID < 0 || processID > math.MaxUint32 {
		return 0, errorInvalidParameter
	}
	handle, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(processID))
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, syscall.CloseHandle(handle)) }()
	// A process that has exited keeps its number while anything holds it open, so ending is
	// read from its exit code, not only from its number being free.
	var code uint32
	if err := syscall.GetExitCodeProcess(handle, &code); err != nil {
		return 0, err
	}
	if code != stillActive {
		return 0, errProcessExited
	}
	var creation, exit, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return 0, err
	}
	return creation.Nanoseconds(), nil
}

// processGone is whether an error from processStart says the process has ended, not that it
// could not be told.
func processGone(err error) bool {
	return errors.Is(err, errorInvalidParameter) || errors.Is(err, errProcessExited)
}
