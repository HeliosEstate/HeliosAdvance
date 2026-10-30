// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package testrun

import (
	"errors"
	"io/fs"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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

// mine is whether this user owns the folder: the temporary folder here is this user's own.
func mine(fs.FileInfo) bool {
	return true
}

// serverRunsIn is whether the process postmaster.pid names is the server that wrote it, started
// in the second the file records. A server ended without its file, as by a restart of the
// machine, leaves a number Windows may give to another process, another PostgreSQL server among
// them, which pg_ctl would stop.
func serverRunsIn(data string) bool {
	text, err := readSmall(filepath.Join(data, "postmaster.pid"))
	if err != nil {
		return false
	}
	// Its first line is the server's number, its third the second it started.
	lines := strings.Split(string(text), "\n")
	if len(lines) < 3 {
		return false
	}
	processID, idErr := strconv.Atoi(strings.TrimSpace(lines[0]))
	written, writtenErr := strconv.ParseInt(strings.TrimSpace(lines[2]), 10, 64)
	if idErr != nil || writtenErr != nil {
		return false
	}
	started, err := processStart(processID)
	// The server writes its start inside its main, after Windows made the process, which on a
	// loaded machine may be seconds later, and a live server judged stale is the worse mistake:
	// so a minute is allowed. The other mistake needs a new PostgreSQL, the only process
	// pg_ctl's signal reaches, to be given the number within that minute of the old start.
	late := written - started/int64(time.Second)
	return err == nil && late >= 0 && late <= 60
}
