// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package testrun

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// processStart is when the process with the number started, in clock ticks since boot.
func processStart(processID int) (int64, error) {
	text, err := readSmall(fmt.Sprintf("/proc/%d/stat", processID))
	if err != nil {
		return 0, err
	}
	// The command's name may hold spaces and parentheses, so the fields are counted after its
	// last closing parenthesis: the start time is the twentieth field after it.
	fields := strings.Fields(string(text[bytes.LastIndexByte(text, ')')+1:]))
	if len(fields) < 20 {
		return 0, errors.New("the process's stat holds no start time")
	}
	return strconv.ParseInt(fields[19], 10, 64)
}

// processGone is whether an error from processStart says the process has ended, not that it
// could not be told.
func processGone(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}

// mine is whether this user owns the folder: /tmp is every user's.
func mine(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

// serverRunsIn is whether the process postmaster.pid names is the server of that data folder,
// whose working folder it is. A server ended without its file leaves a number the kernel may
// give to any other process, and pg_ctl would signal that one. Only a process that has ended
// reads as not running; anything that cannot be told is an error, and the folder stays.
func serverRunsIn(data string) (bool, error) {
	text, err := readSmall(filepath.Join(data, "postmaster.pid"))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	line, _, _ := strings.Cut(string(text), "\n")
	processID, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		return false, fmt.Errorf("the server's number in %s: %w", data, err)
	}
	// Compared as folders, not as names: the kernel names the working folder with every
	// symbolic link resolved, and the temporary folder may be reached through one.
	working, err := os.Stat(fmt.Sprintf("/proc/%d/cwd", processID))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	folder, err := os.Stat(data)
	if err != nil {
		return false, err
	}
	return os.SameFile(working, folder), nil
}
