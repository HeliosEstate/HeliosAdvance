// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package testrun

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
)

// processStart is when the process with the number started, in clock ticks since boot.
func processStart(processID int) (int64, error) {
	text, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", processID))
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
