// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap_test

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// bytesRead is the bytes this process has read, rchar in /proc/self/io, and how many bytes this
// reading of it read.
func bytesRead(t *testing.T) (count int64, length int64) {
	t.Helper()
	text, err := os.ReadFile("/proc/self/io")
	if err != nil {
		t.Fatalf("reading this process's count of bytes read: %v", err)
	}
	for _, line := range strings.Split(string(text), "\n") {
		if value, found := strings.CutPrefix(line, "rchar: "); found {
			count, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				t.Fatalf("reading rchar %q: %v", value, err)
			}
			return count, int64(len(text))
		}
	}
	t.Fatalf("no rchar in /proc/self/io: %q", text)
	return 0, 0
}
