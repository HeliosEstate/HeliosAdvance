// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap_test

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// bytesRead is the bytes this process has read, its ReadTransferCount as the system's own process
// list gives it, and how many bytes this reading of it read: the count comes back over a pipe,
// which this process reads, padded to a fixed width so every reading reads the same. The count
// is asked of another process, since GetProcessIoCounters is reached only through unsafe, which
// the engine's imports refuse.
func bytesRead(t *testing.T) (count int64, length int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testrun.Patient(testrun.HangBound))
	defer cancel()
	query := "'{0:D20}' -f (Get-CimInstance Win32_Process -Filter 'ProcessId=" + strconv.Itoa(os.Getpid()) + "').ReadTransferCount"
	output, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", query).Output()
	if err != nil {
		t.Fatalf("asking for this process's count of bytes read: %v", err)
	}
	count, err = strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64)
	if err != nil {
		t.Fatalf("reading the count %q: %v", output, err)
	}
	return count, int64(len(output))
}
