// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main_test

import (
	"syscall"
	"testing"
)

// keepFromReading holds the file open with no sharing until the row ends, so that no other open
// of it, the program's among them, can read it: Windows' own way for an ordinary user to make a
// file it owns unreadable.
func keepFromReading(t *testing.T, path string) {
	t.Helper()
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatalf("the path %s: %v", path, err)
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ, 0, nil, syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatalf("holding %s with no sharing: %v", path, err)
	}
	t.Cleanup(func() { _ = syscall.CloseHandle(handle) })
}
