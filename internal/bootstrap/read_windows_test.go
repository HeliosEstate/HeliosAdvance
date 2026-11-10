// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// expectReadAtMost holds the folder's file named name locked from byte most onward, through a
// handle of its own, while Open reads it, and fails the row unless Open refused the folder with
// want. An Open that reads no more than most bytes of the file never meets the lock; one that
// reads further is refused by the lock and returns another refusal. Before Open, a read of the
// byte at most through a third handle must meet the lock, so a lock that does not hold fails the
// row instead of passing it. The lock refuses a read that reaches it even where the file ends
// before it.
func expectReadAtMost(t *testing.T, made *layout, name string, most uint32, want error) {
	t.Helper()
	path := filepath.Join(made.folder, name)
	lockFrom(t, path, most)
	expectLocked(t, path, most)
	contents, err := open(t, made.folder)
	expectError(t, contents, err, want)
}

// lockFrom holds an exclusive byte-range lock on the file from byte offset onward, 4 GiB long,
// through a handle of its own until the row ends: another handle may read the bytes before it,
// but a read that reaches it fails. The cleanup is registered after the row's folder, so the lock
// and its handle go before the folder does.
func lockFrom(t *testing.T, path string, offset uint32) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening %s to lock it: %v", path, err)
	}
	handle := windows.Handle(file.Fd())
	length := uint32(0xFFFFFFFF)
	lockedRange := func() *windows.Overlapped {
		return &windows.Overlapped{Offset: offset}
	}
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0,
		length, 0, lockedRange()); err != nil {
		_ = file.Close()
		t.Fatalf("locking %s from byte %d: %v", path, offset, err)
	}
	t.Cleanup(func() {
		if err := windows.UnlockFileEx(handle, 0, length, 0, lockedRange()); err != nil {
			t.Errorf("unlocking %s: %v", path, err)
		}
		if err := file.Close(); err != nil {
			t.Errorf("closing %s: %v", path, err)
		}
	})
}

// expectLocked fails the row unless a read of the byte at offset, through a handle of its own,
// meets the lock.
func expectLocked(t *testing.T, path string, offset uint32) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening %s to try the lock: %v", path, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("closing %s: %v", path, err)
		}
	}()
	if _, err := file.ReadAt(make([]byte, 1), int64(offset)); !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		t.Fatalf("reading the byte at %d of %s, which the lock holds, returned %v, not the lock's refusal: a fault in the test", offset, path, err)
	}
}
