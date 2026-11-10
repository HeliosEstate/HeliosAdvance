// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// What Open reads of an oversized file: no more than its limit and one byte. How a row learns
// what Open read of that one file is each system's own, in expectReadAtMost: on Linux the row
// runs again in a child under strace, which names the file behind every read; on Windows the
// file is locked from the byte past the limit onward while Open reads it.
package bootstrap_test

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/bootstrap"
)

// readBoundChild marks the run of this test binary that is a row's child under strace, on Linux:
// an argument after the test flags, which the testing package leaves alone, followed by the
// bootstrap folder the child opens.
const readBoundChild = "read-bound-child"

// childFolder is the bootstrap folder this run opens when it is a row's child, and whether it is
// one.
func childFolder() (string, bool) {
	place := slices.Index(os.Args, readBoundChild)
	if place < 0 {
		return "", false
	}
	if place+1 >= len(os.Args) {
		return "", true
	}
	return os.Args[place+1], true
}

// openAsChild, in a row's child, opens the folder the parent made and fails the row unless Open
// refused it with want; it reports whether this run is a child, so the row ends there.
func openAsChild(t *testing.T, want error) bool {
	t.Helper()
	folder, child := childFolder()
	if !child {
		return false
	}
	if folder == "" {
		t.Fatalf("the child was given no bootstrap folder after %s", readBoundChild)
	}
	contents, err := open(t, folder)
	expectError(t, contents, err, want)
	return true
}

func TestReadBound(t *testing.T) {
	t.Parallel()
	t.Run("If the bootstrap file is longer than FileMostBytes, then Open shall return ErrFileTooLarge, having read at most FileMostBytes and one byte more of it.", func(t *testing.T) {
		t.Parallel()
		t.Run("65,537 bytes: ErrFileTooLarge, no more than 65,537 bytes of it read", func(t *testing.T) {
			t.Parallel()
			if openAsChild(t, bootstrap.ErrFileTooLarge) {
				return
			}
			made := makeFolderWith(t, plaintextOf(t, fileMostBytes+1-sealedOverhead), "")
			expectSize(t, made, fileMostBytes+1)
			expectReadAtMost(t, made, fileName, fileMostBytes+1, bootstrap.ErrFileTooLarge)
		})
		t.Run("1 MiB: ErrFileTooLarge, no more than 65,537 bytes of it read", func(t *testing.T) {
			t.Parallel()
			if openAsChild(t, bootstrap.ErrFileTooLarge) {
				return
			}
			made := makeFolder(t)
			made.writeFile(t, append(made.sealed, make([]byte, 1<<20-len(made.sealed))...))
			expectReadAtMost(t, made, fileName, fileMostBytes+1, bootstrap.ErrFileTooLarge)
		})
	})
	t.Run("If the key file is longer than KeyFileMostBytes, is not in the form the package comment gives, or holds a key of 32 zero bytes, then Open shall return ErrKeyFileForm, having read at most KeyFileMostBytes and one byte more of it.", func(t *testing.T) {
		t.Parallel()
		t.Run("a 1 MiB key file beside a good bootstrap file: ErrKeyFileForm, no more than 47 bytes of it read", func(t *testing.T) {
			t.Parallel()
			if openAsChild(t, bootstrap.ErrKeyFileForm) {
				return
			}
			made := makeFolder(t)
			made.writeKey(t, strings.TrimRight(made.keyText, "\r\n")+strings.Repeat("\n", 1<<20))
			expectReadAtMost(t, made, keyFileName, keyFileMostBytes+1, bootstrap.ErrKeyFileForm)
		})
	})
}
