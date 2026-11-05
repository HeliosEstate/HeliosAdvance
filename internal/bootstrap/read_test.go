// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap_test

import (
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/bootstrap"
)

// TestReadBound counts every byte this process reads while Open runs, from the system's own
// count for the process, so it runs alone: no other row reads beside it.
func TestReadBound(t *testing.T) { //nolint:paralleltest // it counts every byte this process reads, so no other row may run beside it
	t.Run("If the bootstrap file is longer than FileMostBytes, then Open shall return ErrFileTooLarge, having read at most FileMostBytes and one byte more of it.", func(t *testing.T) { //nolint:paralleltest // it counts every byte this process reads
		t.Run("65,537 bytes: ErrFileTooLarge, at most 65,537 bytes read", func(t *testing.T) { //nolint:paralleltest // it counts every byte this process reads
			made := makeFolderWith(t, plaintextOf(t, fileMostBytes+1-sealedOverhead), "")
			expectSize(t, made, fileMostBytes+1)
			expectReadAtMost(t, made, bootstrap.ErrFileTooLarge, fileMostBytes+1)
		})
		t.Run("1 MiB: ErrFileTooLarge, at most 65,537 bytes read", func(t *testing.T) { //nolint:paralleltest // it counts every byte this process reads
			made := makeFolder(t)
			made.writeFile(t, append(made.sealed, make([]byte, 1<<20-len(made.sealed))...))
			expectReadAtMost(t, made, bootstrap.ErrFileTooLarge, fileMostBytes+1)
		})
	})
	t.Run("If the key file is longer than KeyFileMostBytes, is not in the form the package comment gives, or holds a key of 32 zero bytes, then Open shall return ErrKeyFileForm, having read at most KeyFileMostBytes and one byte more of it.", func(t *testing.T) { //nolint:paralleltest // it counts every byte this process reads
		t.Run("a 1 MiB key file beside a good bootstrap file: ErrKeyFileForm, at most the bootstrap file and 47 bytes read", func(t *testing.T) { //nolint:paralleltest // it counts every byte this process reads
			made := makeFolder(t)
			made.writeKey(t, strings.TrimRight(made.keyText, "\r\n")+strings.Repeat("\n", 1<<20))
			expectReadAtMost(t, made, bootstrap.ErrKeyFileForm, len(made.sealed)+keyFileMostBytes+1)
		})
	})
}

// expectReadAtMost opens the folder, fails the row unless Open refused it with want, and fails it
// when the process read more than most bytes while Open ran. The count's own reading is taken
// out: the bytes the reading before Open read, which the system counts after it. A first pair of
// readings with nothing between proves that is all a reading adds.
func expectReadAtMost(t *testing.T, made *layout, want error, most int) {
	t.Helper()
	first, firstLength := bytesRead(t)
	second, secondLength := bytesRead(t)
	if second-first != firstLength {
		t.Fatalf("two readings of the count with nothing between differ by %d, not the %d bytes the first read: a fault in the test", second-first, firstLength)
	}
	contents, err := open(t, made.folder)
	after, _ := bytesRead(t)
	expectError(t, contents, err, want)
	if read := after - second - secondLength; read > int64(most) {
		t.Fatalf("Open read %d bytes, more than %d", read, most)
	}
}
