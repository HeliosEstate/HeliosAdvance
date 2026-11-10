// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The rows of the two read-bound lines: an oversized bootstrap file or key file, refused with the
// line's error, and no more than the line's bound of it read. Each system runs the same rows and
// proves what it can tell: on Linux a row runs again in a child under strace, which names the file
// behind every read, and bounds the bytes read from the line's file; on Windows a row proves the
// refusal alone, since nothing there tells what Open read of one file, and Open reads both files
// with the same code on both systems.
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

// readBoundLine is one read-bound line, word for word, and its rows.
type readBoundLine struct {
	line string
	rows []readBoundRow
}

// readBoundRow is one oversized folder: the row's case and refusal, the folder it makes, the
// folder's file the line bounds, the bound, and the bound in words for the row's name on Linux.
type readBoundRow struct {
	name  string
	make  func(t *testing.T) *layout
	file  string
	most  uint32
	bound string
	want  error
}

func readBoundLines() []readBoundLine {
	return []readBoundLine{
		{
			line: "If the bootstrap file is longer than FileMostBytes, then Open shall return ErrFileTooLarge, having read at most FileMostBytes and one byte more of it.",
			rows: []readBoundRow{
				{
					name: "65,537 bytes: ErrFileTooLarge",
					make: func(t *testing.T) *layout {
						t.Helper()
						made := makeFolderWith(t, plaintextOf(t, fileMostBytes+1-sealedOverhead), "")
						expectSize(t, made, fileMostBytes+1)
						return made
					},
					file: fileName, most: fileMostBytes + 1, bound: "65,537 bytes", want: bootstrap.ErrFileTooLarge,
				},
				{
					name: "1 MiB: ErrFileTooLarge",
					make: func(t *testing.T) *layout {
						t.Helper()
						made := makeFolder(t)
						made.writeFile(t, append(made.sealed, make([]byte, 1<<20-len(made.sealed))...))
						return made
					},
					file: fileName, most: fileMostBytes + 1, bound: "65,537 bytes", want: bootstrap.ErrFileTooLarge,
				},
			},
		},
		{
			line: "If the key file is longer than KeyFileMostBytes, is not in the form the package comment gives, or holds a key of 32 zero bytes, then Open shall return ErrKeyFileForm, having read at most KeyFileMostBytes and one byte more of it.",
			rows: []readBoundRow{
				{
					name: "a 1 MiB key file beside a good bootstrap file: ErrKeyFileForm",
					make: func(t *testing.T) *layout {
						t.Helper()
						made := makeFolder(t)
						made.writeKey(t, strings.TrimRight(made.keyText, "\r\n")+strings.Repeat("\n", 1<<20))
						return made
					},
					file: keyFileName, most: keyFileMostBytes + 1, bound: "47 bytes", want: bootstrap.ErrKeyFileForm,
				},
			},
		},
	}
}
