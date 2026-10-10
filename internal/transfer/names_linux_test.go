// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The symbolic link rows of issue #141, on Linux only: an unelevated Windows process
// cannot make a symbolic link, and the loop's Windows machine is unelevated. Each link is
// relative, so a refusal is for where it points and not for being absolute, which os.Root
// refuses as well.
package transfer_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/transfer"
)

const lineLinkOut = "When a sender names a file after a symbolic link in the download folder that points outside it, the receive cancels the transfer with `ErrNameRefused` and writes nothing outside the folder."

// The outside targets: one that exists beside the download folder and one that does not.
const (
	outsideFile = "outside.bin"
	missingFile = "missing.bin"
)

// mustLinkReport makes download/report.bin a relative symbolic link to target.
func mustLinkReport(t *testing.T, download, target string) {
	t.Helper()
	if err := os.Symlink(target, filepath.Join(download, "report.bin")); err != nil {
		t.Fatal(err)
	}
}

func TestReceiveRefusesLinkOut(t *testing.T) {
	t.Parallel()
	t.Run(lineLinkOut, func(t *testing.T) {
		t.Parallel()
		rows := []struct {
			name    string
			command []string
			target  string
			opt     transfer.Options
		}{
			{"ZMODEM, a link to a file outside", []string{"sz", "-b", "-q"}, outsideFile, transfer.Options{}},
			{"ZMODEM, a link to a missing file outside", []string{"sz", "-b", "-q"}, missingFile, transfer.Options{}},
			{"ZMODEM with resume, a link to a shorter file outside", []string{"sz", "-b", "-q", "-r"}, outsideFile, transfer.Options{Resume: true}},
			{"YMODEM, a link to a file outside", []string{"sb", "-b", "-q"}, outsideFile, transfer.Options{Protocol: transfer.YMODEM}},
			{"YMODEM, a link to a missing file outside", []string{"sb", "-b", "-q"}, missingFile, transfer.Options{Protocol: transfer.YMODEM}},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				far := t.TempDir()
				parent, download := newDownloadFolder(t)
				src := mustWriteRandom(t, far, "report.bin", 150_000, mtime)
				whole, err := os.ReadFile(src)
				if err != nil {
					t.Fatal(err)
				}
				// The outside file is the sent file's first part, so a resume through the link
				// would append the rest to it.
				if err := os.WriteFile(filepath.Join(parent, outsideFile), whole[:60_000], 0o600); err != nil {
					t.Fatal(err)
				}
				mustLinkReport(t, download, filepath.Join("..", row.target))
				before := folderState(t, parent)
				sender, wait := oracle(t, far, append(row.command, "report.bin")...)
				got, err := transfer.Receive(withinNameRow(t), sender, download, row.opt)
				// The sender's exit is not the line: a cancelled sz and an abandoned one both
				// fail.
				_, _ = wait()
				if !errors.Is(err, transfer.ErrNameRefused) {
					t.Errorf("Receive returned %+v, %v; want ErrNameRefused", got, err)
				}
				if after := folderState(t, parent); after != before {
					t.Errorf("the folder changed\nbefore:\n%s\nafter:\n%s", before, after)
				}
			})
		}
		t.Run("edge: a link to another file inside the folder", func(t *testing.T) {
			t.Parallel()
			far := t.TempDir()
			_, download := newDownloadFolder(t)
			src := mustWriteRandom(t, far, "report.bin", 5000, mtime)
			mustWriteRandom(t, download, "inner.bin", 100, mtime)
			mustLinkReport(t, download, "inner.bin")
			sender, wait := oracle(t, far, "sz", "-b", "-q", "report.bin")
			got, err := transfer.Receive(withinNameRow(t), sender, download, transfer.Options{})
			if err != nil {
				t.Fatalf("Receive: %v", err)
			}
			if stderr, err := wait(); err != nil {
				t.Fatalf("sz exited %v: %s", err, stderr)
			}
			mustReceiveUnder(t, got, download, "report.bin", src)
			if mustSum(t, filepath.Join(download, "inner.bin")) != mustSum(t, src) {
				t.Fatal("the link's target inside the folder does not hold the received bytes")
			}
		})
	})
}

func TestXMODEMRefusesLinkOut(t *testing.T) {
	t.Parallel()
	t.Run(lineXMODEMName, func(t *testing.T) {
		t.Parallel()
		for _, target := range []string{outsideFile, missingFile} {
			t.Run("a link to "+target, func(t *testing.T) {
				t.Parallel()
				parent, download := newDownloadFolder(t)
				mustWriteRandom(t, parent, outsideFile, 3000, mtime)
				mustLinkReport(t, download, filepath.Join("..", target))
				mustRefuseXMODEMName(t, parent, download, "report.bin")
			})
		}
	})
}
