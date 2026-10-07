// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/windows"
)

// plantWindows is each kind of item the line refuses, planted at a name in the bootstrap folder
// and pointing at the decoy's file of that name, or at the decoy itself for a junction.
var plantWindows = []struct {
	name  string
	plant func(t *testing.T, planted, decoy string)
}{
	{"a symbolic link to a file outside", func(t *testing.T, planted, decoy string) {
		t.Helper()
		if err := os.Symlink(filepath.Join(decoy, filepath.Base(planted)), planted); err != nil {
			t.Fatal(err)
		}
	}},
	{"a junction to a folder outside", func(t *testing.T, planted, decoy string) {
		t.Helper()
		powerShell(t, "New-Item -ItemType Junction -Path '"+planted+"' -Target '"+decoy+"' | Out-Null\n")
	}},
	{"a second name of a file outside", func(t *testing.T, planted, decoy string) {
		t.Helper()
		if err := os.Link(filepath.Join(decoy, filepath.Base(planted)), planted); err != nil {
			t.Fatal(err)
		}
	}},
}

// handleFolders makes a bootstrap folder and a decoy beside it, with no machine key pair of the
// package's name before the row, and removes every one when the row ends.
func handleFolders(t *testing.T) (folder, decoy string) {
	t.Helper()
	removeKeyPairs(t)
	t.Cleanup(func() { removeKeyPairs(t) })
	base := t.TempDir()
	folder, decoy = filepath.Join(base, "folder"), filepath.Join(base, "outside")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	makeDecoy(t, decoy)
	return folder, decoy
}

// TestWindowsElevatedBuildThroughHandle is the Windows rows for the line. It runs on GitHub's
// Windows runner, whose job fails before the tests when the runner is not elevated, and on any
// elevated machine. The rows run one after another: the machine key pair is one per machine.
//
//nolint:paralleltest // the machine key pair is one per machine
func TestWindowsElevatedBuildThroughHandle(t *testing.T) {
	if !elevated(t) {
		t.Skip("needs an elevated process: runs on GitHub's Windows runner, whose job fails when it is not elevated")
	}

	t.Run(lineEveryFileThroughHandle, func(t *testing.T) {
		// The names Build creates, at the first setup, and the name it renames a file over, at a
		// restore, where an old bootstrap file is in the folder.
		for _, target := range []struct {
			name string
			path BuildPath
		}{
			{nameSealedKey, FirstSetup},
			{nameFile + ".new", FirstSetup},
			{nameFile, Restore},
		} {
			for _, kind := range plantWindows {
				t.Run(target.name+", "+kind.name, func(t *testing.T) {
					folder, decoy := handleFolders(t)
					kind.plant(t, filepath.Join(folder, target.name), decoy)
					_, err := build(t, folder, rowFields(), target.path, FromOSStore)
					wantRefusal(t, err, Link)
					wantDecoyUnchanged(t, decoy)
				})
			}
		}

		t.Run("let through: a restore over a bootstrap file of one name", func(t *testing.T) {
			folder, decoy := handleFolders(t)
			old := filepath.Join(folder, nameFile)
			if err := os.WriteFile(old, []byte("an old bootstrap file"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := build(t, folder, rowFields(), Restore, FromOSStore); err != nil {
				t.Fatalf("refused: %v", err)
			}
			if data, err := os.ReadFile(old); err != nil || string(data) == "an old bootstrap file" {
				t.Errorf("the old bootstrap file was not replaced: %v", err)
			}
			wantDecoyUnchanged(t, decoy)
		})

		t.Run("the folder swapped for a junction while Build runs", func(t *testing.T) {
			folder, decoy := handleFolders(t)
			base := filepath.Dir(folder)
			prepared := filepath.Join(base, "prepared")
			powerShell(t, "New-Item -ItemType Junction -Path '"+prepared+"' -Target '"+decoy+"' | Out-Null\n")
			swapAfterFirstFileWindows(t, folder, prepared)
			wantDecoyUnchanged(t, decoy)
		})
	})
}

// swapAfterFirstFileWindows runs Build at a restore and, as soon as Build has made its first file
// in the folder other than the lock, renames the folder away and the prepared junction into its
// place: what the service account can do between Build's checks and its writes. It waits on a
// change notification and on Build's return, never on time.
func swapAfterFirstFileWindows(t *testing.T, folder, prepared string) {
	t.Helper()
	base := filepath.Dir(folder)
	watch, err := windows.FindFirstChangeNotification(base, true, windows.FILE_NOTIFY_CHANGE_FILE_NAME)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.FindCloseChangeNotification(watch) }()
	returned, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(returned) }()
	done := make(chan error, 1)
	go func() {
		_, err := build(t, folder, rowFields(), Restore, FromOSStore)
		done <- err
		_ = windows.SetEvent(returned)
	}()
	swapped := false
	for !swapped {
		event, err := windows.WaitForMultipleObjects([]windows.Handle{watch, returned}, false, windows.INFINITE)
		if err != nil {
			t.Fatal(err)
		}
		if event == windows.WAIT_OBJECT_0+1 {
			t.Fatalf("Build returned before it made a file other than the lock, so the folder was never swapped: %v", <-done)
		}
		entries, err := os.ReadDir(folder)
		if err != nil {
			t.Fatal(err)
		}
		if slices.ContainsFunc(entries, func(entry os.DirEntry) bool { return entry.Name() != nameLock }) {
			// Windows refuses to rename a folder while a file in it is open: a Build that holds
			// its files open cannot have its folder swapped, and the decoy shows the rest.
			if err := os.Rename(folder, filepath.Join(base, "swapped away")); errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				t.Logf("the folder could not be renamed while Build held a file in it: %v", err)
				break
			} else if err != nil {
				t.Fatalf("renaming the folder away: %v", err)
			}
			if err := os.Rename(prepared, folder); err != nil {
				t.Fatalf("renaming the junction into place: %v", err)
			}
			swapped = true
		} else if err := windows.FindNextChangeNotification(watch); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("Build returned %v", <-done)
}
