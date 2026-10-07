// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// plantLinux is each kind of item the line refuses on Linux, planted at a name in the bootstrap
// folder and pointing at the decoy's file of that name.
var plantLinux = []struct {
	name  string
	plant func(t *testing.T, planted, decoy string)
}{
	{"a symbolic link to a file outside", func(t *testing.T, planted, decoy string) {
		t.Helper()
		if err := os.Symlink(filepath.Join(decoy, filepath.Base(planted)), planted); err != nil {
			t.Fatal(err)
		}
	}},
	{"a second name of a file outside", func(t *testing.T, planted, decoy string) {
		t.Helper()
		if err := os.Link(filepath.Join(decoy, filepath.Base(planted)), planted); err != nil {
			t.Fatal(err)
		}
	}},
}

// handleFoldersLinux makes a bootstrap folder as hadv-setup makes it and a decoy beside it, both
// on the ext4 volume, so a second name can join them.
func handleFoldersLinux(t *testing.T) (folder, decoy string) {
	t.Helper()
	base := buildFolder(t, volume, "")
	folder = filepath.Join(base, "folder")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	decoy = filepath.Join(base, "outside")
	makeDecoy(t, decoy)
	return folder, decoy
}

// TestBuildHandleLinux is the Linux rows for the line, run as root in each booted systemd image
// by TestBuildHandleRowsInContainer.
//
//nolint:paralleltest // the rows share the container's one systemd
func TestBuildHandleLinux(t *testing.T) {
	requireContainer(t)
	if os.Getuid() != 0 {
		t.Fatalf("the Linux rows run as root; running as uid %d", os.Getuid())
	}

	t.Run(lineEveryFileThroughHandle, func(t *testing.T) {
		// The names Build creates, at the first setup, and the names it renames a file over, at a
		// restore, where an old file of each is in the folder.
		for _, target := range []struct {
			name string
			path BuildPath
		}{
			{nameSystemdKey + ".new", FirstSetup},
			{nameFile + ".new", FirstSetup},
			{nameSystemdKey, Restore},
			{nameFile, Restore},
		} {
			for _, kind := range plantLinux {
				t.Run(target.name+", "+kind.name, func(t *testing.T) {
					folder, decoy := handleFoldersLinux(t)
					kind.plant(t, filepath.Join(folder, target.name), decoy)
					_, err := build(t, folder, rowFields(), target.path, FromOSStore)
					wantRefusal(t, err, Link)
					wantDecoyUnchanged(t, decoy)
				})
			}
		}

		t.Run("let through: a restore over a bootstrap file and a credential of one name", func(t *testing.T) {
			folder, decoy := handleFoldersLinux(t)
			for _, name := range []string{nameFile, nameSystemdKey} {
				if err := os.WriteFile(filepath.Join(folder, name), []byte("an old file"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := build(t, folder, rowFields(), Restore, FromOSStore); err != nil {
				t.Fatalf("refused: %v", err)
			}
			for _, name := range []string{nameFile, nameSystemdKey} {
				if data, err := os.ReadFile(filepath.Join(folder, name)); err != nil || string(data) == "an old file" {
					t.Errorf("the old %s was not replaced: %v", name, err)
				}
			}
			wantDecoyUnchanged(t, decoy)
		})

		t.Run("the folder swapped for a symbolic link while Build runs", func(t *testing.T) {
			folder, decoy := handleFoldersLinux(t)
			prepared := filepath.Join(filepath.Dir(folder), "prepared")
			if err := os.Symlink(decoy, prepared); err != nil {
				t.Fatal(err)
			}
			swapAfterFirstFileLinux(t, folder, prepared)
			wantDecoyUnchanged(t, decoy)
		})
	})
}

// swapAfterFirstFileLinux runs Build at a restore and, as soon as Build has made its first file
// in the folder other than the lock, renames the folder away and the prepared link into its place.
// It waits on inotify and on Build's return, never on time.
func swapAfterFirstFileLinux(t *testing.T, folder, prepared string) {
	t.Helper()
	watch, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(watch) }()
	if _, err := unix.InotifyAddWatch(watch, folder, unix.IN_CREATE); err != nil {
		t.Fatal(err)
	}
	var returned [2]int
	if err := unix.Pipe2(returned[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(returned[0]) }()
	done := make(chan error, 1)
	go func() {
		_, err := build(t, folder, rowFields(), Restore, FromOSStore)
		done <- err
		_ = unix.Close(returned[1]) // the close itself is the signal
	}()
	buffer := make([]byte, 4096)
	for {
		ready := []unix.PollFd{{Fd: int32(watch), Events: unix.POLLIN}, {Fd: int32(returned[0]), Events: unix.POLLIN}} //nolint:gosec // descriptors are small
		if _, err := unix.Poll(ready, -1); err != nil {
			t.Fatal(err)
		}
		if ready[0].Revents&unix.POLLIN == 0 {
			t.Fatalf("Build returned before it made a file other than the lock, so the folder was never swapped: %v", <-done)
		}
		count, err := unix.Read(watch, buffer)
		if err != nil {
			t.Fatal(err)
		}
		for offset := 0; offset < count; {
			event := (*unix.InotifyEvent)(unsafe.Pointer(&buffer[offset])) //nolint:gosec // inotify's record layout
			name := buffer[offset+unix.SizeofInotifyEvent : offset+unix.SizeofInotifyEvent+int(event.Len)]
			offset += unix.SizeofInotifyEvent + int(event.Len)
			if string(bytes.TrimRight(name, "\x00")) == nameLock {
				continue
			}
			if err := os.Rename(folder, filepath.Join(filepath.Dir(folder), "swapped away")); err != nil {
				t.Fatalf("renaming the folder away: %v", err)
			}
			if err := os.Rename(prepared, folder); err != nil {
				t.Fatalf("renaming the link into place: %v", err)
			}
			t.Logf("Build returned %v", <-done)
			return
		}
	}
}
