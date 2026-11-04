// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Open's lines on Linux: the key file's owner and mode, a named pipe in place of either file, a
// symbolic link that stays inside the folder, and every descriptor closed on return. Modes are
// set from outside Open; another owner is set with sudo, which CI's runner has.
package bootstrap_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/bootstrap"
	"github.com/heliosestate/heliosadvance/internal/testrun"
)

func TestLinuxOpen(t *testing.T) {
	t.Parallel()

	t.Run("If, on Linux, the key file's owner is not the engine's effective user ID, or its mode gives its group or others any access, then Open shall return ErrKeyFileReachable.", func(t *testing.T) {
		t.Parallel()
		for _, mode := range []os.FileMode{0o640, 0o620, 0o610, 0o604, 0o602, 0o601} {
			t.Run("mode "+strconv.FormatUint(uint64(mode), 8)+": ErrKeyFileReachable", func(t *testing.T) {
				t.Parallel()
				made := makeFolder(t)
				setMode(t, made.keyFile, mode)
				made.expectRefused(t, bootstrap.ErrKeyFileReachable)
			})
		}
		t.Run("an access-list entry letting the user nobody read it, the mode then 0640: ErrKeyFileReachable", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			run(t, "setfacl", "-m", "u:nobody:r", made.keyFile)
			info, err := os.Stat(made.keyFile)
			if err != nil {
				t.Fatalf("reading the key file's mode: %v", err)
			}
			if info.Mode().Perm() != 0o640 {
				t.Fatalf("the key file's mode is %o with the entry, not 0640: a fault in the test", info.Mode().Perm())
			}
			made.expectRefused(t, bootstrap.ErrKeyFileReachable)
		})
		for _, mode := range []os.FileMode{0o600, 0o400, 0o700} {
			t.Run("mode "+strconv.FormatUint(uint64(mode), 8)+", the owner's bits alone: opens", func(t *testing.T) {
				t.Parallel()
				made := makeFolder(t)
				setMode(t, made.keyFile, mode)
				made.expectOpened(t)
			})
		}
	})

	t.Run("If the bootstrap file will not open or read, is not a regular file, or is a link leading out of the bootstrap folder, then Open shall return ErrFileUnreadable.", func(t *testing.T) {
		t.Parallel()
		t.Run("a symbolic link to a good bootstrap file inside the folder: opens", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			inside := filepath.Join(made.folder, "sealed.hadv")
			if err := os.Rename(made.file, inside); err != nil {
				t.Fatalf("moving the bootstrap file: %v", err)
			}
			if err := os.Symlink("sealed.hadv", made.file); err != nil {
				t.Fatalf("linking the bootstrap file: %v", err)
			}
			made.expectOpened(t)
		})
	})

	t.Run("Open shall open each file without waiting on it, so a file that is not a regular file, such as a named pipe, is refused and never waited on.", func(t *testing.T) {
		t.Parallel()
		t.Run("a named pipe as the bootstrap file, no writer: ErrFileUnreadable within the hang bound", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			remove(t, made.file)
			makePipe(t, made.file)
			made.expectRefused(t, bootstrap.ErrFileUnreadable)
		})
		t.Run("a named pipe as the key file, no writer: ErrKeyFileUnreadable within the hang bound", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			remove(t, made.keyFile)
			makePipe(t, made.keyFile)
			made.expectRefused(t, bootstrap.ErrKeyFileUnreadable)
		})
	})

	t.Run("When it returns, Open shall have closed the bootstrap folder and both files.", func(t *testing.T) {
		t.Parallel()
		for name, way := range closingOutcomes() {
			t.Run(name+": no descriptor of this process leads into the folder", func(t *testing.T) {
				t.Parallel()
				made := way.reach(t)
				if left := descriptorsInto(t, made.folder); len(left) != 0 {
					t.Fatalf("still open after Open returned: %v", left)
				}
			})
		}
	})
}

// makePipe makes a named pipe at path. An Open that waits on it for a writer is let go once the
// row ends, by opening it to write, so the row's folder can be removed.
func makePipe(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("making a named pipe: %v", err)
	}
	t.Cleanup(func() {
		writer, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = writer.Close()
		}
	})
}

// descriptorsInto lists this process's open descriptors that lead to the folder or anything in
// it, read from /proc/self/fd. Each row's folder is its own, so rows running beside it add none.
func descriptorsInto(t *testing.T, folder string) []string {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("reading this process's descriptors: %v", err)
	}
	var into []string
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err != nil {
			continue // closed between the listing and the read: not open now
		}
		if target == folder || strings.HasPrefix(target, folder+string(filepath.Separator)) {
			into = append(into, entry.Name()+" -> "+target)
		}
	}
	return into
}

// run runs one of the system's own tools and fails the row when it fails or is not there.
func run(t *testing.T, name string, arguments ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testrun.Patient(testrun.HangBound))
	defer cancel()
	if output, err := exec.CommandContext(ctx, name, arguments...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
}

// TestLinuxRootOpen needs sudo and setpriv, which CI's runner has: another account as the key
// file's owner, read by a copy of this test binary given the capability to read any file, so the
// owner is the only thing wrong with the key file.
func TestLinuxRootOpen(t *testing.T) {
	t.Parallel()

	t.Run("If, on Linux, the key file's owner is not the engine's effective user ID, or its mode gives its group or others any access, then Open shall return ErrKeyFileReachable.", func(t *testing.T) {
		t.Parallel()
		t.Run("the owner nobody, mode 0600, read by a process that may read any file: ErrKeyFileReachable", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			run(t, "sudo", "-n", "chown", "nobody", made.keyFile)
			output, err := capableOpen(t, made.folder)
			if err != nil {
				t.Fatalf("the capable copy: %v: %s", err, strings.TrimSpace(string(output)))
			}
			want := "refused " + strconv.Itoa(errorIndex(bootstrap.ErrKeyFileReachable))
			got, _, _ := strings.Cut(strings.TrimSpace(string(output)), "\n")
			// A copy that says it lacks the capability proves nothing about Open: the test's
			// setup failed. Bit 2 is cap_dac_read_search.
			_, report, _ := strings.Cut(string(output), "effective capabilities ")
			capabilities, _, _ := strings.Cut(report, ";")
			if bits, err := strconv.ParseUint(capabilities, 16, 64); got != want && err == nil && bits&(1<<2) == 0 {
				t.Fatalf("cannot tell: the test's setup failed, the copy did not hold the capability to read any file; all it printed:\n%s", output)
			}
			if got != want {
				t.Fatalf("the capable copy's Open: %q, want %q (%v); all it printed:\n%s", got, want,
					bootstrap.ErrKeyFileReachable, output)
			}
		})
	})
}

// capableOpen copies this test binary into the row's folder, inside the run's own, runs the copy
// as a child that opens folder, as this test's own user with the capability to read any file
// whatever its owner and mode, and returns all it printed. sudo gives the capability to the
// process, as an ambient one, not to the copy's file: the kernel ignores a file's capabilities on
// a file system mounted nosuid, as the temporary folder is on some CI runners, and there the copy
// ran without it.
func capableOpen(t *testing.T, folder string) ([]byte, error) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("finding this test binary: %v", err)
	}
	child := filepath.Join(t.TempDir(), "open-child")
	run(t, "cp", self, child)
	ctx, cancel := context.WithTimeout(context.Background(), testrun.Patient(testrun.HangBound))
	defer cancel()
	command := exec.CommandContext(ctx, "sudo", "-n", "setpriv",
		"--reuid="+strconv.Itoa(os.Getuid()), "--regid="+strconv.Itoa(os.Getgid()), "--init-groups",
		"--inh-caps=+dac_read_search", "--ambient-caps=+dac_read_search", child, "-"+openChildFlag+"="+folder)
	// Ending sudo does not end the copy it started, which would hold the output open.
	command.WaitDelay = testrun.Patient(testrun.HangBound)
	return command.CombinedOutput()
}
