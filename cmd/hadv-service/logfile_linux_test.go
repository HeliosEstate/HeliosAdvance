// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

// unopenableLogFiles are the log files only Linux can make that will not open for appending: a
// file whose mode lets its owner, the program's user, only read it. Root opens every file, so the
// row needs an ordinary user, as CI's runners are.
func unopenableLogFiles() map[string]func(t *testing.T) (string, func(t *testing.T)) {
	return map[string]func(t *testing.T) (string, func(t *testing.T)){
		"a file of mode 0400": func(t *testing.T) (string, func(t *testing.T)) {
			t.Helper()
			if os.Geteuid() == 0 {
				t.Fatalf("this row needs an ordinary user, not root")
			}
			path := filepath.Join(t.TempDir(), "hadv.log")
			if err := os.WriteFile(path, []byte(sysopLine), 0o400); err != nil {
				t.Fatalf("writing the read-only log file: %v", err)
			}
			return path, func(t *testing.T) {
				t.Helper()
				expectFileUnchanged(t, path, []byte(sysopLine), 0o400)
			}
		},
	}
}

// expectFileUnchanged checks a file still holds what it held and has the mode it had.
func expectFileUnchanged(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("reading the log file's mode: %v", err)
	}
	if info.Mode().Perm() != mode {
		t.Fatalf("the log file's mode is %v, want %v as it was", info.Mode().Perm(), mode)
	}
	found, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the log file: %v", err)
	}
	if !bytes.Equal(found, contents) {
		t.Fatalf("the log file holds %q, want %q as it was", found, contents)
	}
}

func TestLinuxLogFile(t *testing.T) {
	t.Parallel()
	t.Run("When, on Linux, the engine creates the log file, the engine shall create it readable and writable by its own account alone.", func(t *testing.T) {
		t.Parallel()
		for _, mask := range []string{"022", "000"} {
			t.Run("started under umask "+mask+": the log file it made is mode 0600 and the runner's own", func(t *testing.T) {
				t.Parallel()
				if os.Geteuid() == 0 {
					t.Fatalf("this row needs an ordinary user, not root")
				}
				if buildFailure != nil {
					t.Fatalf("the program did not build: %v", buildFailure)
				}
				path := filepath.Join(t.TempDir(), "hadv.log")
				// The shell sets the mask the program inherits, then becomes the program.
				command := exec.CommandContext(t.Context(), "sh", "-c", "umask "+mask+`; exec "$0" "$@"`,
					programPath, databaseOption, sharedRowFile(t), portOption, "0", logFileOption, path)
				program := startCommand(t, command)
				expectStartedLine(t, readLogFile(t, program, path, 0, 1)[0])
				info, err := os.Stat(path)
				if err != nil {
					t.Fatalf("reading the log file's mode: %v", err)
				}
				if info.Mode() != 0o600 {
					t.Fatalf("the log file is %v, want a regular file of mode 0600", info.Mode())
				}
				owner, isUnix := info.Sys().(*syscall.Stat_t)
				if !isUnix || int(owner.Uid) != os.Getuid() {
					t.Fatalf("the log file's owner is %+v, want the runner's own user, %d", info.Sys(), os.Getuid())
				}
			})
		}
	})
}
