// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The program and its key file on Linux: the key file's owner and mode, and a symbolic link that
// stays inside the folder. Modes are set from outside; another owner is set with sudo, which CI's
// runner has.
package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// modeName writes a mode for a row's name.
func modeName(mode os.FileMode) string {
	return "mode " + strconv.FormatUint(uint64(mode), 8)
}

func TestLinuxBootstrapProgram(t *testing.T) {
	t.Parallel()

	t.Run("If, on Linux, the key file's owner is not the account the engine runs as, or its mode gives its group or others any access, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		for _, mode := range []os.FileMode{0o640, 0o620, 0o610, 0o604, 0o602, 0o601} {
			t.Run(modeName(mode)+": one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) {
				t.Parallel()
				made := goodFolder(t)
				setKeyMode(t, made.keyFile, mode)
				expectOwnReason(t, made.refused(t), keyMissingReason(t), "a missing key file")
			})
		}
		t.Run("an access-list entry letting the user nobody read it, the mode then 0640: one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			made := goodFolder(t)
			runSystemTool(t, "setfacl", "-m", "u:nobody:r", made.keyFile)
			info, err := os.Stat(made.keyFile)
			if err != nil {
				t.Fatalf("reading the key file's mode: %v", err)
			}
			if info.Mode().Perm() != 0o640 {
				t.Fatalf("the key file's mode is %o with the entry, not 0640: a fault in the test", info.Mode().Perm())
			}
			expectOwnReason(t, made.refused(t), keyMissingReason(t), "a missing key file")
		})
		for _, mode := range []os.FileMode{0o600, 0o400, 0o700} {
			t.Run(modeName(mode)+", the owner's bits alone: it starts", func(t *testing.T) {
				t.Parallel()
				made := goodFolder(t)
				setKeyMode(t, made.keyFile, mode)
				made.starts(t)
			})
		}
	})

	t.Run("If the bootstrap folder is missing or unreadable, or the bootstrap file or the key file in it is missing, unreadable or a link leading out of the bootstrap folder, then the engine shall write one `start_failed` line saying which, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("the bootstrap file a symbolic link to a good one inside the folder: it starts", func(t *testing.T) {
			t.Parallel()
			made := goodFolder(t)
			inside := filepath.Join(made.path, "sealed.hadv")
			if err := os.Rename(made.file, inside); err != nil {
				t.Fatalf("moving the bootstrap file: %v", err)
			}
			if err := os.Symlink("sealed.hadv", made.file); err != nil {
				t.Fatalf("linking the bootstrap file: %v", err)
			}
			made.starts(t)
		})
	})
}

// TestLinuxRootBootstrapProgram needs sudo, which CI's runner has: another account as the key
// file's owner, read by a copy of the program given the capability to read any file, so the
// owner is the only thing wrong with the key file.
func TestLinuxRootBootstrapProgram(t *testing.T) {
	t.Parallel()

	t.Run("If, on Linux, the key file's owner is not the account the engine runs as, or its mode gives its group or others any access, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("the owner nobody, mode 0600, the program able to read any file: one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			made := goodFolder(t)
			runSystemTool(t, "sudo", "-n", "chown", "nobody", made.keyFile)
			if buildFailure != nil {
				t.Fatalf("the program did not build: %v", buildFailure)
			}
			capable := filepath.Join(t.TempDir(), "hadv-service")
			runSystemTool(t, "cp", programPath, capable)
			runSystemTool(t, "sudo", "-n", "setcap", "cap_dac_read_search+ep", capable)
			command := exec.CommandContext(t.Context(), capable, databaseOption, made.path, portOption, "0")
			command.Env = cleanEnvironment()
			run := startCommand(t, command)
			reason := run.expectRefusal(t)
			expectNoPassword(t, run)
			made.expectKeyNotIn(t, run.text())
			expectOwnReason(t, reason, keyMissingReason(t), "a missing key file")
		})
	})
}
