// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The program and its key file on Linux: the key file's mode, and a symbolic link that stays
// inside the folder. Modes are set from outside; whether the account nobody may read or write the
// key file is the system's own answer, asked through sudo, which CI's runner has.
package main_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// modeName writes a mode for a row's name.
func modeName(mode os.FileMode) string {
	return "mode " + strconv.FormatUint(uint64(mode), 8)
}

func TestLinuxBootstrapProgram(t *testing.T) {
	t.Parallel()

	t.Run("If, on Linux, the key file's mode gives its group or others any access, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
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

// TestLinuxRootBootstrapProgram needs sudo, which CI's runner has: each row first asks the system
// itself, as the account nobody, whether nobody may read or write the key file, which proves the
// row's setup gives nobody exactly that access, and only then judges the program.
func TestLinuxRootBootstrapProgram(t *testing.T) {
	t.Parallel()

	t.Run("If, on Linux, the key file's mode gives its group or others any access, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		for _, row := range nobodyRows() {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				made := goodFolder(t)
				row.set(t, made.keyFile)
				openFoldersToNobody(t, made.path)
				expectNobodyMay(t, made.keyFile, row.read, row.write)
				if row.read || row.write {
					expectOwnReason(t, made.refused(t), keyMissingReason(t), "a missing key file")
				} else {
					made.starts(t)
				}
			})
		}
	})
}

// nobodyRow is one key file whose access for the account nobody the system is asked about: how
// the row sets it, and what the system must answer for nobody's read and write.
type nobodyRow struct {
	name        string
	set         func(t *testing.T, keyFile string)
	read, write bool
}

// nobodyRows are a key file nobody may read, one it may write, by mode and by an access-list
// entry, and the engine's own at mode 0600, which nobody may do neither to.
func nobodyRows() []nobodyRow {
	withMode := func(mode os.FileMode) func(*testing.T, string) {
		return func(t *testing.T, keyFile string) {
			t.Helper()
			setKeyMode(t, keyFile, mode)
		}
	}
	withEntry := func(entry string, shown os.FileMode) func(*testing.T, string) {
		return func(t *testing.T, keyFile string) {
			t.Helper()
			runSystemTool(t, "setfacl", "-m", entry, keyFile)
			info, err := os.Stat(keyFile)
			if err != nil {
				t.Fatalf("reading the key file's mode: %v", err)
			}
			if info.Mode().Perm() != shown {
				t.Fatalf("the key file's mode is %o with the entry, not %o: a fault in the test", info.Mode().Perm(), shown)
			}
		}
	}
	return []nobodyRow{
		{"mode 0604, which the system says nobody may read and not write: one start_failed line, a reason of its own, and a non-zero exit",
			withMode(0o604), true, false},
		{"mode 0602, which the system says nobody may write and not read: one start_failed line, a reason of its own, and a non-zero exit",
			withMode(0o602), false, true},
		{"an access-list entry letting nobody read it, the mode then 0640, which the system says nobody may read and not write: one start_failed line, a reason of its own, and a non-zero exit",
			withEntry("u:nobody:r", 0o640), true, false},
		{"an access-list entry letting nobody write it, the mode then 0620, which the system says nobody may write and not read: one start_failed line, a reason of its own, and a non-zero exit",
			withEntry("u:nobody:w", 0o620), false, true},
		{"mode 0600, which the system says nobody may neither read nor write: it starts", withMode(0o600), false, false},
	}
}

// openFoldersToNobody lets others search, never list, every folder from the bootstrap folder up
// to the run's own, which testrun made the temporary folder, so the system's answers about the key
// file are about the key file alone. Search alone lists nothing: past the run's own folder nobody
// reaches only a path it already knows. The row's own folders get their modes back when it ends;
// the run's own folder keeps others' search until testrun removes it, since the rows beside this
// one still need it. The row fails as a fault in the test unless the system then says nobody may
// search the bootstrap folder.
func openFoldersToNobody(t *testing.T, folder string) {
	t.Helper()
	runFolder := os.TempDir()
	var own []string
	for current := folder; current != runFolder; current = filepath.Dir(current) {
		if current == filepath.Dir(current) {
			t.Fatalf("%s is not inside the run's own folder %s: a fault in the test", folder, runFolder)
		}
		own = append(own, current)
	}
	for _, path := range own {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("reading %s's mode: %v", path, err)
		}
		mode := info.Mode().Perm()
		setKeyMode(t, path, mode|0o001)
		t.Cleanup(func() {
			if err := os.Chmod(path, mode); err != nil {
				t.Errorf("giving %s its mode back: %v", path, err)
			}
		})
	}
	info, err := os.Stat(runFolder)
	if err != nil {
		t.Fatalf("reading %s's mode: %v", runFolder, err)
	}
	setKeyMode(t, runFolder, info.Mode().Perm()|0o001)
	if !nobodyMay(t, "-x", folder) {
		t.Fatalf("the system says nobody may not search %s once its folders let others search them: a fault in the test", folder)
	}
}

// expectNobodyMay fails the row as a fault in the test unless the system says nobody may read and
// write the key file exactly as the row's setup means.
func expectNobodyMay(t *testing.T, keyFile string, read, write bool) {
	t.Helper()
	if got := nobodyMay(t, "-r", keyFile); got != read {
		t.Fatalf("the system says nobody may read the key file: %v, where the row's setup means %v: a fault in the test", got, read)
	}
	if got := nobodyMay(t, "-w", keyFile); got != write {
		t.Fatalf("the system says nobody may write the key file: %v, where the row's setup means %v: a fault in the test", got, write)
	}
}

// nobodyMay asks the system, as the account nobody, whether nobody may do to path what test's
// operator names: -r read, -w write, -x search. sudo sets both of nobody's user IDs, so test's own
// check answers for nobody, access-list entries included. The shell prints test's own exit code,
// read from standard output alone: 0 is yes, 1 is no. Anything else, such as test's 2 for a
// question it cannot ask, or a sudo that cannot run, which prints none, fails the row as a fault
// in the test, so it never reads as a "no".
func nobodyMay(t *testing.T, operator, path string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testrun.Patient(testrun.HangBound))
	defer cancel()
	var complaints strings.Builder
	command := exec.CommandContext(ctx, "sudo", "-n", "-u", "nobody", "sh", "-c",
		`test "$1" "$2"; echo "$?"`, "sh", operator, path)
	command.Stderr = &complaints
	output, err := command.Output()
	if err != nil {
		t.Fatalf("asking the system as nobody, test %s %s: %v: %s", operator, path, err, strings.TrimSpace(complaints.String()))
	}
	switch code := strings.TrimSpace(string(output)); code {
	case "0":
		return true
	case "1":
		return false
	default:
		t.Fatalf("asking the system as nobody, test %s %s ended with %q, neither 0 nor 1: a fault in the test; it wrote: %s",
			operator, path, code, strings.TrimSpace(complaints.String()))
		return false
	}
}
