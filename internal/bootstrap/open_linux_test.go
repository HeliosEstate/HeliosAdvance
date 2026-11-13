// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Open's lines on Linux: the key file's mode, a named pipe in place of either file, a symbolic
// link that stays inside the folder, and every descriptor closed on return. Modes are set from
// outside Open; whether the account nobody may read or write the key file is the system's own
// answer, asked through sudo, which CI's runner has.
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

	t.Run("If, on Linux, the key file's mode gives its group or others any access, then Open shall return ErrKeyFileReachable.", func(t *testing.T) {
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

	t.Run("If the bootstrap file is shorter than HeaderBytes, NonceBytes and TagBytes together, or its first HeaderBytes are not Magic, FormatVersion, then KeyHolderKeyFile with a sealed-key length of 0 or, on Windows, KeyHolderTPM or KeyHolderSoftwareKeyStore with a sealed-key length of SealedKeyBytes, or, under key holder 2 or 3, the file is too short for the sealed key, nonce and tag, or the sealed key's first KeyNameBytes are not KeyNamePrefix and 32 lower-case hex digits, then Open shall return ErrHeader before it opens the key file or asks a key store.", func(t *testing.T) {
		t.Parallel()
		// Linux has neither of Windows' key stores, so a header naming either is one it does not
		// read, however well formed its sealed key is.
		for _, holder := range []string{"2", "3"} {
			t.Run("key holder "+holder+", 293 sealed bytes, a name in its form: ErrHeader", func(t *testing.T) {
				t.Parallel()
				made := makeFolderWith(t, plaintextOf(t, 64), "holder "+holder+"\nsealed \"hadv-0123456789abcdef0123456789abcdef\" random:256")
				expectSize(t, made, 64+sealedOverhead+293)
				made.expectRefused(t, bootstrap.ErrHeader)
			})
		}
	})

	t.Run("When it returns, Open shall have closed the bootstrap folder and the files it opened, and freed every key store handle it opened.", func(t *testing.T) {
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

// TestLinuxRootOpen needs sudo, which CI's runner has: each row first asks the system itself, as
// the account nobody, whether nobody may read or write the key file, which proves the row's setup
// gives nobody exactly that access, and only then judges Open.
func TestLinuxRootOpen(t *testing.T) {
	t.Parallel()

	t.Run("If, on Linux, the key file's mode gives its group or others any access, then Open shall return ErrKeyFileReachable.", func(t *testing.T) {
		t.Parallel()
		for _, row := range nobodyRows() {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				made := makeFolder(t)
				row.set(t, made.keyFile)
				openFoldersToNobody(t, made.folder)
				expectNobodyMay(t, made.keyFile, row.read, row.write)
				if row.read || row.write {
					made.expectRefused(t, bootstrap.ErrKeyFileReachable)
				} else {
					made.expectOpened(t)
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
			setMode(t, keyFile, mode)
		}
	}
	withEntry := func(entry string, shown os.FileMode) func(*testing.T, string) {
		return func(t *testing.T, keyFile string) {
			t.Helper()
			run(t, "setfacl", "-m", entry, keyFile)
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
		{"mode 0604, which the system says nobody may read and not write: ErrKeyFileReachable", withMode(0o604), true, false},
		{"mode 0602, which the system says nobody may write and not read: ErrKeyFileReachable", withMode(0o602), false, true},
		{"an access-list entry letting nobody read it, the mode then 0640, which the system says nobody may read and not write: ErrKeyFileReachable",
			withEntry("u:nobody:r", 0o640), true, false},
		{"an access-list entry letting nobody write it, the mode then 0620, which the system says nobody may write and not read: ErrKeyFileReachable",
			withEntry("u:nobody:w", 0o620), false, true},
		{"mode 0600, which the system says nobody may neither read nor write: opens", withMode(0o600), false, false},
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
		setMode(t, path, mode|0o001)
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
	setMode(t, runFolder, info.Mode().Perm()|0o001)
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
