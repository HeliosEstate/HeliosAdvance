// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// What Open reads of an oversized file, on Linux: no more than its line's bound of it. A row runs
// again in a child, this test binary under strace, which names the file behind every read, and
// adds up the bytes read from the line's file in the row's folder. The count is that file's own:
// the process's whole count also holds what the Go runtime reads for itself, on another thread,
// at moments its scheduler picks. Open reads both files with the same code on every system; on
// Windows the lines' refusals are proved by TestOpen's rows alone.
package bootstrap_test

import (
	"context"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/bootstrap"
	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// traceRead is one whole read in strace's account of a thread: the file behind the descriptor and
// what the read returned, a count of bytes or -1 with an error after it.
var traceRead = regexp.MustCompile(`^(?:read|pread64|readv|preadv|preadv2)\(\d+<([^>]*)>.*\) += (-?\d+)(?: .*)?$`)

// traceReadStart is the start of a read in strace's account, whole or not, and the file behind its
// descriptor when the account names one.
var traceReadStart = regexp.MustCompile(`^(?:read|pread64|readv|preadv|preadv2)\(\d+(?:<([^>]*)>)?`)

// runPattern is the -test.run pattern that matches the row named name and nothing else.
func runPattern(name string) string {
	parts := strings.Split(name, "/")
	for index, part := range parts {
		parts[index] = "^" + regexp.QuoteMeta(part) + "$"
	}
	return strings.Join(parts, "/")
}

// isFolderFile reports whether path names one of a bootstrap folder's two files.
func isFolderFile(path string) bool {
	base := filepath.Base(path)
	return base == fileName || base == keyFileName
}

// grouped is a count in digits with a comma between each group of three, as the rows' names
// write sizes.
func grouped(count int64) string {
	digits := strconv.FormatInt(count, 10)
	for place := len(digits) - 3; place > 0; place -= 3 {
		digits = digits[:place] + "," + digits[place:]
	}
	return digits
}

// boundRow is a row's name: its case and refusal, then the line's bound on what is read.
func boundRow(name string, most int64) string {
	return name + ", no more than " + grouped(most) + " bytes of it read"
}

// openAsChild, in a row's child, opens the folder the parent made and fails the row unless Open
// refused it with want; it reports whether this run is a child, so the row ends there.
func openAsChild(t *testing.T, want error) bool {
	t.Helper()
	folder, child := childFolder()
	if !child {
		return false
	}
	if folder == "" {
		t.Fatalf("the child was given no bootstrap folder after %s", readBoundChild)
	}
	contents, err := open(t, folder)
	expectError(t, contents, err, want)
	return true
}

func TestLinuxReadBound(t *testing.T) {
	t.Parallel()
	t.Run("If the bootstrap file is longer than FileMostBytes, then Open shall return ErrFileTooLarge, having read at most FileMostBytes and one byte more of it.", func(t *testing.T) {
		t.Parallel()
		t.Run(boundRow("65,537 bytes: ErrFileTooLarge", fileMostBytes+1), func(t *testing.T) {
			t.Parallel()
			if openAsChild(t, bootstrap.ErrFileTooLarge) {
				return
			}
			made := makeFolderWith(t, plaintextOf(t, fileMostBytes+1-sealedOverhead), "")
			expectSize(t, made, fileMostBytes+1)
			expectReadAtMost(t, made, fileName, fileMostBytes+1)
		})
		t.Run(boundRow("1 MiB: ErrFileTooLarge", fileMostBytes+1), func(t *testing.T) {
			t.Parallel()
			if openAsChild(t, bootstrap.ErrFileTooLarge) {
				return
			}
			made := makeFolder(t)
			made.writeFile(t, append(made.sealed, make([]byte, 1<<20-len(made.sealed))...))
			expectReadAtMost(t, made, fileName, fileMostBytes+1)
		})
	})
	t.Run("If the key file is longer than KeyFileMostBytes, is not in the form the package comment gives, or holds a key of 32 zero bytes, then Open shall return ErrKeyFileForm, having read at most KeyFileMostBytes and one byte more of it.", func(t *testing.T) {
		t.Parallel()
		t.Run(boundRow("a 1 MiB key file beside a good bootstrap file: ErrKeyFileForm", keyFileMostBytes+1), func(t *testing.T) {
			t.Parallel()
			if openAsChild(t, bootstrap.ErrKeyFileForm) {
				return
			}
			made := makeFolder(t)
			made.writeKey(t, strings.TrimRight(made.keyText, "\r\n")+strings.Repeat("\n", 1<<20))
			expectReadAtMost(t, made, keyFileName, keyFileMostBytes+1)
		})
	})
}

// expectReadAtMost runs the calling row again in a child under strace, which opens the folder and
// checks what Open returned, and fails the row when the child read more than most bytes of the
// folder's file named name.
func expectReadAtMost(t *testing.T, made *layout, name string, most int64) {
	t.Helper()
	reads := readsOf(t, made.folder)
	// Open reads the bootstrap file before it opens the key file, so a key file row that finds
	// no read of the bootstrap file in the account has an account whose paths are not the
	// folder's, and its bound would pass on nothing counted.
	if name == keyFileName && reads[fileName] == 0 {
		t.Fatalf("strace's account shows no read of %s in the row's folder, which Open reads before the key file: a fault in the test", fileName)
	}
	if reads[name] > most {
		t.Fatalf("Open read %d bytes of %s, more than %d", reads[name], name, most)
	}
}

// readsOf runs the calling row again in a child under strace, which opens folder, and returns the
// bytes read from each file in folder, by its name. The child must pass the row: it checks what
// Open returned. Each thread's reads go to a file of their own, so no read is split across lines
// by another thread's.
func readsOf(t *testing.T, folder string) map[string]int64 {
	t.Helper()
	if _, err := exec.LookPath("strace"); err != nil {
		t.Fatalf("strace, which names the file behind each read, is not installed: %v", err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatalf("finding the test binary: %v", err)
	}
	root, err := filepath.EvalSymlinks(folder)
	if err != nil {
		t.Fatalf("resolving the bootstrap folder %s: %v", folder, err)
	}
	account := filepath.Join(t.TempDir(), "reads")
	bound := testrun.Patient(testrun.HangBound)
	// --seccomp-bpf stops the child only at the reads traced, not at every system call.
	arguments := []string{"-ff", "--seccomp-bpf", "-y", "-e", "trace=read,pread64,readv,preadv,preadv2", "-o", account, binary,
		"-test.run=" + runPattern(t.Name()), "-test.count=1", "-test.v", "-test.timeout=" + bound.String()}
	// Under go test -cover the child writes its counters where this binary's own counters go.
	if directory := flag.Lookup("test.gocoverdir"); directory != nil && directory.Value.String() != "" {
		arguments = append(arguments, "-test.gocoverdir="+directory.Value.String())
	}
	arguments = append(arguments, readBoundChild, folder)
	// The child ends its own run at its test timeout; this bound is for strace itself.
	ctx, cancel := context.WithTimeout(t.Context(), 2*bound)
	defer cancel()
	child := exec.CommandContext(ctx, "strace", arguments...)
	child.WaitDelay = bound
	start := time.Now()
	output, err := child.CombinedOutput()
	t.Logf("the child under strace took %v, its own test timeout %v", time.Since(start), bound)
	if err != nil {
		t.Fatalf("the row's child under strace failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "--- PASS: "+t.Name()+" (") {
		t.Fatalf("the row's child under strace did not pass the row:\n%s", output)
	}
	threads, err := filepath.Glob(account + ".*")
	if err != nil || len(threads) == 0 {
		t.Fatalf("strace wrote no account of the child's reads (%v)", err)
	}
	reads := map[string]int64{}
	for _, thread := range threads {
		text, err := os.ReadFile(thread)
		if err != nil {
			t.Fatalf("reading strace's account %s: %v", thread, err)
		}
		for line := range strings.SplitSeq(string(text), "\n") {
			found := traceRead.FindStringSubmatch(line)
			if found == nil {
				// A read whose descriptor the account does not name cannot be counted by file, and
				// one it does not show whole cannot be counted at all; either fails the row when
				// it may be of a folder's file. The runtime's own threads have reads of their
				// pipes restarted at moments their scheduler picks, and those name what they
				// read. A resumed read names no file; its start, in the same thread's account,
				// was judged.
				if start := traceReadStart.FindStringSubmatch(line); start != nil && (start[1] == "" || isFolderFile(start[1])) {
					t.Fatalf("strace's account shows a read it cannot count, of a bootstrap folder's file or of a descriptor it does not name: %q", line)
				}
				continue
			}
			bytes, err := strconv.ParseInt(found[2], 10, 64)
			if err != nil {
				t.Fatalf("strace's account gives a read's result as %q: %v", found[2], err)
			}
			if filepath.Dir(found[1]) != root {
				// A folder's file the account names in another form than the folder's would be
				// counted nowhere, and a bound on it would pass on nothing read.
				if isFolderFile(found[1]) {
					t.Fatalf("strace's account names a bootstrap folder's file outside the row's folder %s: %q", root, line)
				}
				continue
			}
			if bytes > 0 {
				reads[filepath.Base(found[1])] += bytes
			}
		}
	}
	return reads
}
