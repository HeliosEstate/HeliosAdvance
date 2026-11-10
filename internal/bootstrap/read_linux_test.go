// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

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

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// traceRead is one whole read in strace's account of a thread: the file behind the descriptor and
// what the read returned, a count of bytes or -1 with an error after it.
var traceRead = regexp.MustCompile(`^(?:read|pread64|readv|preadv|preadv2)\(\d+<([^>]*)>.*\) += (-?\d+)(?: .*)?$`)

// traceReadFile is the file behind the descriptor at the start of any read in strace's account,
// whole or not.
var traceReadFile = regexp.MustCompile(`^(?:read|pread64|readv|preadv|preadv2)\(\d+<([^>]*)>`)

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

func TestLinuxReadBound(t *testing.T) {
	t.Parallel()
	for _, line := range readBoundLines() {
		t.Run(line.line, func(t *testing.T) {
			t.Parallel()
			for _, row := range line.rows {
				t.Run(row.name+", no more than "+row.bound+" of it read", func(t *testing.T) {
					t.Parallel()
					if folder, child := childFolder(); child {
						if folder == "" {
							t.Fatalf("the child was given no bootstrap folder after %s", readBoundChild)
						}
						contents, err := open(t, folder)
						expectError(t, contents, err, row.want)
						return
					}
					made := row.make(t)
					reads := readsOf(t, made.folder)
					// Open reads the bootstrap file before it opens the key file, so a key file row
					// that finds no read of the bootstrap file in the account has an account whose
					// paths are not the folder's, and its bound would pass on nothing counted.
					if row.file == keyFileName && reads[fileName] == 0 {
						t.Fatalf("strace's account shows no read of %s in the row's folder, which Open reads before the key file: a fault in the test", fileName)
					}
					if reads[row.file] > int64(row.most) {
						t.Fatalf("Open read %d bytes of %s, more than %d", reads[row.file], row.file, row.most)
					}
				})
			}
		})
	}
}

// readsOf runs the calling row again in a child under strace, which opens folder, and returns the
// bytes read from each file in folder, by its name. The child must pass the row: it checks what
// Open returned. Each thread's reads go to a file of their own, so no read is split across lines
// by another thread's. The count is each file's own: the process's whole count also holds what
// the Go runtime reads for itself, on another thread, at moments its scheduler picks.
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
				// A read the account does not show whole, one a signal broke off or left
				// unfinished, is the row's business only when it is of a folder's file: the
				// runtime's own threads end reads so at moments their scheduler picks. A resumed
				// read names no file; its unfinished start, in the same thread's account, did.
				if start := traceReadFile.FindStringSubmatch(line); start != nil && isFolderFile(start[1]) {
					t.Fatalf("strace's account shows a read of a bootstrap folder's file it does not show whole: %q", line)
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
