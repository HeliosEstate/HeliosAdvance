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

// traceReadStart is the start of any read in strace's account, whole or not.
var traceReadStart = regexp.MustCompile(`^(?:read|pread64|readv|preadv|preadv2)\(`)

// runPattern is the -test.run pattern that matches the row named name and nothing else.
func runPattern(name string) string {
	parts := strings.Split(name, "/")
	for index, part := range parts {
		parts[index] = "^" + regexp.QuoteMeta(part) + "$"
	}
	return strings.Join(parts, "/")
}

// expectReadAtMost runs the calling row again in a child under strace, which opens the folder and
// checks Open refused it with want, and fails the row when the child read more than most bytes of
// the folder's file named name. The count is that file's own: the process's whole count also
// holds what the Go runtime reads for itself, on another thread, at moments its scheduler picks.
func expectReadAtMost(t *testing.T, made *layout, name string, most uint32, _ error) {
	t.Helper()
	reads := readsOf(t, made.folder)
	// Open reads the bootstrap file before it opens the key file, so a key file row that finds
	// no read of the bootstrap file in the account has an account whose paths are not the
	// folder's, and its bound would pass on nothing counted.
	if name == keyFileName && reads[fileName] == 0 {
		t.Fatalf("strace's account shows no read of %s in the row's folder, which Open reads before the key file: a fault in the test", fileName)
	}
	if reads[name] > int64(most) {
		t.Fatalf("Open read %d bytes of %s, more than %d", reads[name], name, most)
	}
}

// readsOf runs the calling row again in a child under strace, which opens folder, and returns the
// bytes read from each file in folder, by its name. The child must pass the row: it checks what
// Open returned. Each thread's reads go to a file of their own, so no read is split across lines
// by another thread's, and a read the account does not show whole fails the row.
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
	arguments := []string{"-ff", "-y", "-e", "trace=read,pread64,readv,preadv,preadv2", "-o", account, binary,
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
				if traceReadStart.MatchString(line) || strings.Contains(line, " resumed>") {
					t.Fatalf("strace's account shows a read it does not show whole: %q", line)
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
				if base := filepath.Base(found[1]); base == fileName || base == keyFileName {
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
