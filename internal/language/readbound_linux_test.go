// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// What Load reads of each language's file: no more than MostFileBytes and one byte of a file over
// it, and each file once. A row runs its Load again in a child, this test binary run again under
// strace, which names the file behind every read, and adds up the bytes read from each file in
// the row's lang folder. The count is the file's own: the process's whole count also holds what
// the Go runtime reads for itself, on another thread, at moments its scheduler picks.
package language_test

import (
	"context"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// readBoundChild marks the run of this test binary that is a row's child under strace: an argument
// after the test flags, which the testing package leaves alone, followed by the lang folder the
// child loads.
const readBoundChild = "read-bound-child"

// childFolder is the lang folder this run loads when it is a row's child, and whether it is one.
func childFolder(t *testing.T) (string, bool) {
	t.Helper()
	place := slices.Index(os.Args, readBoundChild)
	if place < 0 {
		return "", false
	}
	if place+1 >= len(os.Args) {
		t.Fatalf("the child was given no lang folder after %s", readBoundChild)
	}
	return os.Args[place+1], true
}

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

// readsOf runs the calling row again in a child under strace, which loads folder, and returns the
// bytes read from each file in folder, by its path inside folder. The child must pass the row: it
// checks what Load returned. Each thread's reads go to a file of their own, so no read is split
// across lines by another thread's, and a read the account does not show whole fails the row.
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
		t.Fatalf("resolving the lang folder %s: %v", folder, err)
	}
	account := filepath.Join(t.TempDir(), "reads")
	arguments := []string{"-ff", "-y", "-e", "trace=read,pread64,readv,preadv,preadv2", "-o", account, binary,
		"-test.run=" + runPattern(t.Name()), "-test.count=1", "-test.v", "-test.timeout=" + testrun.Patient(testrun.HangBound).String()}
	// Under go test -cover the child writes its counters where this binary's own counters go.
	if directory := flag.Lookup("test.gocoverdir"); directory != nil && directory.Value.String() != "" {
		arguments = append(arguments, "-test.gocoverdir="+directory.Value.String())
	}
	arguments = append(arguments, readBoundChild, folder)
	// The child ends its own run at its test timeout; this bound is for strace itself.
	ctx, cancel := context.WithTimeout(t.Context(), 2*testrun.Patient(testrun.HangBound))
	defer cancel()
	child := exec.CommandContext(ctx, "strace", arguments...)
	child.WaitDelay = testrun.Patient(testrun.HangBound)
	output, err := child.CombinedOutput()
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
			inside, err := filepath.Rel(root, found[1])
			if err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
				// A language's file the account names in another form than the folder's would be
				// counted nowhere, and a bound on it would pass on nothing read.
				if strings.HasSuffix(found[1], ".toml") {
					t.Fatalf("strace's account names a language's file outside the row's lang folder %s: %q", root, line)
				}
				continue
			}
			if bytes > 0 {
				reads[inside] += bytes
			}
		}
	}
	return reads
}

// sizeOf is a file's size on disk.
func sizeOf(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("reading %s's size: %v", path, err)
	}
	return info.Size()
}

// expectReadOnce fails the row unless the reads are exactly each of codes' files read once, whole,
// and nothing else in folder read.
func expectReadOnce(t *testing.T, folder string, reads map[string]int64, codes ...string) {
	t.Helper()
	want := map[string]int64{}
	for _, code := range codes {
		inside := filepath.Join(code, fileName(code))
		want[inside] = sizeOf(t, filepath.Join(folder, inside))
	}
	for inside, size := range want {
		if reads[inside] != size {
			t.Errorf("Load read %d bytes of %s, not the %d it holds", reads[inside], inside, size)
		}
	}
	for inside, read := range reads {
		if _, found := want[inside]; !found {
			t.Errorf("Load read %d bytes of %s, which the row does not load", read, inside)
		}
	}
}

func TestLinuxReadBound(t *testing.T) {
	t.Parallel()
	t.Run("If a language's file is over MostFileBytes, then Load shall return ErrFileRefused naming it, having read no more than MostFileBytes and one byte of it.", func(t *testing.T) {
		t.Parallel()
		for name, size := range map[string]int{"2 MiB": 2 << 20, "64 MiB": 64 << 20} {
			t.Run("fr-fr a valid file padded to "+name+": ErrFileRefused, no more than 1 MiB and one byte of fr-fr read", func(t *testing.T) {
				t.Parallel()
				if folder, child := childFolder(t); child {
					expectRefused(t, folder, fallbackCode, fileName(frFR))
					return
				}
				folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), frFR: padded(t, frFile(nil), size)})
				inside := filepath.Join(frFR, fileName(frFR))
				if read := readsOf(t, folder)[inside]; read > mostFileBytes+1 {
					t.Fatalf("Load read %d bytes of %s, more than %d", read, inside, mostFileBytes+1)
				}
			})
		}
	})
	t.Run("Load shall read each language's file once, and every language's, not only those in the chain.", func(t *testing.T) {
		t.Parallel()
		t.Run("fr-fr a valid file of 900 KiB, the board en-us: each of the two files read once, whole", func(t *testing.T) {
			t.Parallel()
			if folder, child := childFolder(t); child {
				expectShown(t, expectLoaded(t, folder, fallbackCode), enUSShown)
				return
			}
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), frFR: padded(t, frFile(nil), 900<<10)})
			expectReadOnce(t, folder, readsOf(t, folder), fallbackCode, frFR)
		})
		t.Run("es-mx, es-es and en-us, the board es-mx: each of the three files read once, whole", func(t *testing.T) {
			t.Parallel()
			if folder, child := childFolder(t); child {
				expectShown(t, expectLoaded(t, folder, esMX), esShown(esMX).from(keyGreeting, esShown(esES)).missingFrom(keyGreeting))
				return
			}
			folder := makeLang(t, map[string]string{
				fallbackCode: enUSFile(),
				esES:         padded(t, esFile(esES, "", esTexts(esES)), 300<<10),
				esMX:         padded(t, esFile(esMX, esES, esTexts(esMX, shortGreeting)), 200<<10),
			})
			expectReadOnce(t, folder, readsOf(t, folder), fallbackCode, esES, esMX)
		})
	})
}
