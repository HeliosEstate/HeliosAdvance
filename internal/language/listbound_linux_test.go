// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// What Load lists of a folder holding far more entries than the limit. A row runs its Load again
// in a child under strace, as the read-bound rows do, which names the folder behind every listing
// call and every entry each call handed back. The system hands entries back in batches whose size
// the library's buffer sets, so no row can count exactly the entries Load took: a sound Load stops
// calling once it holds one more than the limit, so every call but its last handed back no more
// than the limit, whatever its buffer. Names of 200 characters keep a batch to a few dozen entries.
package language_test

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// traceListing is one whole listing call in strace's account of a thread: the folder behind the
// descriptor, the entries handed back and what the call returned.
var traceListing = regexp.MustCompile(`^getdents(?:64)?\(\d+<([^>]*)>, (.*)\) += (-?\d+)(?: .*)?$`)

// traceListingStart is the start of a listing call in strace's account, whole or not.
var traceListingStart = regexp.MustCompile(`^getdents(?:64)?\(`)

// traceEntry is one entry's name in a listing call's account; the folder itself and its parent
// are the two dots, which a listing hands back and Load does not count.
var traceEntry = regexp.MustCompile(`d_name="((?:[^"\\]|\\.)*)"`)

// listingsOf runs the calling row again in a child under strace, which loads folder, and returns
// how many entries, the two dots left out, each listing call of the folder inside it handed back.
// The child must pass the row: it checks what Load returned.
func listingsOf(t *testing.T, folder, inside string) []int {
	t.Helper()
	if _, err := exec.LookPath("strace"); err != nil {
		t.Fatalf("strace, which names the folder behind each listing call, is not installed: %v", err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatalf("finding the test binary: %v", err)
	}
	root, err := filepath.EvalSymlinks(folder)
	if err != nil {
		t.Fatalf("resolving the lang folder %s: %v", folder, err)
	}
	judged := filepath.Join(root, inside)
	account := filepath.Join(t.TempDir(), "listings")
	// -v prints every entry a call handed back, and -s every character of its name.
	arguments := []string{"-ff", "--seccomp-bpf", "-y", "-v", "-s", "512", "-e", "trace=getdents,getdents64", "-o", account, binary,
		"-test.run=" + runPattern(t.Name()), "-test.count=1", "-test.v", "-test.timeout=" + testrun.Patient(testrun.HangBound).String()}
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
		t.Fatalf("strace wrote no account of the child's listing calls (%v)", err)
	}
	var calls []int
	for _, thread := range threads {
		text, err := os.ReadFile(thread)
		if err != nil {
			t.Fatalf("reading strace's account %s: %v", thread, err)
		}
		for line := range strings.SplitSeq(string(text), "\n") {
			if !traceListingStart.MatchString(line) {
				continue
			}
			found := traceListing.FindStringSubmatch(line)
			if found == nil || strings.Contains(line, "...]") {
				// A listing call not shown whole, or with its entries cut short, cannot be counted.
				t.Fatalf("strace's account shows a listing call it cannot count: %.300q", line)
			}
			if found[1] != judged {
				continue
			}
			entries := 0
			for _, name := range traceEntry.FindAllStringSubmatch(found[2], -1) {
				if name[1] != "." && name[1] != ".." {
					entries++
				}
			}
			calls = append(calls, entries)
		}
	}
	return calls
}

func TestLinuxListBound(t *testing.T) {
	t.Parallel()
	t.Run("If folder, or a folder in it, holds more than MostEntries entries, then Load shall return ErrFileRefused naming that folder, having listed no more than MostEntries and one of its entries.", func(t *testing.T) {
		t.Parallel()
		const held = 4096
		for _, each := range []struct{ name, inside, named, code string }{
			{"the lang folder", "", langFolder, fallbackCode},
			{"fr-fr's folder, the board's language", frFR, frFR, frFR},
			{"notes, a folder that is no language", notesFolder, notesFolder, fallbackCode},
		} {
			t.Run(fmt.Sprintf("%s of %d entries named in 200 characters: ErrFileRefused naming it, every listing call of it but the last handing back no more than 256", each.name, held), func(t *testing.T) {
				t.Parallel()
				if folder, child := childFolder(t); child {
					expectFolderRefused(t, folder, each.code, each.named)
					return
				}
				folder := overLimit(t, each.inside, strings.Repeat("x", 190), held)
				filled := filepath.Join(folder, each.inside)
				calls := listingsOf(t, folder, each.inside)
				total, largest := 0, 0
				for _, entries := range calls {
					total += entries
					largest = max(largest, entries)
				}
				// Load must list one more than the limit to know the folder holds more.
				if total < mostEntries+1 {
					t.Fatalf("strace's account shows %d entries of %s handed back in %d calls, fewer than the %d Load needs to refuse it", total, filled, len(calls), mostEntries+1)
				}
				if total-largest > mostEntries {
					t.Fatalf("Load listed %d entries of %s in %d calls %v: the calls but the largest handed back %d, more than %d", total, filled, len(calls), calls, total-largest, mostEntries)
				}
				t.Logf("%d entries handed back in %d calls %v", total, len(calls), calls)
			})
		}
	})
}
