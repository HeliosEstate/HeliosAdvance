// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main_test

import (
	"os"
	"path/filepath"
	"testing"
)

// unopenableLogFiles are the log files only Windows can make that will not open for appending: a
// file the test holds open with no sharing, for reading and writing, which CI's elevated runner
// cannot get past either.
func unopenableLogFiles() map[string]func(t *testing.T) (string, func(t *testing.T)) {
	return map[string]func(t *testing.T) (string, func(t *testing.T)){
		"a file held open with no sharing": func(t *testing.T) (string, func(t *testing.T)) {
			t.Helper()
			path := filepath.Join(t.TempDir(), "hadv.log")
			if err := os.WriteFile(path, []byte(sysopLine), 0o600); err != nil {
				t.Fatalf("writing the log file: %v", err)
			}
			// Registered before the hold, so it runs once the hold has ended and the file can be
			// read whole.
			t.Cleanup(func() {
				found, err := os.ReadFile(path)
				if err != nil || string(found) != sysopLine {
					t.Errorf("the log file holds %q (%v) after the refusal, want %q as it was", found, err, sysopLine)
				}
			})
			makeUnopenable(t, path)
			return path, func(*testing.T) {}
		},
	}
}
