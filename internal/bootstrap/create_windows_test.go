// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The Windows rows of issue #149: the key holders Windows does not have, named by create's
// caller or by a file's header. Each folder holds the test key as bootstrap.key, so a build that
// took key holder 4 on Windows would open or create rather than fail for a missing key. Named to
// run on CI's Windows runner, which needs no oracle for them.
package bootstrap

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestWindowsMissingKeyHolders(t *testing.T) {
	t.Parallel()
	keyFolder := func(t *testing.T) string {
		t.Helper()
		folder := t.TempDir()
		if err := os.WriteFile(filepath.Join(folder, KeyFileName), sampleBytes(t, "test.key"), 0o600); err != nil {
			t.Fatal(err)
		}
		return folder
	}
	t.Run(lineKeyHolderMissing, func(t *testing.T) {
		t.Parallel()
		for _, holder := range []KeyHolder{SystemdByService, SystemdAtStart, KeyFile, SwarmSecret, 0, 6} {
			t.Run("create with key holder "+strconv.Itoa(int(holder)), func(t *testing.T) {
				t.Parallel()
				wantCode(t, create(t, keyFolder(t), holder, rowFields(), false), ErrKey)
			})
		}
		for _, holder := range []KeyHolder{SystemdByService, SystemdAtStart, KeyFile, SwarmSecret} {
			t.Run("open a file whose header names key holder "+strconv.Itoa(int(holder)), func(t *testing.T) {
				t.Parallel()
				folder := keyFolder(t)
				copySample(t, folder, "keyholder-"+strconv.Itoa(int(holder)))
				file, err := open(t, folder)
				wantRefused(t, file, err, ErrKey)
			})
		}
	})
}
