// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Key holders 4 and 5 on Windows, a header the engine does not read there: refused, even with a
// good credential named in the program's environment and a good key file beside the bootstrap
// file, so a program that took either holder's key would start.
package main_test

import "testing"

func TestWindowsHoldersProgram(t *testing.T) {
	t.Parallel()

	t.Run("If the bootstrap file's header is not format version 1's for the key file, on Windows for the TPM or the software key store, or on Linux for a systemd credential or a Swarm secret, or the bootstrap file is too short for its header, nonce and tag, then the engine shall write one `start_failed` line saying so, without reading the key file, asking a key store, or reading a credential or secret, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		for _, holder := range []string{"4", "5"} {
			t.Run("key holder "+holder+", no sealed key, a good key file and a good credential named: one start_failed line, and a non-zero exit, the same reason with the key file missing, not a missing key file's", func(t *testing.T) {
				t.Parallel()
				made := brokenFolder(t, "holder "+holder)
				reason := made.refusedWith(t, nil, namingFolder(writeCredentialFolder(t, made.key)))
				without := brokenFolder(t, "holder "+holder)
				removeFile(t, without.keyFile)
				if got := without.refusedWith(t, nil, namingFolder(writeCredentialFolder(t, without.key))); got != reason {
					t.Fatalf("with the key file missing the reason was %q, not the header's %q: the key file was read", got, reason)
				}
				expectOwnReason(t, reason, keyMissingReason(t), "a missing key file")
			})
		}
	})
}
