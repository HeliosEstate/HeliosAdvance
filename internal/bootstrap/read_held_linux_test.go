// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// What Open reads of an oversized credential under key holder 4 and an oversized secret under key
// holder 5, on Linux: no more than the line's bound of it, counted as for the bootstrap file and
// the key file, from strace's account of a child that runs the row again. The child runs every
// ancestor's body again, so each top-level test here does nothing but run its rows, and each row
// makes its folders only once it knows it is not the child; the child takes the credential folder
// from the environment its parent set, and the secret its parent planted.
package bootstrap_test

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/bootstrap"
)

// TestLinuxCredentialReadBound sets the process's environment, so it runs alone.
func TestLinuxCredentialReadBound(t *testing.T) {
	t.Run("If the credential is not exactly KeyBytes bytes, or is KeyBytes zero bytes, then Open shall return ErrCredentialForm, having read at most KeyBytes and one byte more of it.", func(t *testing.T) {
		t.Run(boundRow("a 1 MiB credential, the right key then zeros: ErrCredentialForm", 33), func(t *testing.T) {
			if openAsChild(t, bootstrap.ErrCredentialForm) {
				return
			}
			made := makeFolderWith(t, plaintextOf(t, 64), "holder 4")
			folder := writeCredential(t, append(bytes.Clone(made.key), make([]byte, 1<<20-len(made.key))...))
			t.Setenv(systemdFolderVariable, folder)
			expectHeldReadAtMost(t, made, folder, 33)
		})
	})
}

// TestLinuxRootSecretReadBound plants the secret at the one path the machine has for it, through
// sudo, so it runs alone.
func TestLinuxRootSecretReadBound(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
	t.Run("If the secret is longer than KeyFileMostBytes, is not in the key file's form, or holds a key of 32 zero bytes, then Open shall return ErrSecretForm, having read at most KeyFileMostBytes and one byte more of it.", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
		t.Run(boundRow("a 1 MiB secret, the key then line feeds: ErrSecretForm", keyFileMostBytes+1), func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			if openAsChild(t, bootstrap.ErrSecretForm) {
				return
			}
			made := makeFolderWith(t, plaintextOf(t, 64), "holder 5")
			takeSecretFolder(t, true)
			plantSecret(t, []byte(baseOf(made)+strings.Repeat("\n", 1<<20)), 0o400, ownOwner)
			expectHeldReadAtMost(t, made, secretFolder, keyFileMostBytes+1)
		})
	})
}

// expectHeldReadAtMost runs the calling row again in a child under strace and fails the row when
// the child read more than most bytes of the credential or secret in folder. A count with no read
// of the bootstrap file, or none of the credential or secret, is an account whose paths are not
// the row's, and its bound would pass on nothing counted.
func expectHeldReadAtMost(t *testing.T, made *layout, folder string, most int64) {
	t.Helper()
	reads := readsOf(t, made.folder, folder)
	if reads[fileName] == 0 {
		t.Fatalf("strace's account shows no read of %s in the row's folder, which Open reads first: a fault in the test", fileName)
	}
	if reads[heldKeyName] == 0 {
		t.Fatalf("strace's account shows no read of %s in %s: a fault in the test", heldKeyName, filepath.Clean(folder))
	}
	if reads[heldKeyName] > most {
		t.Fatalf("Open read %d bytes of %s, more than %d", reads[heldKeyName], heldKeyName, most)
	}
}
