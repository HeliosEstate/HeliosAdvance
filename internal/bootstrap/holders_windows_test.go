// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Key holders 4 and 5 on Windows, a header the engine does not read there: each refused with
// ErrHeader, even with a good credential named in the variable systemd names it in and a good key
// file beside it, so an engine that took either holder's key would open the file.
package bootstrap_test

import (
	"testing"

	"github.com/heliosestate/heliosadvance/internal/bootstrap"
)

// TestWindowsHolders sets the process's environment, so it runs alone, before the parallel tests.
func TestWindowsHolders(t *testing.T) { //nolint:paralleltest // it sets the process's environment
	t.Run("If the bootstrap file is shorter than HeaderBytes, NonceBytes and TagBytes together, or its first HeaderBytes are not Magic, FormatVersion, then KeyHolderKeyFile with a sealed-key length of 0, on Windows KeyHolderTPM or KeyHolderSoftwareKeyStore with a sealed-key length of SealedKeyBytes, or on Linux KeyHolderSystemd or KeyHolderSwarm with a sealed-key length of 0, or, under key holder 2 or 3, the file is too short for the sealed key, nonce and tag, or the sealed key's first KeyNameBytes are not KeyNamePrefix and 32 lower-case hex digits, then Open shall return ErrHeader before it opens the key file, asks a key store, or reads a credential or secret.", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
		for _, holder := range []string{"4", "5"} {
			for name, spoil := range map[string]func(t *testing.T, made *layout){
				"":                       func(*testing.T, *layout) {},
				", the key file missing": func(t *testing.T, made *layout) { t.Helper(); remove(t, made.keyFile) },
				", the key file no one may open": func(t *testing.T, made *layout) {
					t.Helper()
					makeUnopenable(t, made.keyFile)
				},
				", the key file open to others": func(t *testing.T, made *layout) { t.Helper(); openToOthers(t, made.keyFile) },
			} {
				t.Run("key holder "+holder+", no sealed key, a good credential named and a good key file"+name+": ErrHeader", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
					made := makeFolderWith(t, plaintextOf(t, 64), "holder "+holder)
					made.credential = made.key
					made.nameCredential(t, made.key)
					spoil(t, made)
					made.expectRefused(t, bootstrap.ErrHeader)
				})
			}
		}
	})
}
