// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The approved tests for issue #149, create and the write path, written by the QA session from
// the issue's lines. Each group of rows quotes, word for word, the line its rows prove. Create
// has key holders 4 and 5 only on Linux, so the Linux rows run as root in the bootstrap file
// oracle's own image, through TestCreateLinuxRowsInContainer, and the oracle reads every file
// create writes under the same test key. Windows has only key holder 1, built by a later issue,
// so its rows here are the key holders it does not have. Every create is passed fields that
// keep every rule on Fields, so that no row's code changes once create checks its fields.
package bootstrap

import "testing"

// The line the rows on both platforms prove, word for word.
const lineKeyHolderMissing = "If the caller or the header names a key holder the platform does not have, then the bootstrap package shall return ErrKey."

// TestCreateLinuxRowsInContainer runs create's Linux rows in the bootstrap file oracle's image:
// as root, then the rows that need permissions to refuse as the account nobody.
func TestCreateLinuxRowsInContainer(t *testing.T) {
	t.Parallel()
	linuxRowsInContainer(t, "TestCreateLinuxAsRoot", "TestCreateLinuxAsNobody")
}

// rowFields is fields that keep every rule on Fields, with one vault key: a fresh copy on each
// call.
func rowFields() Fields {
	return Fields{
		Server:          7,
		Connection:      "host=db.example.invalid port=5432 dbname=helios",
		AccountName:     "helios_server_7",
		AccountPassword: []byte("a row's database password"),
		VaultKeys:       []VaultKey{{Version: 1, Key: rowKey(1)}},
		ReceivingKey:    []byte("a row's receiving key, private half"),
		SigningKey:      []byte("a row's signing key, private half"),
	}
}

// rowKey is a 256-bit key whose bytes count up from seed, so each row's keys differ and read
// back recognizably.
func rowKey(seed byte) Key256 {
	var key Key256
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

// create creates a bootstrap file in folder, as hadv-setup does. Key holders 2 to 5 make no
// Windows key, so no create here has one it could not delete.
func create(t *testing.T, folder string, holder KeyHolder, fields Fields, overwrite bool) error {
	t.Helper()
	undeleted, err := New().Create(t.Context(), folder, holder, rowAccount, fields, overwrite)
	if undeleted != "" {
		t.Errorf("got the undeleted Windows key %q, want none", undeleted)
	}
	return err
}
