// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
)

var credentialRefusals = refusals{ErrCredentialMissing, ErrCredentialUnreadable, ErrCredentialForm}

// readCredential takes the key from systemd's credential into buffer, which the caller clears.
// The credential is opened by its path and not inside a folder handle, because a link leading out
// of the folder is allowed here and a handle would refuse it.
func readCredential(buffer []byte) ([]byte, error) {
	folder, _ := os.LookupEnv(CredentialsVariable)
	if folder == "" {
		return nil, ErrCredentialUnset
	}
	path := filepath.Join(filepath.Clean(folder), CredentialName)
	opened, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	key, err := readAndClose(opened, err, KeyBytes, credentialRefusals, nil)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	if len(key) != KeyBytes || bytes.Equal(key, make([]byte, KeyBytes)) {
		return nil, ErrCredentialForm
	}
	return buffer[:copy(buffer, key)], nil
}
