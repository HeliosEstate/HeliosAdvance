// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"errors"
	"io/fs"
	"os"
)

var secretRefusals = refusals{ErrSecretMissing, ErrSecretUnreadable, ErrSecretForm}

func checkSecret(_ *os.File, info fs.FileInfo) error {
	return judgeOwnerAndMode(info, ErrSecretUnreadable, ErrSecretReachable)
}

// readSecret takes the key from the Swarm secret into buffer, which the caller clears.
func readSecret(buffer []byte) ([]byte, error) {
	root, err := os.OpenRoot(SecretFolder)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrSecretMissing
	}
	if err != nil {
		return nil, ErrSecretUnreadable
	}
	key, err := readKeyText(root, SecretName, secretRefusals, checkSecret, buffer)
	if closeErr := root.Close(); err == nil && closeErr != nil {
		return nil, ErrSecretUnreadable
	}
	return key, err
}
