// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"context"
	"os"
	"path"
)

// fileKeyHolder is key holders 4 and 5: they differ only in how the file holding the key is
// opened.
type fileKeyHolder struct {
	openFile func(folder *os.Root) (*os.File, error)
}

// openKeyFile opens bootstrap.key through the folder's root, which refuses a link out of it.
func openKeyFile(folder *os.Root) (*os.File, error) { return folder.Open(KeyFileName) }

// openSwarmSecret opens the Swarm secret by its fixed path, without the folder.
func openSwarmSecret(_ *os.Root) (*os.File, error) {
	return os.OpenInRoot(path.Dir(SwarmSecretPath), path.Base(SwarmSecretPath))
}

func (fileHolder fileKeyHolder) key(_ context.Context, folder *os.Root, _ []byte,
	_ ServiceAccount) (Key256, error) {
	file, err := fileHolder.openFile(folder)
	if err != nil {
		return Key256{}, Error{Code: ErrKey, Err: err}
	}
	key, readErr := readKey(file)
	closeErr := file.Close()
	if readErr != nil {
		return Key256{}, readErr
	}
	if closeErr != nil {
		clear(key[:])
		return Key256{}, Error{Code: ErrKey, Err: closeErr}
	}
	return key, nil
}

func (fileHolder fileKeyHolder) newKey(ctx context.Context, folder *os.Root,
	account ServiceAccount) (Key256, []byte, error) {
	key, err := fileHolder.key(ctx, folder, nil, account)
	return key, nil, err
}

func (fileKeyHolder) deleteKey(context.Context, []byte) error { return nil }
