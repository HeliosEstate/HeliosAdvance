// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"io/fs"
	"os"
	"syscall"
)

// groupOrOthersAccess is every bit of a mode that lets someone but the owner reach a file.
const groupOrOthersAccess = 0o077

// checkKeyFile judges the owner and mode of the key file as the opened file's own Stat gives
// them, so a name swapped after the open changes nothing.
func checkKeyFile(_ *os.File, info fs.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ErrKeyFilePermissions
	}
	if int64(stat.Uid) != int64(os.Geteuid()) || stat.Mode&groupOrOthersAccess != 0 {
		return ErrKeyFileReachable
	}
	return nil
}
