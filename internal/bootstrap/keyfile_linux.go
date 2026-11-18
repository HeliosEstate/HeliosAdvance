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

// checkKeyFile is the key file's check for readOpened; the judging is shared with the secret.
func checkKeyFile(_ *os.File, info fs.FileInfo) error {
	return judgeOwnerAndMode(info, ErrKeyFilePermissions, ErrKeyFileReachable)
}

// judgeOwnerAndMode judges the owner and mode as the opened file's own Stat gives them, so a name
// swapped after the open changes nothing.
func judgeOwnerAndMode(info fs.FileInfo, unconfirmed, reachable error) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return unconfirmed
	}
	if int64(stat.Uid) != int64(os.Geteuid()) || stat.Mode&groupOrOthersAccess != 0 {
		return reachable
	}
	return nil
}
