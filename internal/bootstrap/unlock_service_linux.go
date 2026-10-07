// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func unlockServiceOnPlatform(ctx context.Context, folder string, mode KeyMode) (ServiceHandle, error) {
	if isElevated() {
		return nil, &Refusal{Cause: WrongAccount}
	}
	if mode == ModeContainer {
		folder = containerBootstrapFolder
	}
	directory, err := openFolderHandle(folder)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return nil, &Refusal{Cause: WrongAccount}
		}
		return nil, err
	}
	defer func() { _ = directory.Close() }() //nolint:errcheck // no pending writes
	var stat unix.Stat_t
	if err := unix.Fstat(int(directory.Fd()), &stat); err != nil {
		return nil, err
	}
	if stat.Uid != uint32(os.Geteuid()) { //nolint:gosec // an effective user ID is never negative
		return nil, &Refusal{Cause: WrongAccount}
	}
	lock, err := openLinuxLock(int(directory.Fd()), filepath.Join(folder, lockFileName), stat.Uid, false)
	if err != nil {
		return nil, err
	}
	locked := false
	defer func() {
		if !locked {
			releaseSetupLock(lock)
		}
	}()
	if err := judgeFolder(directory, folder); err != nil {
		return nil, err
	}
	if err := checkServiceItems(directory, folder, mode, stat.Uid); err != nil {
		return nil, err
	}
	if err := checkSetupMode(ctx, mode); err != nil {
		return nil, err
	}
	opened, holding, err := unlockLinuxFile(ctx, directory, folder, mode, stat.Uid, true)
	if err != nil {
		return nil, err
	}
	locked = true
	return serviceHandle{&setupHandle{file: opened, lock: lock, holding: holding}}, nil
}

// checkServiceItems refuses a link, then an item looser than its rule, then a file or folder the
// service account cannot write, in that order.
func checkServiceItems(directory *os.File, folder string, mode KeyMode, accountID uint32) error {
	for _, name := range []string{bootstrapFileName, keyFileName} {
		var stat unix.Stat_t
		err := unix.Fstatat(int(directory.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			continue
		} else if err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFLNK || (stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Nlink != 1) {
			return &Refusal{Cause: Link, Path: filepath.Join(folder, name), Item: itemOf(name)}
		}
	}
	account := strconv.FormatUint(uint64(accountID), 10)
	if found, err := user.LookupId(account); err == nil {
		account = found.Username
	}
	findings, err := findLooserItems(directory, folder, mode, account, accountID)
	if err != nil {
		return err
	}
	if len(findings) > 0 {
		// Map order is random; the first by path keeps the refusal the same every time.
		first := slices.MinFunc(findings, func(left, right Finding) int { return strings.Compare(left.Path, right.Path) })
		return &Refusal{Cause: LooserThanRule, Path: first.Path, Item: first.Item}
	}
	err = unix.Faccessat(int(directory.Fd()), bootstrapFileName, unix.W_OK, unix.AT_EACCESS)
	if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EROFS) {
		return &Refusal{Cause: NotWritable, Path: filepath.Join(folder, bootstrapFileName), Item: ItemFile}
	}
	err = unix.Faccessat(int(directory.Fd()), ".", unix.W_OK, unix.AT_EACCESS)
	if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EROFS) {
		return &Refusal{Cause: NotWritable, Path: folder, Item: ItemFolder}
	}
	return nil
}
