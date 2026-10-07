// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

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
	var bootstrapFile *os.File
	for _, name := range []string{bootstrapFileName, keyFileName} {
		judged, err := openJudgedItem(directory, folder, name)
		if err != nil {
			return err
		}
		if name == bootstrapFileName {
			bootstrapFile = judged
		} else if judged != nil {
			_ = judged.Close() //nolint:errcheck // a path handle holds nothing to flush
		}
	}
	if bootstrapFile != nil {
		defer func() { _ = bootstrapFile.Close() }() //nolint:errcheck // a path handle holds nothing to flush
	}
	findings, err := findLooserItems(directory, folder, mode, ownerName(accountID), accountID)
	if err != nil {
		return err
	}
	if len(findings) > 0 {
		return looserRefusal(findings)
	}
	if bootstrapFile != nil {
		// Reopening the judged descriptor through /proc asks that file itself, a link or a
		// swapped name cannot answer for it; any refusal of write access, an immutable flag
		// included, is NotWritable.
		writer, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", bootstrapFile.Fd()), unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err == nil {
			_ = unix.Close(writer) //nolint:errcheck // nothing was written
		} else if refusedWrite(err) {
			return &Refusal{Cause: NotWritable, Path: filepath.Join(folder, bootstrapFileName), Item: ItemFile}
		} else {
			return err
		}
	}
	if err := unix.Faccessat(int(directory.Fd()), ".", unix.W_OK, unix.AT_EACCESS); refusedWrite(err) {
		return &Refusal{Cause: NotWritable, Path: folder, Item: ItemFolder}
	}
	return nil
}

// openJudgedItem opens a name in the folder as a path handle, without following a link, and refuses
// a link or a file with more than one name. An absent name gives no handle.
func openJudgedItem(directory *os.File, folder, name string) (*os.File, error) {
	descriptor, err := unix.Openat(int(directory.Fd()), name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	judged := os.NewFile(uintptr(descriptor), name)
	var stat unix.Stat_t
	if err := unix.Fstat(descriptor, &stat); err != nil {
		_ = judged.Close() //nolint:errcheck // returning the stat error
		return nil, err
	}
	if stat.Mode&unix.S_IFMT == unix.S_IFLNK || (stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Nlink != 1) {
		_ = judged.Close() //nolint:errcheck // returning the refusal
		return nil, &Refusal{Cause: Link, Path: filepath.Join(folder, name), Item: itemOf(name)}
	}
	return judged, nil
}

func refusedWrite(err error) bool {
	return errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EROFS)
}
