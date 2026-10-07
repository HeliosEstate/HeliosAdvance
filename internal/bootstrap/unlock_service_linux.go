// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package bootstrap

import (
	"context"
	"errors"
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
	judged, err := checkServiceItems(directory, folder, mode, stat.Uid)
	if err != nil {
		return nil, err
	}
	if judged != nil {
		defer func() { _ = judged.Close() }() //nolint:errcheck // a path handle holds nothing to flush
	}
	if err := checkSetupMode(ctx, mode); err != nil {
		return nil, err
	}
	opened, holding, err := unlockLinuxFile(ctx, directory, folder, mode, stat.Uid, true, judged)
	if err != nil {
		return nil, err
	}
	locked = true
	return serviceHandle{&setupHandle{file: opened, lock: lock, holding: holding}}, nil
}

// checkServiceItems refuses a link, then an item looser than its rule, then a file or folder the
// service account cannot write, in that order. The bootstrap file is opened once, here, and every
// check and the read that follows go through that descriptor; the caller closes it. An absent file
// gives none.
func checkServiceItems(directory *os.File, folder string, mode KeyMode, accountID uint32) (*os.File, error) {
	var bootstrapFile *os.File
	fail := func(err error) (*os.File, error) {
		if bootstrapFile != nil {
			_ = bootstrapFile.Close() //nolint:errcheck // a path handle holds nothing to flush
		}
		return nil, err
	}
	for _, name := range []string{bootstrapFileName, keyFileName} {
		judged, _, err := openUnlinked(int(directory.Fd()), name, filepath.Join(folder, name), unix.O_PATH, itemOf(name))
		if errors.Is(err, unix.ENOENT) {
			continue
		} else if err != nil {
			return fail(err)
		}
		if name == bootstrapFileName {
			bootstrapFile = judged
		} else {
			_ = judged.Close() //nolint:errcheck // a path handle holds nothing to flush
		}
	}
	judged := map[string]*os.File{}
	if bootstrapFile != nil {
		judged[filepath.Join(folder, bootstrapFileName)] = bootstrapFile
	}
	findings, err := findLooserItems(directory, folder, mode, ownerName(accountID), accountID, judged)
	if err != nil {
		return fail(err)
	}
	if len(findings) > 0 {
		return fail(looserRefusal(findings))
	}
	if bootstrapFile != nil {
		// Any refusal of write access, an immutable flag included, is NotWritable; any other
		// failure of the check is returned as it is.
		writer, err := reopenDescriptor(bootstrapFile, unix.O_WRONLY)
		if refusedWrite(err) {
			return fail(&Refusal{Cause: NotWritable, Path: filepath.Join(folder, bootstrapFileName), Item: ItemFile})
		} else if err != nil {
			return fail(err)
		}
		_ = writer.Close() //nolint:errcheck // nothing was written
	}
	// Flags 0 ask the kernel itself: the service is not setuid, so its real and effective IDs match,
	// and AT_EACCESS would fall back to the mode bits alone when the kernel answers EPERM.
	if err := unix.Faccessat(int(directory.Fd()), ".", unix.W_OK, 0); refusedWrite(err) {
		return fail(&Refusal{Cause: NotWritable, Path: folder, Item: ItemFolder})
	} else if err != nil {
		return fail(err)
	}
	return bootstrapFile, nil
}

func refusedWrite(err error) bool {
	return errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EROFS)
}
