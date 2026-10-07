// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"io/fs"
	"maps"
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
	judged, err := checkServiceItems(directory, folder, mode, stat.Uid, lock)
	if err != nil {
		return nil, err
	}
	defer closeJudged(judged)
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
// service account cannot write, in that order. Every item the unlock reads is opened once, here,
// and judged on that descriptor, the held lock on its own; the read that follows goes through the
// same descriptors, which are returned by path and closed by the caller. An absent item is not in
// the map.
func checkServiceItems(directory *os.File, folder string, mode KeyMode, accountID uint32, lock *os.File) (map[string]*os.File, error) {
	held := map[string]*os.File{}
	fail := func(err error) (map[string]*os.File, error) {
		closeJudged(held)
		return nil, err
	}
	keep := func(path string, file *os.File, err error) error {
		if errors.Is(err, unix.ENOENT) {
			return nil
		} else if err != nil {
			return err
		}
		held[path] = file
		return nil
	}
	for _, name := range []string{bootstrapFileName, keyFileName} {
		path := filepath.Join(folder, name)
		file, _, err := openUnlinked(int(directory.Fd()), name, path, unix.O_PATH, itemOf(name))
		if err := keep(path, file, err); err != nil {
			return fail(err)
		}
	}
	// A link in either of these is a finding of the permission check, not a Link refusal.
	credentialPath := filepath.Join(folder, systemdCredentialFileName)
	credential, err := openPathHandle(int(directory.Fd()), systemdCredentialFileName, credentialPath)
	if err := keep(credentialPath, credential, err); err != nil {
		return fail(err)
	}
	if mode == ModeContainer {
		secret, err := openPathHandle(unix.AT_FDCWD, swarmSecretPath, swarmSecretPath)
		if err := keep(swarmSecretPath, secret, err); err != nil {
			return fail(err)
		}
	}
	inspected := maps.Clone(held)
	inspected[filepath.Join(folder, lockFileName)] = lock
	findings, err := findLooserItems(directory, folder, mode, ownerName(accountID), accountID, inspected)
	if err != nil {
		return fail(err)
	}
	if len(findings) > 0 {
		return fail(looserRefusal(findings))
	}
	if bootstrapFile := held[filepath.Join(folder, bootstrapFileName)]; bootstrapFile != nil {
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
	return held, nil
}

func closeJudged(held map[string]*os.File) {
	for _, file := range held {
		_ = file.Close() //nolint:errcheck // a path handle holds nothing to flush
	}
}

// openPathHandle opens an item as itself, a link included, without reading it.
func openPathHandle(directory int, name, path string) (*os.File, error) {
	descriptor, err := unix.Openat(directory, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(descriptor), path), nil
}

func refusedWrite(err error) bool {
	return errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EROFS)
}
