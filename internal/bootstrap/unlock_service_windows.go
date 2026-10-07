// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package bootstrap

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/sys/windows"
)

// fileAddFile is the right to create a file in a folder, FILE_ADD_FILE of winnt.h.
const fileAddFile = 0x2

var reOpenFile = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReOpenFile")

func unlockServiceOnPlatform(ctx context.Context, folder string, mode KeyMode) (ServiceHandle, error) {
	if isElevated() {
		return nil, &Refusal{Cause: WrongAccount}
	}
	directory, err := openFolderHandle(folder)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return nil, &Refusal{Cause: WrongAccount}
		}
		return nil, err
	}
	defer func() { _ = directory.Close() }() //nolint:errcheck // no pending writes
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	if err := checkFolderNamesAccount(directory, folder, user.User.Sid); err != nil {
		return nil, err
	}
	account := accountName(user.User.Sid)
	lockPath := filepath.Join(folder, lockFileName)
	lock, err := takeSetupLock(directory, folder, user.User.Sid, true)
	if err != nil {
		return nil, err
	}
	locked := false
	defer func() {
		if !locked {
			_ = lock.Close() //nolint:errcheck // closing releases the exclusive share
		}
	}()
	if err := judgeFolder(directory, folder); err != nil {
		return nil, err
	}
	if err := checkWindowsHandle(windows.Handle(lock.Fd()), lockPath); err != nil {
		return nil, err
	}
	judged, err := checkServiceItems(directory, folder, mode, account, user.User.Sid, lock)
	if err != nil {
		return nil, err
	}
	defer closeJudged(judged)
	if mode != ModeMachineKeyPair {
		return nil, &Refusal{Cause: SourceRefused}
	}
	opened, holding, err := unlockWindowsFile(ctx, directory, folder, judged)
	if err != nil {
		return nil, err
	}
	locked = true
	return serviceHandle{&setupHandle{file: opened, lock: lock, holding: holding}}, nil
}

// checkFolderNamesAccount refuses a process whose own account the folder's access list does not
// name beside SYSTEM and Administrators: a group the account belongs to does not count.
func checkFolderNamesAccount(directory *os.File, folder string, account *windows.SID) error {
	found, err := readHeld(windows.Handle(directory.Fd()), folder, ItemFolder)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(found.grantees, func(trustee *windows.SID) bool { return windows.EqualSid(trustee, account) }) {
		return &Refusal{Cause: WrongAccount}
	}
	return nil
}

// checkServiceItems refuses a link, then an item looser than its rule, then a file or folder the
// service account cannot write, in that order. The bootstrap file and the sealed-key file are
// opened once, here, and judged on those handles, the held lock on its own; the read that follows
// goes through the same handles, which are returned by name and closed by the caller. An absent
// file is not in the map.
func checkServiceItems(directory *os.File, folder string, mode KeyMode, account string, accountSID *windows.SID, lock *os.File) (map[string]*os.File, error) {
	folderHandle := windows.Handle(directory.Fd())
	held := map[string]*os.File{}
	fail := func(err error) (map[string]*os.File, error) {
		closeJudged(held)
		return nil, err
	}
	for _, name := range []string{bootstrapFileName, sealedKeyFileName} {
		handle, err := openChild(folderHandle, name, windows.GENERIC_READ|windows.FILE_READ_ATTRIBUTES)
		if windowsMissingItem(err) {
			continue
		} else if err != nil {
			return fail(err)
		}
		judged := os.NewFile(uintptr(handle), name)
		if err := checkWindowsHandle(handle, filepath.Join(folder, name)); err != nil {
			_ = judged.Close() //nolint:errcheck // nothing to flush on a read-only handle
			return fail(err)
		}
		held[name] = judged
	}
	allowed, err := allowedForSID(accountSID)
	if err != nil {
		return fail(err)
	}
	handles := map[string]windows.Handle{lockFileName: windows.Handle(lock.Fd())}
	for name, file := range held {
		handles[name] = windows.Handle(file.Fd())
	}
	findings, err := findLooserItems(directory, folder, mode, account, allowed, handles)
	if err != nil {
		return fail(err)
	}
	if len(findings) > 0 {
		return fail(looserRefusal(findings))
	}
	// A rewrite renames a new file over the bootstrap file, which needs delete access as well as
	// write. Only a refusal of access is NotWritable; a sharing violation or any other failure of
	// the check is returned as it is.
	if bootstrapFile := held[bootstrapFileName]; bootstrapFile != nil {
		err = reopenForWrite(windows.Handle(bootstrapFile.Fd()), windows.FILE_WRITE_DATA|windows.DELETE)
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return fail(&Refusal{Cause: NotWritable, Path: filepath.Join(folder, bootstrapFileName), Item: ItemFile})
		} else if err != nil {
			return fail(err)
		}
	}
	// ReOpenFile refuses a directory handle whatever its access list says, so the folder is
	// opened again as an empty name under itself.
	again, err := openChild(folderHandle, "", fileAddFile)
	if errors.Is(err, windows.STATUS_ACCESS_DENIED) {
		return fail(&Refusal{Cause: NotWritable, Path: folder, Item: ItemFolder})
	} else if err != nil {
		return fail(err)
	}
	_ = windows.CloseHandle(again) //nolint:errcheck // nothing to flush
	return held, nil
}

func closeJudged(held map[string]*os.File) {
	for _, file := range held {
		_ = file.Close() //nolint:errcheck // nothing to flush on a read-only handle
	}
}

// reopenForWrite asks the judged handle for a handle to the same item with the access given and
// closes it at once: the check is made on the handle that was judged, never on a name.
func reopenForWrite(handle windows.Handle, access uint32) error {
	reopened, _, err := reOpenFile.Call(uintptr(handle), uintptr(access), shareAll, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if windows.Handle(reopened) == windows.InvalidHandle {
		return err
	}
	return windows.CloseHandle(windows.Handle(reopened))
}
