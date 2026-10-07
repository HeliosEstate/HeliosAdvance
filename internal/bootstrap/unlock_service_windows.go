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
	lockHandle, err := openSetupLock(windows.Handle(directory.Fd()), user.User.Sid, true)
	if errors.Is(err, windows.STATUS_SHARING_VIOLATION) || errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) {
		return nil, &Refusal{Cause: InUse}
	} else if err != nil {
		return nil, err
	}
	lock := os.NewFile(uintptr(lockHandle), lockPath)
	locked := false
	defer func() {
		if !locked {
			_ = lock.Close() //nolint:errcheck // closing releases the exclusive share
		}
	}()
	if err := judgeFolder(directory, folder); err != nil {
		return nil, err
	}
	if err := checkWindowsHandle(lockHandle, lockPath); err != nil {
		return nil, err
	}
	if err := checkServiceItems(directory, folder, mode, account, user.User.Sid); err != nil {
		return nil, err
	}
	if mode != ModeMachineKeyPair {
		return nil, &Refusal{Cause: SourceRefused}
	}
	opened, holding, err := unlockWindowsFile(ctx, directory, folder)
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
// service account cannot write, in that order.
func checkServiceItems(directory *os.File, folder string, mode KeyMode, account string, accountSID *windows.SID) error {
	folderHandle := windows.Handle(directory.Fd())
	bootstrapHandle := windows.InvalidHandle
	defer func() {
		if bootstrapHandle != windows.InvalidHandle {
			_ = windows.CloseHandle(bootstrapHandle) //nolint:errcheck // nothing to flush on a read-only handle
		}
	}()
	for _, name := range []string{bootstrapFileName, sealedKeyFileName} {
		handle, err := openChild(folderHandle, name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
		if windowsMissingItem(err) {
			continue
		} else if err != nil {
			return err
		}
		if err := checkWindowsHandle(handle, filepath.Join(folder, name)); err != nil {
			_ = windows.CloseHandle(handle) //nolint:errcheck // nothing to flush on a read-only handle
			return err
		}
		if name == bootstrapFileName {
			bootstrapHandle = handle
		} else {
			_ = windows.CloseHandle(handle) //nolint:errcheck // nothing to flush on a read-only handle
		}
	}
	allowed, err := allowedForSID(accountSID)
	if err != nil {
		return err
	}
	findings, err := findLooserItems(directory, folder, mode, account, allowed)
	if err != nil {
		return err
	}
	if len(findings) > 0 {
		return looserRefusal(findings)
	}
	if bootstrapHandle != windows.InvalidHandle {
		err = reopenForWrite(bootstrapHandle, windows.FILE_WRITE_DATA|windows.DELETE)
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return &Refusal{Cause: NotWritable, Path: filepath.Join(folder, bootstrapFileName), Item: ItemFile}
		}
	}
	// ReOpenFile refuses a directory handle whatever its access list says, so the folder is
	// opened again as an empty name under itself.
	const shareAll = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE
	again, err := ntOpenChild(folderHandle, "", fileAddFile, shareAll, windows.FILE_OPEN, nil)
	if errors.Is(err, windows.STATUS_ACCESS_DENIED) {
		return &Refusal{Cause: NotWritable, Path: folder, Item: ItemFolder}
	} else if err == nil {
		_ = windows.CloseHandle(again) //nolint:errcheck // nothing to flush
	}
	return nil
}

// reopenForWrite asks the judged handle for a handle to the same item with the access given and
// closes it at once: the check is made on the handle that was judged, never on a name. A rewrite
// renames a new file over the bootstrap file, so the access asked for is write and delete.
func reopenForWrite(handle windows.Handle, access uint32) error {
	const shareAll = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE
	reopened, _, err := reOpenFile.Call(uintptr(handle), uintptr(access), shareAll, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if windows.Handle(reopened) == windows.InvalidHandle {
		return err
	}
	return windows.CloseHandle(windows.Handle(reopened))
}
