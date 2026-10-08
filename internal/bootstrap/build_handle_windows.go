// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// createChild creates a file inside the folder exclusively, relative to the folder's handle and
// already set to its rule for the service account, so no later call needs the file's path. A name
// that is taken by a link or by a file with more than one name is refused as Link. The handle
// can write, read and delete.
func createChild(folder windows.Handle, folderPath, name string, service *windows.SID) (*os.File, error) {
	path := filepath.Join(folderPath, name)
	rule, err := windows.SecurityDescriptorFromString(ruleSDDL(service, "", fileAllAccess))
	if err != nil {
		return nil, err
	}
	restore := enablePrivileges("SeRestorePrivilege")
	handle, err := ntOpenChild(folder, name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE, 0, windows.FILE_CREATE, rule)
	restore()
	if err == nil {
		return os.NewFile(uintptr(handle), path), nil
	}
	if windowsNameTaken(err) {
		existing, openErr := openChild(folder, name, windows.FILE_READ_ATTRIBUTES)
		if openErr == nil {
			defer windows.CloseHandle(existing) //nolint:errcheck // nothing to flush on a read-only handle
			if linkErr := checkWindowsHandle(existing, path); linkErr != nil {
				return nil, linkErr
			}
		}
	}
	return nil, fmt.Errorf("bootstrap: creating %s: %w", path, err)
}

func windowsNameTaken(err error) bool {
	return errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) || errors.Is(err, windows.ERROR_FILE_EXISTS)
}

// renameOver renames the open file to a name in the folder, replacing a file of that name, with
// the folder's handle as the root of the new name. The file's handle must have been opened with
// DELETE. This is the native call: SetFileInformationByHandle refuses a root folder handle.
func renameOver(file *os.File, folder windows.Handle, name string) error {
	units, err := windows.UTF16FromString(name)
	if err != nil {
		return err
	}
	units = units[:len(units)-1]
	// FILE_RENAME_INFORMATION: a flags word padded to a pointer, the root handle, the name's length
	// in bytes, then the name. The buffer is 8-byte words so the handle is aligned.
	const header = 20
	words := make([]uint64, (header+2*len(units)+7)/8)
	buffer := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(words)*8) //nolint:gosec // the call reads a packed struct
	buffer[0] = 1                                                            // ReplaceIfExists
	*(*uintptr)(unsafe.Pointer(&buffer[8])) = uintptr(folder)                //nolint:gosec // RootDirectory
	*(*uint32)(unsafe.Pointer(&buffer[16])) = uint32(2 * len(units))         //nolint:gosec // FileNameLength
	for index, unit := range units {
		*(*uint16)(unsafe.Pointer(&buffer[header+2*index])) = unit //nolint:gosec // FileName
	}
	var status windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(windows.Handle(file.Fd()), &status, &buffer[0], uint32(len(buffer)), windows.FileRenameInformation) //nolint:gosec // a file name is at most 32767 units
}
