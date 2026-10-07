// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func unlockSetupOnPlatform(ctx context.Context, folder string, mode KeyMode, account string) (SetupHandle, error) {
	if !isElevated() {
		return nil, &Refusal{Cause: NotElevated}
	}
	if mode != ModeMachineKeyPair {
		return nil, &Refusal{Cause: SourceRefused}
	}
	directory, err := openFolder(folder)
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.Close() }() //nolint:errcheck // no pending writes
	lockPath := filepath.Join(folder, lockFileName)
	lockHandle, err := openSetupLock(windows.Handle(directory.Fd()), account)
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
	if err := checkWindowsHandle(lockHandle, lockPath); err != nil {
		return nil, err
	}
	_ = os.Remove(filepath.Join(folder, bootstrapFileName+".new")) //nolint:errcheck // stale partial rewrite is disposable
	bootstrapHandle, err := openChild(windows.Handle(directory.Fd()), bootstrapFileName, windows.GENERIC_READ|windows.FILE_READ_ATTRIBUTES)
	if windowsMissingItem(err) {
		return nil, &Refusal{Cause: FileNotFound}
	} else if err != nil {
		return nil, err
	}
	bootstrapInput := os.NewFile(uintptr(bootstrapHandle), bootstrapFileName)
	defer func() { _ = bootstrapInput.Close() }() //nolint:errcheck // read-only handle
	if err := checkWindowsHandle(bootstrapHandle, filepath.Join(folder, bootstrapFileName)); err != nil {
		return nil, err
	}
	sealedHandle, err := openChild(windows.Handle(directory.Fd()), sealedKeyFileName, windows.GENERIC_READ|windows.FILE_READ_ATTRIBUTES)
	if windowsMissingItem(err) {
		return nil, &Refusal{Cause: KeyNotFound}
	} else if err != nil {
		return nil, err
	}
	sealedFile := os.NewFile(uintptr(sealedHandle), sealedKeyFileName)
	defer func() { _ = sealedFile.Close() }() //nolint:errcheck // read-only handle
	if err := checkWindowsHandle(sealedHandle, filepath.Join(folder, sealedKeyFileName)); err != nil {
		return nil, err
	}
	sealedInfo, err := sealedFile.Stat()
	if err != nil {
		return nil, err
	}
	if sealedInfo.Size() != 256 {
		return nil, &Refusal{Cause: KeyNotUnsealed}
	}
	sealed := make([]byte, 256)
	if _, err := sealedFile.ReadAt(sealed, 0); err != nil {
		clear(sealed)
		return nil, err
	}
	defer clear(sealed)
	key, holding, err := decryptWindowsKey(ctx, sealed)
	if err != nil || len(key) != 32 {
		clear(key)
		return nil, &Refusal{Cause: KeyNotUnsealed}
	}
	defer clear(key)
	info, err := bootstrapInput.Stat()
	var opened *bootstrapFile
	if err == nil {
		opened, err = openFile(bootstrapInput, info.Size(), key)
	}
	if err != nil {
		return nil, err
	}
	locked = true
	return &setupHandle{file: opened, lock: lock, holding: holding}, nil
}

// openSetupLock opens the lock exclusively without following a link, relative to the checked
// folder's handle. A lock that is absent is created already set to its rule for the account: the
// account, SYSTEM and Administrators only, not inherited, owned by Administrators. The create runs
// with SeRestorePrivilege so the owner can be given, and holds it for that call only.
func openSetupLock(folder windows.Handle, account string) (windows.Handle, error) {
	const access = windows.GENERIC_READ | windows.GENERIC_WRITE
	handle, err := ntOpenChild(folder, lockFileName, access, 0, windows.FILE_OPEN, nil)
	if !windowsMissingItem(err) {
		return handle, err
	}
	service, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return 0, fmt.Errorf("bootstrap: the account %s: %w", account, err)
	}
	rule, err := windows.SecurityDescriptorFromString(ruleSDDL(service, "", fileAllAccess))
	if err != nil {
		return 0, err
	}
	restorePrivileges := enablePrivileges("SeRestorePrivilege")
	defer restorePrivileges()
	return ntOpenChild(folder, lockFileName, access, 0, windows.FILE_CREATE, rule)
}

func windowsMissingItem(err error) bool {
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) ||
		errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) || errors.Is(err, windows.STATUS_OBJECT_PATH_NOT_FOUND)
}

func checkWindowsHandle(handle windows.Handle, path string) error {
	link, err := isLink(handle)
	if err != nil {
		return err
	}
	info, err := informationOf(handle)
	if err != nil {
		return err
	}
	if link || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || info.NumberOfLinks != 1 {
		return &Refusal{Cause: Link, Path: path}
	}
	return nil
}

var ncryptDecrypt = ncrypt.NewProc("NCryptDecrypt")

// maxDecryptedSize bounds the buffer the size query may ask for; the largest answer is a key's length, 256 for RSA-2048.
const maxDecryptedSize = 512

type oaepPaddingInfo struct {
	Algorithm *uint16
	Label     *byte
	LabelSize uint32
}

func decryptWindowsKey(ctx context.Context, ciphertext []byte) ([]byte, Holding, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	pair, found, err := openKeyPair()
	if err != nil {
		return nil, 0, err
	}
	if !found {
		return nil, 0, fmt.Errorf("NCrypt could not unseal the bootstrap key")
	}
	defer pair.close()
	holding := HeldInSoftwareKeyStore
	if pair.inTPM {
		holding = HeldInTPM
	}
	algorithm, err := windows.UTF16PtrFromString("SHA256")
	if err != nil {
		return nil, 0, err
	}
	padding := oaepPaddingInfo{Algorithm: algorithm}
	var size uint32
	if status := call(ncryptDecrypt, pair.key, uintptr(unsafe.Pointer(&ciphertext[0])), uintptr(len(ciphertext)), uintptr(unsafe.Pointer(&padding)), 0, 0, uintptr(unsafe.Pointer(&size)), 4); status != 0 || size == 0 || size > maxDecryptedSize { //nolint:gosec // the key store's calling convention
		return nil, 0, fmt.Errorf("NCrypt could not unseal the bootstrap key")
	}
	// A key held in the TPM reports the key's length here, not the plaintext's; only the second
	// call's length says how much of the buffer is the key.
	plain := make([]byte, size)
	defer clear(plain)
	if status := call(ncryptDecrypt, pair.key, uintptr(unsafe.Pointer(&ciphertext[0])), uintptr(len(ciphertext)), uintptr(unsafe.Pointer(&padding)), uintptr(unsafe.Pointer(&plain[0])), uintptr(len(plain)), uintptr(unsafe.Pointer(&size)), 4); status != 0 || size != 32 { //nolint:gosec // the key store's calling convention
		return nil, 0, fmt.Errorf("NCrypt could not unseal the bootstrap key")
	}
	return append([]byte(nil), plain[:size]...), holding, nil
}

func releaseSetupLock(lock *os.File) {
	if lock != nil {
		_ = lock.Close() //nolint:errcheck // closing releases the exclusive share
	}
}
