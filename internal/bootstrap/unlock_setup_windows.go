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

func unlockSetupOnPlatform(ctx context.Context, folder string, mode KeyMode) (SetupHandle, error) {
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
	lockPath := filepath.Join(folder, "bootstrap.lock")
	lockName, err := windows.UTF16PtrFromString(lockPath)
	if err != nil {
		return nil, err
	}
	lockHandle, err := windows.CreateFile(lockName, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return nil, &Refusal{Cause: InUse}
		}
		return nil, err
	}
	lock := os.NewFile(uintptr(lockHandle), lockPath)
	locked := false
	defer func() {
		if !locked {
			_ = lock.Close() //nolint:errcheck // closing releases the exclusive share
		}
	}()
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

type oaepPaddingInfo struct {
	Algorithm *uint16
	Label     *byte
	LabelSize uint32
}

func decryptWindowsKey(ctx context.Context, ciphertext []byte) ([]byte, Holding, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	for index, provider := range []struct {
		holding Holding
	}{{HeldInSoftwareKeyStore}, {HeldInTPM}} {
		providerName, err := windows.UTF16PtrFromString(keyProviders[index])
		if err != nil {
			return nil, 0, err
		}
		var providerHandle uintptr
		status, _, _ := procOpenProvider.Call(uintptr(unsafe.Pointer(&providerHandle)), uintptr(unsafe.Pointer(providerName)), 0) //nolint:errcheck,gosec // NCrypt returns status as its first result; these are API buffers
		if status != 0 {
			continue
		}
		keyName, err := windows.UTF16PtrFromString("heliosadvance-bootstrap-key")
		if err != nil {
			_, _, _ = procFreeObject.Call(providerHandle) //nolint:errcheck // release provider after failed conversion
			return nil, 0, err
		}
		var keyHandle uintptr
		status, _, _ = procOpenKey.Call(providerHandle, uintptr(unsafe.Pointer(&keyHandle)), uintptr(unsafe.Pointer(keyName)), 0, machineKeyFlag) //nolint:errcheck,gosec // NCrypt returns status as its first result; keyName is an API input
		if status != 0 {
			_, _, _ = procFreeObject.Call(providerHandle) //nolint:errcheck // cleanup after failed key open
			continue
		}
		algorithm, err := windows.UTF16PtrFromString("SHA256")
		if err != nil {
			_, _, _ = procFreeObject.Call(keyHandle)      //nolint:errcheck // release key after failed conversion
			_, _, _ = procFreeObject.Call(providerHandle) //nolint:errcheck // release provider after failed conversion
			return nil, 0, err
		}
		padding := oaepPaddingInfo{Algorithm: algorithm}
		var size uint32
		status, _, _ = ncryptDecrypt.Call(keyHandle, uintptr(unsafe.Pointer(&ciphertext[0])), uintptr(len(ciphertext)), uintptr(unsafe.Pointer(&padding)), 0, 0, uintptr(unsafe.Pointer(&size)), 4) //nolint:errcheck,gosec // NCrypt returns status as its first result; buffers follow its API contract
		if status == 0 && size == 32 {
			plain := make([]byte, size)
			status, _, _ = ncryptDecrypt.Call(keyHandle, uintptr(unsafe.Pointer(&ciphertext[0])), uintptr(len(ciphertext)), uintptr(unsafe.Pointer(&padding)), uintptr(unsafe.Pointer(&plain[0])), uintptr(len(plain)), uintptr(unsafe.Pointer(&size)), 4) //nolint:errcheck,gosec // NCrypt returns status as its first result; buffers follow its API contract
			_, _, _ = procFreeObject.Call(keyHandle)                                                                                                                                                                                                       //nolint:errcheck // cleanup after decrypt
			_, _, _ = procFreeObject.Call(providerHandle)                                                                                                                                                                                                  //nolint:errcheck // cleanup after decrypt
			if status == 0 {
				return plain, provider.holding, nil
			}
			clear(plain)
		} else {
			_, _, _ = procFreeObject.Call(keyHandle)      //nolint:errcheck // cleanup after failed decrypt
			_, _, _ = procFreeObject.Call(providerHandle) //nolint:errcheck // cleanup after failed decrypt
		}
	}
	return nil, 0, fmt.Errorf("NCrypt could not unseal the bootstrap key")
}

func releaseSetupLock(lock *os.File) {
	if lock != nil {
		_ = lock.Close() //nolint:errcheck // closing releases the exclusive share
	}
}
