//go:build windows

package bootstrap

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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
		return nil, &Refusal{Cause: InUse}
	}
	lock := os.NewFile(uintptr(lockHandle), lockPath)
	locked := false
	defer func() {
		if !locked {
			_ = lock.Close() //nolint:errcheck // closing releases the exclusive share
		}
	}()
	_ = os.Remove(filepath.Join(folder, bootstrapFileName+".new")) //nolint:errcheck // stale partial rewrite is disposable
	if err := checkWindowsItem(filepath.Join(folder, bootstrapFileName)); errors.Is(err, os.ErrNotExist) {
		return nil, &Refusal{Cause: FileNotFound}
	} else if err != nil {
		return nil, err
	}
	sealedPath := filepath.Join(folder, sealedKeyFileName)
	if err := checkWindowsItem(sealedPath); errors.Is(err, os.ErrNotExist) {
		return nil, &Refusal{Cause: KeyNotFound}
	} else if err != nil {
		return nil, err
	}
	//nolint:gosec // sealedPath is inside the absolute folder checked by openFolder.
	sealed, err := os.ReadFile(sealedPath)
	if err != nil {
		return nil, err
	}
	if len(sealed) != 256 {
		return nil, &Refusal{Cause: KeyNotUnsealed}
	}
	defer clear(sealed)
	const script = `$ErrorActionPreference='Stop'; $name='heliosadvance-bootstrap-key'; foreach($providerName in @('Microsoft Software Key Storage Provider','Microsoft Platform Crypto Provider')) { try { $provider=New-Object Security.Cryptography.CngProvider $providerName; $key=[Security.Cryptography.CngKey]::Open($name,$provider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey); $rsa=New-Object Security.Cryptography.RSACng $key; $plain=$rsa.Decrypt([IO.File]::ReadAllBytes($env:HELIOS_SEALED_PATH),[Security.Cryptography.RSAEncryptionPadding]::OaepSHA256); $holding=if($providerName -eq 'Microsoft Platform Crypto Provider'){'TPM'}else{'SOFTWARE'}; [Console]::Out.WriteLine('HELIOS_KEY='+[Convert]::ToBase64String($plain)); [Console]::Out.WriteLine('HELIOS_HOLDING='+$holding); exit 0 } catch {} }; exit 1`
	command := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	command.Env = append(os.Environ(), "HELIOS_SEALED_PATH="+sealedPath)
	output, err := command.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &Refusal{Cause: KeyNotUnsealed}
	}
	var key []byte
	holding := HeldInSoftwareKeyStore
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if value, ok := strings.CutPrefix(line, "HELIOS_KEY="); ok {
			key, err = base64.StdEncoding.DecodeString(value)
		}
		if strings.TrimSpace(line) == "HELIOS_HOLDING=TPM" {
			holding = HeldInTPM
		}
	}
	if err != nil || len(key) != 32 {
		clear(key)
		return nil, &Refusal{Cause: KeyNotUnsealed}
	}
	defer clear(key)
	//nolint:gosec // folder was opened and the file itself passed the no-link check.
	file, err := os.Open(filepath.Join(folder, bootstrapFileName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, &Refusal{Cause: FileNotFound}
		}
		return nil, err
	}
	info, err := file.Stat()
	var opened *bootstrapFile
	if err == nil {
		opened, err = openFile(file, info.Size(), key)
	}
	_ = file.Close() //nolint:errcheck // read has completed
	if err != nil {
		return nil, err
	}
	locked = true
	return &setupHandle{file: opened, key: append([]byte(nil), key...), lock: lock, holding: holding}, nil
}

func checkWindowsItem(path string) error {
	handle, err := openItem(path, windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle) //nolint:errcheck // no pending I/O
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

func releaseSetupLock(lock *os.File) {
	if lock != nil {
		_ = lock.Close() //nolint:errcheck // closing releases the exclusive share
	}
}
