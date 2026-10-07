//go:build linux

package bootstrap

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// tpmCredentialIDs are systemd's identifiers for every credential form that involves the TPM: under
// the TPM alone or with the host key, system or scoped to an account, with or without a signed
// policy, and with or without the storage root key pinned. The identifier only decides Holding;
// systemd decides whether the credential decrypts.
var tpmCredentialIDs = [][16]byte{
	{0x93, 0xa8, 0x94, 0x09, 0x48, 0x74, 0x44, 0x90, 0x90, 0xca, 0xf2, 0xfc, 0x93, 0xca, 0xb5, 0x53},
	{0xef, 0x4a, 0xc1, 0x36, 0x79, 0xa9, 0x48, 0x0e, 0xa7, 0xdb, 0x68, 0x89, 0x7f, 0x9f, 0x16, 0x5d},
	{0x0c, 0x7c, 0xc0, 0x7b, 0x11, 0x76, 0x45, 0x91, 0x9c, 0x4b, 0x0b, 0xea, 0x08, 0xbc, 0x20, 0xfe},
	{0xfa, 0xf7, 0xeb, 0x93, 0x41, 0xe3, 0x41, 0x2c, 0xa1, 0xa4, 0x36, 0xf9, 0x5a, 0x29, 0x36, 0x2f},
	{0xaf, 0x49, 0x50, 0xa8, 0x49, 0x13, 0x4e, 0xb1, 0xa7, 0x38, 0x46, 0x30, 0x4f, 0xf3, 0x0c, 0x05},
	{0xad, 0xbc, 0x4c, 0xa3, 0xef, 0xb6, 0x42, 0x01, 0xba, 0x88, 0x1b, 0x6f, 0x2e, 0x40, 0x95, 0xea},
	{0xd4, 0x06, 0x2d, 0xfb, 0x71, 0xad, 0x4c, 0x86, 0x80, 0x4b, 0x40, 0xef, 0x11, 0x80, 0xf1, 0xfc},
	{0x5e, 0x2d, 0x5c, 0x76, 0x03, 0x72, 0x4e, 0xaf, 0x84, 0x3c, 0x6f, 0xb5, 0xf6, 0x40, 0x98, 0xf5},
	{0x14, 0x14, 0x25, 0x88, 0x18, 0xa2, 0x40, 0xcd, 0x90, 0x0b, 0xce, 0x86, 0x2d, 0xb5, 0xc7, 0xb9},
	{0x2a, 0x1f, 0x87, 0x7a, 0x42, 0x75, 0x43, 0x1a, 0xb3, 0xf9, 0xed, 0x1f, 0x5d, 0x8f, 0x66, 0x01},
	{0xaf, 0xbf, 0xea, 0xac, 0xeb, 0x6a, 0x4a, 0x37, 0x95, 0x41, 0x9d, 0x13, 0x5c, 0x47, 0xf3, 0x7b},
	{0x16, 0xe4, 0x92, 0x94, 0x9f, 0x94, 0x40, 0x02, 0x86, 0x75, 0x8f, 0x94, 0xb7, 0xc5, 0x2b, 0xc7},
}

func unlockSetupOnPlatform(ctx context.Context, folder string, mode KeyMode) (SetupHandle, error) {
	if !isElevated() {
		return nil, &Refusal{Cause: NotElevated}
	}
	if mode == ModeContainer {
		folder = containerBootstrapFolder
	}
	directory, err := openFolder(folder)
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.Close() }() //nolint:errcheck // no pending writes
	version, hasSystemd, err := runningSystemdVersion(ctx)
	if err != nil {
		return nil, err
	}
	if !linuxSetupMode(mode, version, hasSystemd) {
		return nil, &Refusal{Cause: SourceRefused}
	}
	// The lock's rule is the folder's owner; one this root process just created is root's, so only a
	// lock made here is given over. One found there is for Check and SetToRule.
	lockFD, err := unix.Openat(int(directory.Fd()), "bootstrap.lock", unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		lockFD, err = unix.Openat(int(directory.Fd()), "bootstrap.lock", unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("bootstrap: opening the lock: %w", err)
	}
	lock := os.NewFile(uintptr(lockFD), "bootstrap.lock")
	if created {
		var folderStat unix.Stat_t
		if err := unix.Fstat(int(directory.Fd()), &folderStat); err != nil {
			_ = lock.Close() //nolint:errcheck // returning the stat error
			return nil, err
		}
		if err := unix.Fchown(lockFD, int(folderStat.Uid), -1); err != nil {
			_ = lock.Close() //nolint:errcheck // returning the chown error
			return nil, err
		}
	}
	locked := false
	defer func() {
		if !locked {
			_ = unix.Flock(lockFD, unix.LOCK_UN) //nolint:errcheck // closing releases the lock
			_ = lock.Close()                     //nolint:errcheck // no buffered data
		}
	}()
	if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return nil, &Refusal{Cause: InUse}
	} else if err != nil {
		return nil, err
	}
	_ = unix.Unlinkat(int(directory.Fd()), bootstrapFileName+".new", 0) //nolint:errcheck // stale partial rewrite is disposable
	var bootstrapStat unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), bootstrapFileName, &bootstrapStat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil, &Refusal{Cause: FileNotFound}
	} else if err != nil {
		return nil, err
	}
	if bootstrapStat.Mode&unix.S_IFMT != unix.S_IFREG || bootstrapStat.Nlink != 1 {
		return nil, &Refusal{Cause: Link, Path: filepath.Join(folder, bootstrapFileName)}
	}
	var key []byte
	holding := HeldInKeyFile
	switch mode {
	case ModeKeyFile:
		key, err = readBootstrapKey(int(directory.Fd()), keyFileName, filepath.Join(folder, keyFileName))
		if errors.Is(err, unix.ENOENT) {
			err = &Refusal{Cause: KeyNotFound}
		}
	case ModeContainer:
		key, _, err = linuxBuildKey(directory, folder, FromContainer)
		if len(key) > 0 {
			if _, statErr := os.Stat(swarmSecretPath); statErr == nil {
				holding = HeldAsSwarmSecret
			}
			if holding != HeldAsSwarmSecret {
				holding = HeldInKeyFile
			}
		}
	case ModeSystemdAtStart, ModeSystemdPerUse:
		credential := filepath.Join(folder, systemdCredentialFileName)
		credentialFile, credentialID, statErr := openLinuxCredential(int(directory.Fd()), credential)
		if errors.Is(statErr, os.ErrNotExist) {
			err = &Refusal{Cause: KeyNotFound}
			break
		} else if statErr != nil {
			err = statErr
			break
		}
		defer func() { _ = credentialFile.Close() }() //nolint:errcheck // read-only credential
		if slices.Contains(tpmCredentialIDs, credentialID) {
			holding = HeldInTPM
			if _, err = linuxTPMDevice(ctx); err != nil {
				break
			}
		} else {
			holding = HeldUnderHostKey
		}
		args := []string{"decrypt", "--name=" + machineKeyPairName, "-", "-"}
		if mode == ModeSystemdPerUse {
			var stat unix.Stat_t
			if err = unix.Fstat(int(directory.Fd()), &stat); err != nil {
				break
			}
			args = []string{"--user", fmt.Sprintf("--uid=%d", stat.Uid), "decrypt", "--name=" + machineKeyPairName, "-", "-"}
		}
		command := exec.CommandContext(ctx, "systemd-creds", args...)
		command.Stdin = credentialFile
		key, err = command.Output()
		if err != nil {
			clear(key)
			key = nil
			err = &Refusal{Cause: KeyNotUnsealed}
			break
		}
	}
	if err != nil {
		clear(key)
		return nil, err
	}
	defer clear(key)
	if len(key) != 32 {
		return nil, &Refusal{Cause: KeyNotUnsealed}
	}
	fileFD, err := unix.Openat(int(directory.Fd()), bootstrapFileName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, &Refusal{Cause: FileNotFound}
	}
	if errors.Is(err, unix.ELOOP) {
		return nil, &Refusal{Cause: Link, Path: filepath.Join(folder, bootstrapFileName)}
	}
	if err != nil {
		return nil, err
	}
	input := os.NewFile(uintptr(fileFD), bootstrapFileName)
	info, err := input.Stat()
	if err == nil {
		var stat unix.Stat_t
		statErr := unix.Fstat(fileFD, &stat)
		if statErr != nil {
			err = statErr
		} else if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
			err = &Refusal{Cause: Link, Path: filepath.Join(folder, bootstrapFileName)}
		}
	}
	if err != nil {
		_ = input.Close() //nolint:errcheck // returning the stat error
		return nil, err
	}
	opened, err := openFile(input, info.Size(), key)
	_ = input.Close() //nolint:errcheck // no buffered writes
	if err != nil {
		return nil, err
	}
	locked = true
	return &setupHandle{file: opened, lock: lock, holding: holding}, nil
}

func openLinuxCredential(directory int, path string) (*os.File, [16]byte, error) {
	var id [16]byte
	descriptor, err := unix.Openat(directory, systemdCredentialFileName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, id, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	var stat unix.Stat_t
	if err := unix.Fstat(descriptor, &stat); err != nil {
		_ = file.Close() //nolint:errcheck // returning the stat error
		return nil, id, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		_ = file.Close() //nolint:errcheck // returning the refusal
		return nil, id, &Refusal{Cause: Link, Path: path}
	}
	if stat.Size > 1<<20 {
		_ = file.Close() //nolint:errcheck // refusing an oversized credential
		return nil, id, &Refusal{Cause: KeyNotUnsealed}
	}
	data := make([]byte, stat.Size)
	_, err = io.ReadFull(file, data)
	if err != nil {
		clear(data)
		_ = file.Close() //nolint:errcheck // returning the read error
		return nil, id, err
	}
	decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if decodeErr == nil {
		clear(data)
		data = decoded
	}
	if len(data) < len(id) {
		clear(data)
		_ = file.Close() //nolint:errcheck // refusing a malformed credential
		return nil, id, &Refusal{Cause: KeyNotUnsealed}
	}
	copy(id[:], data[:len(id)])
	clear(data)
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close() //nolint:errcheck // returning the seek error
		return nil, id, err
	}
	return file, id, nil
}

func linuxSetupMode(mode KeyMode, version int, systemd bool) bool {
	switch mode {
	case ModeKeyFile:
		return true
	case ModeContainer:
		return !systemd
	case ModeSystemdAtStart:
		return systemd && version >= 250
	case ModeSystemdPerUse:
		return systemd && version >= 256
	default:
		return false
	}
}

func releaseSetupLock(lock *os.File) {
	if lock == nil {
		return
	}
	_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN) //nolint:errcheck // closing also releases the lock
	_ = lock.Close()                             //nolint:errcheck // no buffered data
}
