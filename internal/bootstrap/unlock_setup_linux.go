//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/unix"
)

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
	lockFD, err := unix.Openat(int(directory.Fd()), "bootstrap.lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: opening the lock: %w", err)
	}
	lock := os.NewFile(uintptr(lockFD), "bootstrap.lock")
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
		var credentialHeader [16]byte
		credentialID, statErr := linuxCredentialID(int(directory.Fd()), credential, &credentialHeader)
		if errors.Is(statErr, os.ErrNotExist) {
			err = &Refusal{Cause: KeyNotFound}
			break
		} else if statErr != nil {
			err = statErr
			break
		}
		if credentialID == [16]byte{0x93, 0xa8, 0x94, 0x09, 0x48, 0x74, 0x44, 0x90, 0x90, 0xca, 0xf2, 0xfc, 0x93, 0xca, 0xb5, 0x53} {
			holding = HeldInTPM
		} else {
			holding = HeldUnderHostKey
		}
		if _, err = linuxTPMDevice(ctx); err != nil {
			break
		}
		args := []string{"decrypt", "--name=" + machineKeyPairName, credential, "-"}
		if mode == ModeSystemdPerUse {
			var stat unix.Stat_t
			if err = unix.Fstat(int(directory.Fd()), &stat); err != nil {
				break
			}
			args = []string{"--user", fmt.Sprintf("--uid=%d", stat.Uid), "decrypt", "--name=" + machineKeyPairName, credential, "-"}
		}
		command := exec.CommandContext(ctx, "systemd-creds", args...) //nolint:gosec // fixed binary and operation; variable UID is derived from folder owner
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

func linuxCredentialID(directory int, path string, header *[16]byte) ([16]byte, error) {
	var id [16]byte
	descriptor, err := unix.Openat(directory, systemdCredentialFileName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil { return id, err }
	file := os.NewFile(uintptr(descriptor), path)
	defer func() { _ = file.Close() }() //nolint:errcheck // read-only credential
	var stat unix.Stat_t
	if err := unix.Fstat(descriptor, &stat); err != nil { return id, err }
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 { return id, &Refusal{Cause: Link, Path: path} }
	if _, err := io.ReadFull(file, header[:]); err != nil { return id, err }
	copy(id[:], header[:])
	return id, nil
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
