// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const systemdCredentialFileName = "bootstrap-key.cred" //nolint:gosec // fixed credential filename, not secret data

func buildOnPlatform(ctx context.Context, folder string, fields Fields, path BuildPath, account string, source KeySource) (KeyMode, error) {
	if !isElevated() {
		return 0, &Refusal{Cause: NotElevated}
	}
	if source != FromKeyFile && source != FromContainer && source != FromOSStore {
		return 0, &Refusal{Cause: SourceRefused}
	}
	if source == FromContainer {
		folder = containerBootstrapFolder
	}
	directory, err := openFolder(folder)
	if err != nil {
		return 0, err
	}
	defer func() { _ = directory.Close() }() //nolint:errcheck // the lock and file syncs happen before this close
	if err := validateFields(fields); err != nil {
		return 0, err
	}
	version, hasSystemd, err := runningSystemdVersion(ctx)
	if err != nil {
		return 0, err
	}
	if (source == FromContainer && hasSystemd) || (source == FromKeyFile && version >= 250) {
		return 0, &Refusal{Cause: SourceRefused}
	}
	if source == FromOSStore && version < 250 {
		return 0, &Refusal{Cause: NoCredentialStore}
	}
	key, mode, err := linuxBuildKey(directory, folder, source)
	if source == FromOSStore {
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return 0, fmt.Errorf("bootstrap: making the bootstrap key: %w", err)
		}
		if version >= 256 {
			mode = ModeSystemdPerUse
		} else {
			mode = ModeSystemdAtStart
		}
	}
	if err != nil {
		return 0, err
	}
	defer clear(key)
	accountID, err := lookupAccount(account)
	if err != nil {
		return 0, err
	}
	if err := unix.Fchown(int(directory.Fd()), int(accountID), -1); err != nil {
		return 0, fmt.Errorf("bootstrap: setting the owner of %s: %w", folder, err)
	}
	if err := unix.Fchmod(int(directory.Fd()), 0o700); err != nil {
		return 0, fmt.Errorf("bootstrap: setting the mode of %s: %w", folder, err)
	}
	lock, err := openLinuxLock(int(directory.Fd()), accountID, true)
	if err != nil {
		return 0, err
	}
	defer releaseSetupLock(lock)
	var existing unix.Stat_t
	err = unix.Fstatat(int(directory.Fd()), bootstrapFileName, &existing, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil && (path == FirstSetup || path == Joining) {
		return 0, &Refusal{Cause: FileExists}
	}
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return 0, fmt.Errorf("bootstrap: checking the old bootstrap file: %w", err)
	}
	tpmDevice, err := linuxTPMDevice(ctx)
	if err != nil {
		return 0, err
	}
	credentialMade := false
	if source == FromOSStore {
		credentialMade = true
		defer func() {
			if credentialMade {
				_ = unix.Unlinkat(int(directory.Fd()), systemdCredentialFileName, 0) //nolint:errcheck // a failed build must not leave a credential
			}
		}()
		if err := sealSystemdCredential(ctx, folder, accountID, version >= 256, tpmDevice, key); err != nil {
			return 0, err
		}
	}
	file := &bootstrapFile{}
	file.setFields(fields)
	name := bootstrapFileName + ".new"
	descriptor, err := unix.Openat(int(directory.Fd()), name, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return 0, fmt.Errorf("bootstrap: creating the new bootstrap file: %w", err)
	}
	removeNew := true
	defer func() {
		if removeNew {
			_ = unix.Unlinkat(int(directory.Fd()), name, 0) //nolint:errcheck // a failed build must not leave a partial file
		}
	}()
	if err := unix.Fchown(descriptor, int(accountID), -1); err != nil {
		_ = unix.Close(descriptor) //nolint:errcheck // returning the earlier owner-setting error
		return 0, fmt.Errorf("bootstrap: setting the bootstrap file owner: %w", err)
	}
	if err := unix.Fchmod(descriptor, 0o600); err != nil {
		_ = unix.Close(descriptor) //nolint:errcheck // returning the earlier mode-setting error
		return 0, fmt.Errorf("bootstrap: setting the bootstrap file mode: %w", err)
	}
	output := os.NewFile(uintptr(descriptor), name)
	if err := file.writeTo(output, key); err != nil {
		_ = output.Close() //nolint:errcheck // returning the earlier write error
		return 0, &Refusal{Cause: RewriteFailed}
	}
	if err := output.Sync(); err != nil {
		_ = output.Close() //nolint:errcheck // returning the earlier flush error
		return 0, &Refusal{Cause: RewriteFailed}
	}
	info, err := output.Stat()
	if err != nil {
		_ = output.Close() //nolint:errcheck // returning the earlier stat or seek error
		return 0, &Refusal{Cause: RewriteFailed}
	}
	if _, err := output.Seek(0, 0); err != nil {
		_ = output.Close() //nolint:errcheck // returning the earlier seek error
		return 0, &Refusal{Cause: RewriteFailed}
	}
	readback, err := openFile(output, info.Size(), key)
	_ = output.Close() //nolint:errcheck // the read-back completed, and no writes are buffered
	if err != nil || readback == nil {
		return 0, &Refusal{Cause: RewriteFailed}
	}
	if err := unix.Renameat(int(directory.Fd()), name, int(directory.Fd()), bootstrapFileName); err != nil {
		return 0, &Refusal{Cause: RewriteFailed}
	}
	removeNew = false
	if err := directory.Sync(); err != nil {
		return 0, &Refusal{Cause: RewriteFailed}
	}
	credentialMade = false
	return mode, nil
}

func linuxTPMDevice(ctx context.Context) (string, error) {
	for _, device := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
		if _, err := os.Stat(device); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return "", fmt.Errorf("bootstrap: checking %s: %w", device, err)
		}
		command := exec.CommandContext(ctx, "systemd-creds", "--tpm2-device="+device, "--quiet", "has-tpm2") //nolint:gosec // device is selected from fixed /dev paths
		if err := command.Run(); err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			var exitError *exec.ExitError
			if errors.As(err, &exitError) && exitError.ExitCode()&4 != 0 {
				return "", &Refusal{Cause: TPMLibrariesMissing}
			}
			return "", fmt.Errorf("bootstrap: checking TPM support: %w", err)
		}
		return device, nil
	}
	return "", nil
}

func sealSystemdCredential(ctx context.Context, folder string, accountID uint32, perUse bool, tpmDevice string, key []byte) error {
	sealedPath := filepath.Join(folder, systemdCredentialFileName+".new")
	sealed, err := os.OpenFile(sealedPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // folder is the checked bootstrap directory
	if err != nil {
		return err
	}
	if err := sealed.Chown(int(accountID), -1); err != nil {
		_ = sealed.Close()        //nolint:errcheck // return the chown error
		_ = os.Remove(sealedPath) //nolint:errcheck // remove the incomplete credential
		return err
	}
	if err := sealed.Chmod(0o600); err != nil {
		_ = sealed.Close()        //nolint:errcheck // return the chmod error
		_ = os.Remove(sealedPath) //nolint:errcheck // remove the incomplete credential
		return err
	}
	args := []string{"encrypt", "--name=" + machineKeyPairName}
	if tpmDevice != "" {
		args = append(args, "--with-key=host+tpm2", "--tpm2-device="+tpmDevice, "--tpm2-pcrs=")
	} else {
		args = append(args, "--with-key=host")
	}
	args = append(args, "-", "-")
	if perUse {
		args = append([]string{"--user", "--uid=" + strconv.FormatUint(uint64(accountID), 10)}, args...)
	}
	command := exec.CommandContext(ctx, "systemd-creds", args...)
	command.Stdin = bytes.NewReader(key)
	command.Stdout = sealed
	var output strings.Builder
	command.Stderr = &output
	if err := command.Run(); err != nil {
		_ = sealed.Close()        //nolint:errcheck // remove the incomplete credential
		_ = os.Remove(sealedPath) //nolint:errcheck // remove the incomplete credential
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("bootstrap: sealing the credential: %w: %s", err, strings.TrimSpace(output.String()))
	}
	if err := sealed.Sync(); err != nil {
		_ = sealed.Close()        //nolint:errcheck // return the sync error
		_ = os.Remove(sealedPath) //nolint:errcheck // remove the incomplete credential
		return err
	}
	if err := sealed.Close(); err != nil {
		_ = os.Remove(sealedPath) //nolint:errcheck // remove the incomplete credential
		return err
	}
	if err := os.Rename(sealedPath, filepath.Join(folder, systemdCredentialFileName)); err != nil {
		_ = os.Remove(sealedPath) //nolint:errcheck // remove the incomplete credential
		return err
	}
	return nil
}

func runningSystemdVersion(ctx context.Context) (int, bool, error) {
	if running, err := systemdRunning(); !running || err != nil {
		return 0, false, err
	}
	output, err := exec.CommandContext(ctx, "systemctl", "show", "--property=Version", "--value").Output()
	if err != nil {
		if ctx.Err() != nil {
			return 0, false, ctx.Err()
		}
		return 0, false, fmt.Errorf("bootstrap: reading the running systemd version: %w", err)
	}
	text := strings.TrimSpace(string(output))
	major, _, _ := strings.Cut(text, ".")
	version, err := strconv.Atoi(major)
	if err != nil {
		return 0, true, fmt.Errorf("bootstrap: parsing the running systemd version: %w", err)
	}
	return version, true, nil
}

func linuxBuildKey(directory *os.File, folder string, source KeySource) ([]byte, KeyMode, error) {
	if source == FromOSStore {
		return nil, 0, nil
	}
	if source == FromKeyFile {
		key, err := readBootstrapKey(int(directory.Fd()), keyFileName, filepath.Join(folder, keyFileName))
		if errors.Is(err, unix.ENOENT) {
			return nil, 0, &Refusal{Cause: KeyNotFound}
		}
		return key, ModeKeyFile, err
	}
	keyFile, keyFileErr := readBootstrapKey(int(directory.Fd()), keyFileName, filepath.Join(folder, keyFileName))
	if keyFileErr != nil && !errors.Is(keyFileErr, unix.ENOENT) {
		return nil, 0, keyFileErr
	}
	secret, secretErr := readBootstrapKey(unix.AT_FDCWD, swarmSecretPath, swarmSecretPath)
	if secretErr != nil && !errors.Is(secretErr, unix.ENOENT) {
		clear(keyFile)
		return nil, 0, secretErr
	}
	if keyFileErr == nil && secretErr == nil {
		clear(keyFile)
		clear(secret)
		return nil, 0, &Refusal{Cause: BothKeySources}
	}
	if keyFileErr != nil && secretErr != nil {
		return nil, 0, &Refusal{Cause: NoKeySource}
	}
	if secretErr == nil {
		return secret, ModeContainer, nil
	}
	return keyFile, ModeContainer, nil
}

func readBootstrapKey(directory int, name, path string) ([]byte, error) {
	var descriptor int
	var err error
	if directory == unix.AT_FDCWD {
		descriptor, err = unix.Open(name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	} else {
		descriptor, err = unix.Openat(directory, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	}
	if errors.Is(err, unix.ELOOP) {
		return nil, &Refusal{Cause: Link, Path: path}
	}
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(descriptor, &stat); err != nil {
		_ = unix.Close(descriptor) //nolint:errcheck // returning the earlier stat error
		return nil, fmt.Errorf("bootstrap: reading %s: %w", path, err)
	}
	if stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Nlink != 1 {
		_ = unix.Close(descriptor) //nolint:errcheck // refusing the multiply named key
		return nil, &Refusal{Cause: Link, Path: path}
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(descriptor) //nolint:errcheck // refusing a non-file key source
		return nil, fmt.Errorf("bootstrap: %s is not a regular file", path)
	}
	file := os.NewFile(uintptr(descriptor), path)
	key, readErr := readKeyFile(file)
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	return key, closeErr
}

// openLinuxLock opens bootstrap.lock in the folder and takes it exclusively, refusing with InUse
// when another handle holds it. A lock this call creates is given to the owner at 0600 and removed
// again if that fails; one already there is left as found unless reset is set, as Build does.
func openLinuxLock(directory int, owner uint32, reset bool) (*os.File, error) {
	const flags = unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC
	descriptor, err := unix.Openat(directory, lockFileName, flags|unix.O_CREAT|unix.O_EXCL, 0o600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		descriptor, err = unix.Openat(directory, lockFileName, flags, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("bootstrap: opening the lock: %w", err)
	}
	lock := os.NewFile(uintptr(descriptor), lockFileName)
	fail := func(err error) (*os.File, error) {
		if created {
			_ = unix.Unlinkat(directory, lockFileName, 0) //nolint:errcheck // a lock that could not be given over must not stay root's
		}
		_ = lock.Close() //nolint:errcheck // no buffered data
		return nil, err
	}
	if created || reset {
		if err := unix.Fchown(descriptor, int(owner), -1); err != nil {
			return fail(fmt.Errorf("bootstrap: setting the lock owner: %w", err))
		}
		if err := unix.Fchmod(descriptor, 0o600); err != nil {
			return fail(fmt.Errorf("bootstrap: setting the lock mode: %w", err))
		}
	}
	if err := unix.Flock(descriptor, unix.LOCK_EX|unix.LOCK_NB); errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		_ = lock.Close() //nolint:errcheck // no buffered data
		return nil, &Refusal{Cause: InUse}
	} else if err != nil {
		return fail(fmt.Errorf("bootstrap: locking the folder: %w", err))
	}
	return lock, nil
}

func releaseSetupLock(lock *os.File) {
	if lock == nil {
		return
	}
	_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN) //nolint:errcheck // closing also releases the lock
	_ = lock.Close()                             //nolint:errcheck // no buffered data
}

// systemdRunning is whether systemd is the running service manager.
func systemdRunning() (bool, error) {
	if _, err := os.Stat("/run/systemd/system"); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("bootstrap: checking the running service manager: %w", err)
	}
	return true, nil
}
