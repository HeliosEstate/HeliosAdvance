// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package bootstrap

import (
	"bytes"
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
// policy, and with or without the storage root key pinned. The identifier decides Holding;
// systemd decides whether a credential of a known form decrypts.
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

// hostKeyCredentialIDs are systemd's identifiers for the two forms sealed under the host key alone,
// system and scoped to an account. An identifier in neither list, systemd's null form included
// (sealed under no key at all), is refused before systemd is asked to decrypt.
var hostKeyCredentialIDs = [][16]byte{
	{0x5a, 0x1c, 0x6a, 0x86, 0xdf, 0x9d, 0x40, 0x96, 0xb1, 0xd5, 0xa6, 0x5e, 0x08, 0x62, 0xf1, 0x9a},
	{0x55, 0xb9, 0xed, 0x1d, 0x38, 0x59, 0x4d, 0x43, 0xa8, 0x31, 0x9d, 0x2e, 0xbb, 0x33, 0x2a, 0xc6},
}

func unlockSetupOnPlatform(ctx context.Context, folder string, mode KeyMode, account string) (SetupHandle, error) {
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
	if err := checkSetupMode(ctx, mode); err != nil {
		return nil, err
	}
	accountID, err := lookupAccount(account)
	if err != nil {
		return nil, err
	}
	// The lock's rule is for the account given, whoever owns the folder: UnlockForSetup does not
	// refuse a folder set looser than its rule, so the folder cannot say whose it is.
	lock, err := openLinuxLock(int(directory.Fd()), filepath.Join(folder, lockFileName), accountID, false)
	if err != nil {
		return nil, err
	}
	locked := false
	defer func() {
		if !locked {
			releaseSetupLock(lock)
		}
	}()
	opened, holding, err := unlockLinuxFile(ctx, directory, folder, mode, accountID, false, nil)
	if err != nil {
		return nil, err
	}
	locked = true
	return &setupHandle{file: opened, lock: lock, holding: holding}, nil
}

// unlockLinuxFile deletes the half-made file, reads the bootstrap key from where the mode holds it
// and opens the bootstrap file under it, all through the folder's handle. The service's checks
// open every item once and hand the descriptors over in judged, by path; each is read through the
// descriptor that was judged, and an item missing from judged is absent. Without judged, as for
// UnlockForSetup, each item is opened here. The service's ModeSystemdAtStart reads the key from
// the credential folder systemd gives the service.
func unlockLinuxFile(ctx context.Context, directory *os.File, folder string, mode KeyMode, accountID uint32, service bool, judged map[string]*os.File) (*bootstrapFile, Holding, error) {
	if err := unix.Unlinkat(int(directory.Fd()), bootstrapFileName+".new", 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return nil, 0, fmt.Errorf("bootstrap: deleting the half-made bootstrap file: %w", err)
	}
	var input *os.File
	var err error
	if judged != nil {
		held := judged[filepath.Join(folder, bootstrapFileName)]
		if held == nil {
			return nil, 0, &Refusal{Cause: FileNotFound}
		}
		input, err = reopenDescriptor(held, unix.O_RDONLY)
	} else {
		input, err = openLinuxBootstrapFile(int(directory.Fd()), filepath.Join(folder, bootstrapFileName))
	}
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = input.Close() }() //nolint:errcheck // read-only descriptor
	key, holding, err := readLinuxKey(ctx, directory, folder, mode, accountID, service, judged)
	defer clear(key)
	if err != nil {
		return nil, 0, err
	}
	if len(key) != 32 {
		return nil, 0, &Refusal{Cause: KeyNotUnsealed}
	}
	info, err := input.Stat()
	if err != nil {
		return nil, 0, err
	}
	opened, err := openFile(input, info.Size(), key)
	if err != nil {
		return nil, 0, err
	}
	return opened, holding, nil
}

// readLinuxKey is the bootstrap key and how it is held; the caller clears the key.
func readLinuxKey(ctx context.Context, directory *os.File, folder string, mode KeyMode, accountID uint32, service bool, judged map[string]*os.File) ([]byte, Holding, error) {
	switch mode {
	case ModeKeyFile:
		key, err := readBootstrapKey(int(directory.Fd()), keyFileName, filepath.Join(folder, keyFileName), judged)
		if errors.Is(err, unix.ENOENT) {
			err = &Refusal{Cause: KeyNotFound}
		}
		return key, HeldInKeyFile, err
	case ModeContainer:
		key, _, fromSecret, err := linuxBuildKey(directory, folder, FromContainer, judged)
		if fromSecret {
			return key, HeldAsSwarmSecret, err
		}
		return key, HeldInKeyFile, err
	case ModeSystemdAtStart, ModeSystemdPerUse:
	default:
		return nil, 0, &Refusal{Cause: SourceRefused}
	}
	credential, credentialID, err := openLinuxCredential(int(directory.Fd()), filepath.Join(folder, systemdCredentialFileName), judged)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, &Refusal{Cause: KeyNotFound}
	} else if err != nil {
		return nil, 0, err
	}
	// What was judged is what systemd decrypts: the service account owns the file and could
	// rewrite it between two reads.
	defer clear(credential)
	var holding Holding
	if slices.Contains(tpmCredentialIDs, credentialID) {
		holding = HeldInTPM
		// Only the missing libraries are refused here; any other failure of the probe is left
		// for systemd's own decrypt to decide.
		var refusal *Refusal
		if _, probeErr := linuxTPMDevice(ctx); ctx.Err() != nil {
			return nil, 0, ctx.Err()
		} else if errors.As(probeErr, &refusal) && refusal.Cause == TPMLibrariesMissing {
			return nil, 0, probeErr
		}
	} else if slices.Contains(hostKeyCredentialIDs, credentialID) {
		holding = HeldUnderHostKey
	} else {
		return nil, 0, &Refusal{Cause: KeyNotUnsealed}
	}
	if service && mode == ModeSystemdAtStart {
		key, err := readCredentialsDirectoryKey()
		return key, holding, err
	}
	args := []string{"decrypt", "--name=" + machineKeyPairName, "-", "-"}
	if mode == ModeSystemdPerUse {
		args = []string{"--user", fmt.Sprintf("--uid=%d", accountID), "decrypt", "--name=" + machineKeyPairName, "-", "-"}
	}
	command := exec.CommandContext(ctx, "systemd-creds", args...)
	command.Stdin = bytes.NewReader(credential)
	key, err := command.Output()
	if err != nil {
		clear(key)
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
		return nil, 0, &Refusal{Cause: KeyNotUnsealed}
	}
	return key, holding, nil
}

// readCredentialsDirectoryKey reads the key systemd decrypted into the service's credential
// folder, opened as every other key is. The key is 32 bytes, so a larger file is not one.
func readCredentialsDirectoryKey() ([]byte, error) {
	directory := os.Getenv("CREDENTIALS_DIRECTORY") //nolint:forbidigo // systemd gives a service its credential folder only through the environment
	if directory == "" {
		return nil, &Refusal{Cause: KeyNotFound}
	}
	path := filepath.Join(directory, machineKeyPairName)
	file, err := openKeySource(unix.AT_FDCWD, path, path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, &Refusal{Cause: KeyNotFound}
	} else if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()              //nolint:errcheck // read-only descriptor
	key, err := io.ReadAll(io.LimitReader(file, 33)) //nolint:forbidigo // bounded by the LimitReader
	if err != nil {
		clear(key)
		return nil, err
	}
	return key, nil
}

// openLinuxBootstrapFile opens the bootstrap file once, without following a link, and judges that
// descriptor; the reads that follow go through it.
func openLinuxBootstrapFile(directory int, path string) (*os.File, error) {
	file, stat, err := openUnlinked(directory, bootstrapFileName, path, unix.O_RDONLY, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, &Refusal{Cause: FileNotFound}
	} else if err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = file.Close() //nolint:errcheck // returning the refusal
		return nil, &Refusal{Cause: Link, Path: path}
	}
	return file, nil
}

// openLinuxCredential reads the credential through one descriptor and returns its bytes with the
// seal form's identifier; the caller clears the bytes. With judged set, the descriptor is the one
// held there under the path, an absent one being absent.
func openLinuxCredential(directory int, path string, judged map[string]*os.File) ([]byte, [16]byte, error) {
	var id [16]byte
	var file *os.File
	var stat unix.Stat_t
	var err error
	if judged == nil {
		file, stat, err = openUnlinked(directory, systemdCredentialFileName, path, unix.O_RDONLY, 0)
	} else if held := judged[path]; held != nil {
		if file, err = reopenDescriptor(held, unix.O_RDONLY); err == nil {
			err = unix.Fstat(int(file.Fd()), &stat)
		}
	} else {
		err = os.ErrNotExist
	}
	if err != nil {
		if file != nil {
			_ = file.Close() //nolint:errcheck // read-only descriptor
		}
		return nil, id, err
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // read-only descriptor
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, id, &Refusal{Cause: Link, Path: path}
	}
	if stat.Size > 1<<20 {
		return nil, id, &Refusal{Cause: KeyNotUnsealed}
	}
	data := make([]byte, stat.Size)
	if _, err := io.ReadFull(file, data); err != nil {
		clear(data)
		return nil, id, err
	}
	head := data
	if decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data))); decodeErr == nil {
		defer clear(decoded)
		head = decoded
	}
	if len(head) < len(id) {
		clear(data)
		return nil, id, &Refusal{Cause: KeyNotUnsealed}
	}
	copy(id[:], head[:len(id)])
	return data, id, nil
}

// checkSetupMode refuses a mode that is not this platform's. The running systemd's version is read
// only for the modes that turn on it.
func checkSetupMode(ctx context.Context, mode KeyMode) error {
	switch mode {
	case ModeKeyFile:
		return nil
	case ModeContainer:
		running, err := systemdRunning()
		if err != nil {
			return err
		}
		if running {
			return &Refusal{Cause: SourceRefused}
		}
		return nil
	case ModeSystemdAtStart, ModeSystemdPerUse:
		version, running, err := runningSystemdVersion(ctx)
		if err != nil {
			return err
		}
		minimum := 250
		if mode == ModeSystemdPerUse {
			minimum = 256
		}
		if !running || version < minimum {
			return &Refusal{Cause: SourceRefused}
		}
		return nil
	default:
		return &Refusal{Cause: SourceRefused}
	}
}
