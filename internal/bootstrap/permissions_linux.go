// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// The container's fixed places, as the package comment gives them.
const (
	containerBootstrapFolder = "/var/lib/heliosadvance"
	swarmSecretPath          = "/run/secrets/heliosadvance-bootstrap-key"
)

// File systems as statfs reports them: the magic numbers of the kernel's statfs(2).
const (
	magicExtended = 0xEF53 // ext2, ext3 and ext4 share one
	magicXFS      = 0x58465342
	magicBtrfs    = 0x9123683E
	magicZFS      = 0x2FC12FC1
	magicNFS      = 0x6969
	magicSMB      = 0x517B
	magicCIFS     = 0xFF534D42
	magicSMB2     = 0xFE534D42
	magicCeph     = 0x00C36400
	magicAFS      = 0x5346414F
)

func isElevated() bool { return os.Geteuid() == 0 }

// modeOfRule is the permission bits an item's rule gives, on Linux and in a container.
func modeOfRule(item Item) fs.FileMode {
	switch item {
	case ItemFolder:
		return 0o700
	case ItemKeyFile, ItemSwarmSecret:
		return 0o400
	}
	return 0o600
}

func checkPermissions(folder string, mode KeyMode, account string) ([]Finding, error) {
	if !isElevated() {
		return nil, &Refusal{Cause: NotElevated}
	}
	if mode == ModeContainer {
		folder = containerBootstrapFolder
	}
	accountID, err := lookupAccount(account)
	if err != nil {
		return nil, err
	}
	directory, err := openFolder(folder)
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.Close() }() //nolint:errcheck // nothing to flush on a read-only handle

	names, err := readNames(directory)
	if err != nil {
		return nil, err
	}
	items := map[string]Item{folder: ItemFolder}
	for _, name := range names {
		items[filepath.Join(folder, name)] = itemOf(name)
	}
	if mode == ModeContainer {
		items[swarmSecretPath] = ItemSwarmSecret
	}

	findings := []Finding{}
	for path, item := range items {
		stat, err := statItem(directory, path, item)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("bootstrap: reading %s: %w", path, err)
		}
		// A link or a directory where a file should be is looser than the rule, whatever its mode.
		displaced := item != ItemFolder && stat.Mode&unix.S_IFMT != unix.S_IFREG
		found := Permissions{Owner: ownerName(stat.Uid), Mode: fs.FileMode(stat.Mode & 0o777)}
		rule := Permissions{Owner: account, Mode: modeOfRule(item)}
		if displaced || stat.Uid != accountID || found.Mode&^rule.Mode != 0 {
			findings = append(findings, Finding{Item: item, Path: path, Found: found, Rule: rule})
		}
	}
	return findings, nil
}

// statItem reads an item's owner and mode: the folder from its handle, what is in it
// relative to that handle, and the Swarm secret, which is mounted outside, from a handle of its own.
func statItem(directory *os.File, path string, item Item) (unix.Stat_t, error) {
	var stat unix.Stat_t
	var err error
	switch item {
	case ItemFolder:
		err = unix.Fstat(int(directory.Fd()), &stat)
	case ItemSwarmSecret:
		var descriptor int
		if descriptor, err = unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0); err == nil {
			err = unix.Fstat(descriptor, &stat)
			_ = unix.Close(descriptor) //nolint:errcheck // nothing to flush on a read-only handle
		}
	default:
		err = unix.Fstatat(int(directory.Fd()), filepath.Base(path), &stat, unix.AT_SYMLINK_NOFOLLOW)
	}
	return stat, err
}

// openFolder opens the bootstrap folder and judges the folder rules on the handle.
func openFolder(folder string) (*os.File, error) {
	if !filepath.IsAbs(folder) {
		return nil, &Refusal{Cause: FolderRefused, Path: folder, Rule: NotAbsolute}
	}
	descriptor, err := unix.Open(folder, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ELOOP) {
		return nil, &Refusal{Cause: FolderRefused, Path: folder, Rule: FolderLink}
	}
	if err != nil {
		return nil, fmt.Errorf("bootstrap: opening %s: %w", folder, err)
	}
	directory := os.NewFile(uintptr(descriptor), folder)
	var system unix.Statfs_t
	var stat unix.Stat_t
	if err := unix.Fstatfs(descriptor, &system); err != nil {
		_ = directory.Close() //nolint:errcheck // nothing to flush on a read-only handle
		return nil, fmt.Errorf("bootstrap: reading the file system of %s: %w", folder, err)
	}
	if err := unix.Fstat(descriptor, &stat); err != nil {
		_ = directory.Close() //nolint:errcheck // nothing to flush on a read-only handle
		return nil, fmt.Errorf("bootstrap: reading %s: %w", folder, err)
	}
	if rule := folderRuleBroken(uint32(system.Type), uint64(stat.Dev)); rule != 0 { //nolint:gosec // the magic numbers fit 32 bits
		_ = directory.Close() //nolint:errcheck // nothing to flush on a read-only handle
		return nil, &Refusal{Cause: FolderRefused, Path: folder, Rule: rule}
	}
	return directory, nil
}

// folderRuleBroken is the folder rule the file system type or the device breaks, or zero.
func folderRuleBroken(filesystem uint32, device uint64) FolderRule {
	switch filesystem {
	case magicNFS, magicSMB, magicCIFS, magicSMB2, magicCeph, magicAFS:
		return NetworkShare
	case magicExtended, magicXFS, magicBtrfs, magicZFS:
	default:
		return FileSystem
	}
	if isRemovable(device) {
		return Removable
	}
	return 0
}

// isRemovable is what the kernel reports for the device: its own removable flag, or its
// disk's when it is a partition.
func isRemovable(device uint64) bool {
	base := fmt.Sprintf("/sys/dev/block/%d:%d/", unix.Major(device), unix.Minor(device))
	for _, name := range []string{"removable", "../removable"} {
		file, err := os.Open(base + name) //nolint:gosec // a path built from two numbers
		if err != nil {
			continue
		}
		var flag [1]byte
		count, _ := file.Read(flag[:]) //nolint:errcheck // a failed read is not a 1
		_ = file.Close()               //nolint:errcheck // nothing to flush on a read-only handle
		return count == 1 && flag[0] == '1'
	}
	return false
}

// lookupAccount is the account's user ID, parsed to 31 bits: Fchown takes an int, which is 32 bits
// on some targets, and -1 means "leave the owner" to it.
func lookupAccount(account string) (uint32, error) {
	found, err := user.Lookup(account)
	if err != nil {
		return 0, fmt.Errorf("bootstrap: the account %s: %w", account, err)
	}
	userID, err := strconv.ParseUint(found.Uid, 10, 31)
	if err != nil {
		return 0, fmt.Errorf("bootstrap: the account %s: %w", account, err)
	}
	return uint32(userID), nil
}

// ownerName is the account as the OS resolves it, or the number when it does not.
func ownerName(userID uint32) string {
	text := strconv.FormatUint(uint64(userID), 10)
	if found, err := user.LookupId(text); err == nil {
		return found.Username
	}
	return text
}

func setToRule(finding Finding, account string) error {
	if !isElevated() {
		return &Refusal{Cause: NotElevated}
	}
	if finding.Item == ItemSwarmSecret || finding.Item == ItemMachineKeyPair {
		return &Refusal{Cause: LooserThanRule, Path: finding.Path, Item: finding.Item}
	}
	accountID, err := lookupAccount(account)
	if err != nil {
		return err
	}
	descriptor, err := openFinding(finding)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(descriptor) }() //nolint:errcheck // nothing to flush on a read-only handle
	// The owner first: a change of owner clears the set-user-ID bits that the mode then sets.
	if err := unix.Fchown(descriptor, int(accountID), -1); err != nil {
		return fmt.Errorf("bootstrap: setting the owner of %s: %w", finding.Path, err)
	}
	if err := unix.Fchmod(descriptor, uint32(modeOfRule(finding.Item))); err != nil {
		return fmt.Errorf("bootstrap: setting the mode of %s: %w", finding.Path, err)
	}
	return nil
}

// openFinding opens the item the finding names and checks the handle is that kind of item: a
// file through the descriptor of the folder it is in, on that folder's device and held by no
// other name. The open does not block, so a FIFO put there is refused, not waited on.
func openFinding(finding Finding) (int, error) {
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	var descriptor int
	var err error
	var parent unix.Stat_t
	wantType, wantLinks := uint32(unix.S_IFDIR), uint64(0)
	if finding.Item == ItemFolder {
		descriptor, err = unix.Open(finding.Path, flags, 0)
	} else {
		var folder int
		if folder, err = unix.Open(filepath.Dir(finding.Path), flags|unix.O_DIRECTORY, 0); err != nil {
			return -1, fmt.Errorf("bootstrap: opening the folder of %s: %w", finding.Path, err)
		}
		defer func() { _ = unix.Close(folder) }() //nolint:errcheck // nothing to flush on a read-only handle
		if err = unix.Fstat(folder, &parent); err != nil {
			return -1, fmt.Errorf("bootstrap: reading the folder of %s: %w", finding.Path, err)
		}
		descriptor, err = unix.Openat(folder, filepath.Base(finding.Path), flags, 0)
		wantType, wantLinks = unix.S_IFREG, 1
	}
	if errors.Is(err, unix.ELOOP) {
		return -1, &Refusal{Cause: Link, Path: finding.Path}
	}
	if err != nil {
		return -1, fmt.Errorf("bootstrap: opening %s: %w", finding.Path, err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(descriptor, &stat); err != nil {
		_ = unix.Close(descriptor) //nolint:errcheck // nothing to flush on a read-only handle
		return -1, fmt.Errorf("bootstrap: reading %s: %w", finding.Path, err)
	}
	if stat.Mode&unix.S_IFMT != wantType || (wantLinks != 0 && (uint64(stat.Nlink) != wantLinks || stat.Dev != parent.Dev)) {
		_ = unix.Close(descriptor) //nolint:errcheck // nothing to flush on a read-only handle
		return -1, fmt.Errorf("bootstrap: %s is not the item that was checked: its type, its folder's device or its link count differs", finding.Path)
	}
	return descriptor, nil
}
