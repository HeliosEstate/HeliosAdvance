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
		// A link where a file should be is looser than the rule, whatever its mode. Any other
		// thing in its place, or a second name for the file, means hadv-setup did not make the folder.
		displaced := item != ItemFolder && stat.Mode&unix.S_IFMT == unix.S_IFLNK
		if item != ItemFolder && !displaced && (stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1) {
			return nil, fmt.Errorf("bootstrap: %s is not a file with one name, so hadv-setup did not make this folder", path)
		}
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

// maxStackDepth bounds the walk down a stack of block devices (LVM over LUKS over md over a disk).
const maxStackDepth = 8

// isRemovable is what the kernel reports for the device, or for any disk beneath it.
func isRemovable(device uint64) bool {
	return removableAt(fmt.Sprintf("/sys/dev/block/%d:%d", unix.Major(device), unix.Minor(device)), maxStackDepth)
}

// removableAt is whether the block device at a sysfs directory, or a device it is built on, is
// removable. The directory is a symbolic link in sysfs, so it is resolved once and the walk works
// on the real path. The kernel puts a partition file in every partition's directory, and a
// partition's disk is judged in full in its place: the disk's flag and the disk's slaves/. A
// device-mapper or md device has a flag of its own, reading 0, and still has its slaves/ walked,
// because that flag says nothing of the disks beneath.
func removableAt(directory string, depth int) bool {
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(resolved, "partition")); err == nil {
		resolved = filepath.Dir(resolved)
	}
	if readRemovable(resolved) == '1' {
		return true
	}
	if depth == 0 {
		return false
	}
	slaves, err := os.ReadDir(filepath.Join(resolved, "slaves"))
	if err != nil {
		return false
	}
	for _, slave := range slaves {
		if removableAt(filepath.Join(resolved, "slaves", slave.Name()), depth-1) {
			return true
		}
	}
	return false
}

// readRemovable is the first byte of a device directory's removable file, 0 if it cannot be read.
func readRemovable(directory string) byte {
	file, err := os.Open(filepath.Join(directory, "removable")) //nolint:gosec // a path built from names the kernel lists
	if err != nil {
		return 0
	}
	var flag [1]byte
	_, _ = file.Read(flag[:]) //nolint:errcheck // a failed read leaves 0, which is not a 1
	_ = file.Close()          //nolint:errcheck // nothing to flush on a read-only handle
	return flag[0]
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
	if finding.Item == ItemFolder {
		descriptor, err := unix.Open(finding.Path, flags, 0)
		return verifyOpened(finding.Path, descriptor, err, unix.S_IFDIR, nil)
	}
	folderPath := filepath.Dir(finding.Path)
	// No O_DIRECTORY: with O_NOFOLLOW it would answer a link with ENOTDIR instead of ELOOP.
	folder, err := unix.Open(folderPath, flags, 0)
	if _, err := verifyOpened(folderPath, folder, err, unix.S_IFDIR, nil); err != nil {
		return -1, err
	}
	defer func() { _ = unix.Close(folder) }() //nolint:errcheck // nothing to flush on a read-only handle
	var parent unix.Stat_t
	if err := unix.Fstat(folder, &parent); err != nil {
		return -1, fmt.Errorf("bootstrap: reading %s: %w", folderPath, err)
	}
	// The type is known before the open: opening a FIFO or a device can do something.
	name := filepath.Base(finding.Path)
	var entry unix.Stat_t
	if err := unix.Fstatat(folder, name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return -1, fmt.Errorf("bootstrap: reading %s: %w", finding.Path, err)
	}
	if entry.Mode&unix.S_IFMT == unix.S_IFLNK {
		return -1, &Refusal{Cause: Link, Path: finding.Path}
	}
	if entry.Mode&unix.S_IFMT != unix.S_IFREG {
		return -1, fmt.Errorf("bootstrap: %s is not a regular file", finding.Path)
	}
	descriptor, err := unix.Openat(folder, name, flags, 0)
	return verifyOpened(finding.Path, descriptor, err, unix.S_IFREG, &parent)
}

// verifyOpened judges a descriptor just opened: a link is Link, and anything but the wanted type
// is an error. For a file, whose folder is given, it also needs one name and the folder's device.
func verifyOpened(path string, descriptor int, openErr error, wantType uint32, folder *unix.Stat_t) (int, error) {
	if errors.Is(openErr, unix.ELOOP) {
		return -1, &Refusal{Cause: Link, Path: path}
	}
	if openErr != nil {
		return -1, fmt.Errorf("bootstrap: opening %s: %w", path, openErr)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(descriptor, &stat); err != nil {
		_ = unix.Close(descriptor) //nolint:errcheck // nothing to flush on a read-only handle
		return -1, fmt.Errorf("bootstrap: reading %s: %w", path, err)
	}
	if stat.Mode&unix.S_IFMT != wantType || (folder != nil && (stat.Nlink != 1 || stat.Dev != folder.Dev)) {
		_ = unix.Close(descriptor) //nolint:errcheck // nothing to flush on a read-only handle
		return -1, fmt.Errorf("bootstrap: %s is not the item that was checked: its type, its folder's device or its link count differs", path)
	}
	return descriptor, nil
}
