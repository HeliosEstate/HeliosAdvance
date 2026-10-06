// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The accounts every Windows rule names beside the service account, as Windows spells them.
const (
	systemName         = `NT AUTHORITY\SYSTEM`
	administratorsName = `BUILTIN\Administrators`
)

// The machine key pair lives in one of two key storage providers: the software one, and the
// TPM's.
var keyProviders = []string{"Microsoft Software Key Storage Provider", "Microsoft Platform Crypto Provider"}

// What the key store is called with, from ncrypt.h.
const (
	machineKeyFlag      = 0x20 // NCRYPT_MACHINE_KEY_FLAG
	securityProperty    = "Security Descr"
	badKeySet           = 0x80090016 // NTE_BAD_KEYSET: no such key in this provider
	ownerAndDACL        = windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION
	keyPairAccess       = "GA" // SDDL: generic all
	folderInherit       = "OICI"
	fileAllAccess       = "FA"
	securityDescriptors = "O:BAD:P"
)

var ncrypt = windows.NewLazySystemDLL("ncrypt.dll")

var (
	procOpenProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procOpenKey      = ncrypt.NewProc("NCryptOpenKey")
	procGetProperty  = ncrypt.NewProc("NCryptGetProperty")
	procSetProperty  = ncrypt.NewProc("NCryptSetProperty")
	procFreeObject   = ncrypt.NewProc("NCryptFreeObject")

	procSetSecurityObject = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtSetSecurityObject")
)

func isElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// held is who owns an item and who its access list grants anything: what a rule is judged
// against. The security descriptor stays reachable, since the SIDs point into it.
type held struct {
	descriptor *windows.SECURITY_DESCRIPTOR
	owner      *windows.SID
	grantees   []*windows.SID
	inherited  bool
	link       bool // a symbolic link or junction where the item belongs: looser than any rule
}

// The access control entry types of winnt.h that grant. A type neither list knows is treated as
// a grant to Everyone: the safe error is to find an item looser than its rule.
const (
	allowType               = 0
	allowObjectType         = 5
	allowCallbackType       = 9
	allowCallbackObjectType = 11
)

// grantsNothing is the entry types that deny, audit, alarm or label, and so give no access.
var grantsNothing = []byte{1, 2, 3, 6, 7, 8, 10, 12, 13, 14, 15, 16, 17, 18, 19}

// An object entry says with these flags that a GUID sits before its SID.
const (
	objectTypePresent          = 1
	inheritedObjectTypePresent = 2
	guidSize                   = 16
)

// grantee is the account an entry grants access to, or nil when it grants nothing.
func grantee(entry *windows.ACCESS_ALLOWED_ACE) (*windows.SID, error) {
	switch kind := entry.Header.AceType; {
	case kind == allowType || kind == allowCallbackType:
		return (*windows.SID)(unsafe.Pointer(&entry.SidStart)), nil //nolint:gosec // an allow entry's SID follows its mask
	case kind == allowObjectType || kind == allowCallbackObjectType:
		// After the mask come the flags, then the GUIDs the flags name, then the SID.
		flags := *(*uint32)(unsafe.Add(unsafe.Pointer(entry), 8)) //nolint:gosec // an object entry's flags follow its mask
		offset := uintptr(12)
		if flags&objectTypePresent != 0 {
			offset += guidSize
		}
		if flags&inheritedObjectTypePresent != 0 {
			offset += guidSize
		}
		return (*windows.SID)(unsafe.Add(unsafe.Pointer(entry), offset)), nil //nolint:gosec // the SID follows the GUIDs
	case slices.Contains(grantsNothing, kind):
		return nil, nil
	}
	return windows.CreateWellKnownSid(windows.WinWorldSid)
}

// readHeldDescriptor reads a descriptor. An inherit-only entry grants nothing on the object, so it
// is skipped on a file; on the folder it is what every file later made there receives, so it counts.
func readHeldDescriptor(descriptor *windows.SECURITY_DESCRIPTOR, isFolder bool) (held, error) {
	owner, _, err := descriptor.Owner()
	if err != nil {
		return held{}, err
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return held{}, err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil && !errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return held{}, err
	}
	result := held{descriptor: descriptor, owner: owner, inherited: control&windows.SE_DACL_PROTECTED == 0}
	if dacl == nil {
		// A missing access list grants everyone everything.
		everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
		if err != nil {
			return held{}, err
		}
		result.grantees = append(result.grantees, everyone)
		return result, nil
	}
	for index := range uint32(dacl.AceCount) {
		var entry *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &entry); err != nil {
			return held{}, err
		}
		if !isFolder && entry.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		trustee, err := grantee(entry)
		if err != nil {
			return held{}, err
		}
		if trustee != nil {
			result.grantees = append(result.grantees, trustee)
		}
	}
	return result, nil
}

// looserThan is whether the item is owned by, or grants anything to, an account other than
// the three the rule names, or inherits.
func (item held) looserThan(allowed []*windows.SID) bool {
	holds := func(trustee *windows.SID) bool {
		return slices.ContainsFunc(allowed, func(candidate *windows.SID) bool { return windows.EqualSid(candidate, trustee) })
	}
	return item.link || item.inherited || !holds(item.owner) || slices.ContainsFunc(item.grantees, func(trustee *windows.SID) bool { return !holds(trustee) })
}

func (item held) permissions() Permissions {
	accounts := make([]string, 0, len(item.grantees))
	for _, trustee := range item.grantees {
		if name := accountName(trustee); !slices.Contains(accounts, name) {
			accounts = append(accounts, name)
		}
	}
	return Permissions{Owner: accountName(item.owner), Accounts: accounts, Inherited: item.inherited}
}

// accountName is the account as Windows resolves the SID, DOMAIN\name, or the SID's own text.
func accountName(trustee *windows.SID) string {
	name, domain, _, err := trustee.LookupAccount("")
	if err != nil {
		return trustee.String()
	}
	if domain == "" {
		return name
	}
	return domain + `\` + name
}

// ruleFor is every Windows item's rule for the account: the account, SYSTEM and
// Administrators only, no inherited access, owned by Administrators.
func ruleFor(account string) Permissions {
	return Permissions{Owner: administratorsName, Accounts: []string{account, systemName, administratorsName}}
}

// allowedFor is the SIDs the rule names.
func allowedFor(account string) ([]*windows.SID, error) {
	service, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: the account %s: %w", account, err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	return []*windows.SID{service, system, administrators}, nil
}

func checkPermissions(folder string, mode KeyMode, account string) ([]Finding, error) {
	if !isElevated() {
		return nil, &Refusal{Cause: NotElevated}
	}
	allowed, err := allowedFor(account)
	if err != nil {
		return nil, err
	}
	// Backup turns off the access check on the opens that follow, which are all reads: an item
	// that shuts the administrators out is the one most worth reporting.
	defer enablePrivileges("SeBackupPrivilege")()
	directory, err := openFolder(folder)
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.Close() }() //nolint:errcheck // nothing to flush on a read-only handle
	names, err := readNames(directory)
	if err != nil {
		return nil, err
	}

	findings := []Finding{}
	judge := func(handle windows.Handle, path string, item Item) error {
		found, err := readHeld(handle, path, item)
		if err != nil {
			return err
		}
		if found.looserThan(allowed) {
			findings = append(findings, Finding{Item: item, Path: path, Found: found.permissions(), Rule: ruleFor(account)})
		}
		return nil
	}
	folderHandle := windows.Handle(directory.Fd())
	if err := judge(folderHandle, folder, ItemFolder); err != nil {
		return nil, err
	}
	for _, name := range names {
		if err := judgeChild(folderHandle, folder, name, judge); err != nil {
			return nil, err
		}
	}
	if mode == ModeMachineKeyPair {
		found, ok, err := readKeyPairHeld()
		if err != nil {
			return nil, err
		}
		if ok && found.looserThan(allowed) {
			findings = append(findings, Finding{Item: ItemMachineKeyPair, Path: machineKeyPairName, Found: found.permissions(), Rule: ruleFor(account)})
		}
	}
	return findings, nil
}

// judgeChild opens a name in the folder relative to the folder's handle and judges it.
func judgeChild(folder windows.Handle, folderPath, name string, judge func(windows.Handle, string, Item) error) error {
	path := filepath.Join(folderPath, name)
	handle, err := openChild(folder, name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return fmt.Errorf("bootstrap: opening %s: %w", path, err)
	}
	defer func() { _ = windows.CloseHandle(handle) }() //nolint:errcheck // nothing to flush on a read-only handle
	return judge(handle, path, itemOf(name))
}

// readHeld reads who owns an item and its access list through the handle it was opened by. A
// link is read as itself and marked. Anything else that is not the item, a directory where a file
// belongs or a file held by a second name, is an error: hadv-setup did not make that folder.
func readHeld(handle windows.Handle, path string, item Item) (held, error) {
	information, err := informationOf(handle)
	if err != nil {
		return held{}, fmt.Errorf("bootstrap: reading %s: %w", path, err)
	}
	link, err := isLink(handle)
	if err != nil {
		return held{}, fmt.Errorf("bootstrap: reading %s: %w", path, err)
	}
	isDirectory := information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if !link && !isDirectory && information.NumberOfLinks != 1 {
		return held{}, &Refusal{Cause: Link, Path: path, Item: item}
	}
	if !link && isDirectory != (item == ItemFolder) {
		return held{}, fmt.Errorf("bootstrap: %s is not the kind of item it is named for, or has a second name, so hadv-setup did not make this folder", path)
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, ownerAndDACL)
	if err != nil {
		return held{}, fmt.Errorf("bootstrap: reading the access list of %s: %w", path, err)
	}
	result, err := readHeldDescriptor(descriptor, item == ItemFolder)
	result.link = link
	return result, err
}

// isLink is whether the handle is a symbolic link or a junction. Another kind of reparse point,
// such as a deduplicated or cloud file, is an ordinary item.
func isLink(handle windows.Handle) (bool, error) {
	// FAT has no reparse points and refuses the tag query, so the plain attributes are asked first.
	plain, err := informationOf(handle)
	if err != nil {
		return false, err
	}
	if plain.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		return false, nil
	}
	var information struct{ FileAttributes, ReparseTag uint32 }
	err = windows.GetFileInformationByHandleEx(handle, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&information)), uint32(unsafe.Sizeof(information))) //nolint:gosec // the call fills a struct of two fields
	if err != nil {
		return false, err
	}
	return information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 &&
		(information.ReparseTag == windows.IO_REPARSE_TAG_SYMLINK || information.ReparseTag == windows.IO_REPARSE_TAG_MOUNT_POINT), nil
}

func informationOf(handle windows.Handle) (windows.ByHandleFileInformation, error) {
	var information windows.ByHandleFileInformation
	err := windows.GetFileInformationByHandle(handle, &information)
	return information, err
}

// openItem opens a file or folder itself, never what a link points to.
func openItem(path string, access uint32) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(name, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

// openChild opens a name inside a folder, relative to the folder's handle, so it is the folder
// that was judged and not whatever the folder's path names by now. A link is opened as itself, and
// the name is matched exactly as listed: in a case-sensitive folder a name of another case is another file.
func openChild(folder windows.Handle, name string, access uint32) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{RootDirectory: folder, ObjectName: objectName, Attributes: 0}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access|windows.SYNCHRONIZE, &attributes, &status, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN,
		windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	return handle, err
}

// openFolder opens the bootstrap folder, judges the folder rules on the handle, and returns it
// for the reads that follow.
func openFolder(folder string) (*os.File, error) {
	refuse := func(rule FolderRule) error { return &Refusal{Cause: FolderRefused, Path: folder, Rule: rule} }
	if !filepath.IsAbs(folder) {
		return nil, refuse(NotAbsolute)
	}
	if isNetworkPath(folder) {
		return nil, refuse(NetworkShare)
	}
	handle, err := openItem(folder, windows.FILE_LIST_DIRECTORY|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: opening %s: %w", folder, err)
	}
	directory := os.NewFile(uintptr(handle), folder)
	fail := func(err error) (*os.File, error) {
		_ = directory.Close() //nolint:errcheck // nothing to flush on a read-only handle
		return nil, err
	}
	link, err := isLink(handle)
	if err != nil {
		return fail(fmt.Errorf("bootstrap: reading %s: %w", folder, err))
	}
	if link {
		return fail(refuse(FolderLink))
	}
	switch driveType(handle) {
	case windows.DRIVE_REMOTE:
		return fail(refuse(NetworkShare))
	case windows.DRIVE_REMOVABLE, windows.DRIVE_CDROM:
		return fail(refuse(Removable))
	}
	var filesystem [windows.MAX_PATH + 1]uint16
	if err := windows.GetVolumeInformationByHandle(handle, nil, 0, nil, nil, nil, &filesystem[0], uint32(len(filesystem))); err != nil {
		return fail(fmt.Errorf("bootstrap: reading the file system of %s: %w", folder, err))
	}
	if name := windows.UTF16ToString(filesystem[:]); !strings.EqualFold(name, "NTFS") && !strings.EqualFold(name, "ReFS") {
		return fail(refuse(FileSystem))
	}
	return directory, nil
}

// isNetworkPath is whether the path names a UNC share, in either of the two spellings.
func isNetworkPath(path string) bool {
	if rest, ok := strings.CutPrefix(path, `\\?\`); ok {
		return strings.HasPrefix(strings.ToUpper(rest), `UNC\`)
	}
	if strings.HasPrefix(path, `\\.\`) {
		return false
	}
	return strings.HasPrefix(path, `\\`)
}

// The volume namings GetFinalPathNameByHandle is asked for, from fileapi.h.
const (
	volumeNameDOS  = 0
	volumeNameGUID = 1
)

// finalPath is the path the handle stands at, in the volume naming asked for.
func finalPath(handle windows.Handle, flags uint32) (string, bool) {
	size := uint32(1024)
	for range 2 {
		buffer := make([]uint16, size)
		length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], size, flags)
		switch {
		case err != nil:
			return "", false
		case length >= size:
			// The call says how long a buffer it needs, one more than the path for the terminator.
			size = length + 1
		default:
			return windows.UTF16ToString(buffer[:length]), true
		}
	}
	return "", false
}

// driveType is what Windows reports for the volume the handle is on, not the one its path names by now.
func driveType(handle windows.Handle) uint32 {
	root := ""
	if path, ok := finalPath(handle, volumeNameGUID); ok {
		// \\?\Volume{guid}\ is the volume's root.
		if end := strings.Index(path, "}"); end >= 0 {
			root = path[:end+1] + `\`
		}
	} else if path, ok := finalPath(handle, volumeNameDOS); ok {
		// A remote volume has no GUID: it is a share's path or a mapped drive's.
		if isNetworkPath(path) {
			return windows.DRIVE_REMOTE
		}
		if letter, found := strings.CutPrefix(path, `\\?\`); found && len(letter) >= 2 && letter[1] == ':' {
			root = letter[:2] + `\`
		}
	}
	name, err := windows.UTF16PtrFromString(root)
	if root == "" || err != nil {
		return windows.DRIVE_UNKNOWN
	}
	return windows.GetDriveType(name)
}

// The machine key pair, through the CNG key store.

// keyPair is an open machine key pair and the provider it is in.
type keyPair struct{ provider, key uintptr }

func (pair keyPair) close() {
	call(procFreeObject, pair.key)
	call(procFreeObject, pair.provider)
}

// openKeyPair opens the machine key pair in whichever provider holds it: ok is false when
// none does.
func openKeyPair() (pair keyPair, ok bool, err error) {
	keyName, err := windows.UTF16PtrFromString(machineKeyPairName)
	if err != nil {
		return keyPair{}, false, err
	}
	for _, providerName := range keyProviders {
		name, err := windows.UTF16PtrFromString(providerName)
		if err != nil {
			return keyPair{}, false, err
		}
		var provider, key uintptr
		if status := call(procOpenProvider, uintptr(unsafe.Pointer(&provider)), uintptr(unsafe.Pointer(name)), 0); status != 0 { //nolint:gosec // the key store's calling convention
			continue
		}
		status := call(procOpenKey, provider, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(keyName)), 0, machineKeyFlag) //nolint:gosec // the key store's calling convention
		if status == 0 {
			return keyPair{provider, key}, true, nil
		}
		call(procFreeObject, provider)
		if uint32(status) != badKeySet { //nolint:gosec // an NTSTATUS-sized value
			return keyPair{}, false, fmt.Errorf("bootstrap: opening the machine key pair: status %#x", status)
		}
	}
	return keyPair{}, false, nil
}

func readKeyPairHeld() (held, bool, error) {
	pair, ok, err := openKeyPair()
	if err != nil || !ok {
		return held{}, false, err
	}
	defer pair.close()
	property, err := windows.UTF16PtrFromString(securityProperty)
	if err != nil {
		return held{}, false, err
	}
	var size uint32
	if status := call(procGetProperty, pair.key, uintptr(unsafe.Pointer(property)), 0, 0, uintptr(unsafe.Pointer(&size)), ownerAndDACL); status != 0 { //nolint:gosec // the key store's calling convention
		return held{}, false, fmt.Errorf("bootstrap: sizing the machine key pair's access list: status %#x", status)
	}
	buffer := make([]byte, size)
	if status := call(procGetProperty, pair.key, uintptr(unsafe.Pointer(property)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(size), uintptr(unsafe.Pointer(&size)), ownerAndDACL); status != 0 { //nolint:gosec // the key store's calling convention
		return held{}, false, fmt.Errorf("bootstrap: reading the machine key pair's access list: status %#x", status)
	}
	result, err := readHeldDescriptor((*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&buffer[0])), false) //nolint:gosec // the key store returns a self-relative security descriptor
	return result, err == nil, err
}

func setToRule(finding Finding, account string) error {
	if !isElevated() {
		return &Refusal{Cause: NotElevated}
	}
	if finding.Item == ItemSwarmSecret {
		return &Refusal{Cause: LooserThanRule, Path: finding.Path, Item: finding.Item}
	}
	service, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return fmt.Errorf("bootstrap: the account %s: %w", account, err)
	}
	if finding.Item == ItemMachineKeyPair {
		return setKeyPairToRule(service)
	}
	inherit := ""
	if finding.Item == ItemFolder {
		inherit = folderInherit
	}
	descriptor, err := windows.SecurityDescriptorFromString(ruleSDDL(service, inherit, fileAllAccess))
	if err != nil {
		return err
	}
	defer enablePrivileges("SeRestorePrivilege", "SeBackupPrivilege", "SeTakeOwnershipPrivilege")()
	handle, err := openFinding(finding)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(handle) }() //nolint:errcheck // nothing to flush on a read-only handle
	// SetSecurityInfo would hand an inheritable entry on the folder down to the files in it, which
	// are not the finding; the native call sets only the object it is given.
	status := call(procSetSecurityObject, uintptr(handle), uintptr(ownerAndDACL|windows.PROTECTED_DACL_SECURITY_INFORMATION), uintptr(unsafe.Pointer(descriptor))) //nolint:gosec // the security object's calling convention
	if status != 0 {
		return fmt.Errorf("bootstrap: setting the access list of %s: status %#x", finding.Path, status)
	}
	return nil
}

// openFinding opens the item the finding names and checks the handle is that item: the folder
// itself, not a link; a file through the handle of the folder it is in, which is also not a
// link, and held by no other name. A link is refused as Link, naming the item or its folder.
func openFinding(finding Finding) (windows.Handle, error) {
	access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES | windows.WRITE_DAC | windows.WRITE_OWNER)
	var handle windows.Handle
	var err error
	if finding.Item == ItemFolder {
		handle, err = openItem(finding.Path, access)
	} else {
		folderPath := filepath.Dir(finding.Path)
		var folder windows.Handle
		if folder, err = openItem(folderPath, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES); err != nil {
			return 0, fmt.Errorf("bootstrap: opening the folder of %s: %w", finding.Path, err)
		}
		defer func() { _ = windows.CloseHandle(folder) }() //nolint:errcheck // nothing to flush on a read-only handle
		folderIsLink, linkErr := isLink(folder)
		if linkErr != nil {
			return 0, fmt.Errorf("bootstrap: reading the folder of %s: %w", finding.Path, linkErr)
		}
		if folderIsLink {
			return 0, &Refusal{Cause: Link, Path: folderPath}
		}
		handle, err = openChild(folder, filepath.Base(finding.Path), access)
	}
	if err != nil {
		return 0, fmt.Errorf("bootstrap: opening %s: %w", finding.Path, err)
	}
	link, err := isLink(handle)
	if err == nil && link {
		_ = windows.CloseHandle(handle) //nolint:errcheck // nothing to flush on a read-only handle
		return 0, &Refusal{Cause: Link, Path: finding.Path}
	}
	var information windows.ByHandleFileInformation
	if err == nil {
		information, err = informationOf(handle)
	}
	isDirectory := information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if err == nil && !isDirectory && information.NumberOfLinks != 1 {
		_ = windows.CloseHandle(handle) //nolint:errcheck // nothing to flush on a read-only handle
		return 0, &Refusal{Cause: Link, Path: finding.Path}
	}
	if err != nil || isDirectory != (finding.Item == ItemFolder) {
		_ = windows.CloseHandle(handle) //nolint:errcheck // nothing to flush on a read-only handle
		if err == nil {
			err = errors.New("its type or its link count differs from the item that was checked")
		}
		return 0, fmt.Errorf("bootstrap: %s is not the item that was checked: %w", finding.Path, err)
	}
	return handle, nil
}

// ruleSDDL is the rule as a security descriptor: owned by Administrators, protected from
// inheritance, granting the account, SYSTEM and Administrators the access given.
func ruleSDDL(service *windows.SID, inherit, access string) string {
	entry := func(trustee string) string { return "(A;" + inherit + ";" + access + ";;;" + trustee + ")" }
	return securityDescriptors + entry(service.String()) + entry("SY") + entry("BA")
}

func setKeyPairToRule(service *windows.SID) error {
	descriptor, err := windows.SecurityDescriptorFromString(ruleSDDL(service, "", keyPairAccess))
	if err != nil {
		return err
	}
	pair, ok, err := openKeyPair()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("bootstrap: the machine key pair %s is not in the key store", machineKeyPairName)
	}
	defer pair.close()
	property, err := windows.UTF16PtrFromString(securityProperty)
	if err != nil {
		return err
	}
	bytes := unsafe.Slice((*byte)(unsafe.Pointer(descriptor)), descriptor.Length())                                                                                       //nolint:gosec // a self-relative descriptor is its own bytes
	if status := call(procSetProperty, pair.key, uintptr(unsafe.Pointer(property)), uintptr(unsafe.Pointer(&bytes[0])), uintptr(len(bytes)), ownerAndDACL); status != 0 { //nolint:gosec // the key store's calling convention
		return fmt.Errorf("bootstrap: setting the machine key pair's access list: status %#x", status)
	}
	return nil
}

// privilegeLock serialises the work done with privileges on: they belong to the process, so
// two operations turning them on and off would take each other's away.
var privilegeLock sync.Mutex

// enablePrivileges turns on privileges that let an administrator open an item whose access list
// leaves the administrators out, and give it another owner; an administrator's token holds them
// disabled. It returns the function that puts them back as they were, which the caller must run.
// A privilege that cannot be turned on is not reported: the open that needs it says so.
func enablePrivileges(names ...string) (restore func()) {
	privilegeLock.Lock()
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return privilegeLock.Unlock
	}
	var changed []windows.Tokenprivileges
	for _, name := range names {
		var wanted, previous windows.Tokenprivileges
		wanted.PrivilegeCount = 1
		wanted.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
		if windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &wanted.Privileges[0].Luid) != nil {
			continue
		}
		var length uint32
		// The previous state comes back only for a privilege this call changed.
		err := windows.AdjustTokenPrivileges(token, false, &wanted, uint32(unsafe.Sizeof(previous)), &previous, &length)
		if err == nil && previous.PrivilegeCount == 1 {
			changed = append(changed, previous)
		}
	}
	return func() {
		for _, previous := range changed {
			_ = windows.AdjustTokenPrivileges(token, false, &previous, 0, nil, nil) //nolint:errcheck // nothing more can be done about a privilege that stays on
		}
		_ = token.Close() //nolint:errcheck // nothing to flush on a token
		privilegeLock.Unlock()
	}
}

// call makes a key store call and returns its status. The error a LazyProc returns is the
// thread's last error, not the status, so it is not read.
//
//go:uintptrescapes
func call(procedure *windows.LazyProc, arguments ...uintptr) uintptr {
	status, _, _ := procedure.Call(arguments...) //nolint:errcheck // the error is the thread's last error, not the status
	return status
}
