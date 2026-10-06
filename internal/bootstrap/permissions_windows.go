// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
)

func isElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// held is who owns an item and who its access list grants anything: what a rule is judged
// against. The security descriptor stays reachable, since the SIDs point into it.
type held struct {
	descriptor *windows.SECURITY_DESCRIPTOR
	owner      *windows.SID
	grantees   []*windows.SID
	inherited  bool
}

func readHeld(descriptor *windows.SECURITY_DESCRIPTOR) (held, error) {
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
		if entry.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
			result.grantees = append(result.grantees, (*windows.SID)(unsafe.Pointer(&entry.SidStart))) //nolint:gosec // an allow entry's SID follows its mask
		}
	}
	return result, nil
}

// looserThan is whether the item is owned by, or grants anything to, an account other than
// the three the rule names, or inherits.
func (item held) looserThan(allowed []*windows.SID) bool {
	holds := func(sid *windows.SID) bool {
		return slices.ContainsFunc(allowed, func(candidate *windows.SID) bool { return windows.EqualSid(candidate, sid) })
	}
	return item.inherited || !holds(item.owner) || slices.ContainsFunc(item.grantees, func(sid *windows.SID) bool { return !holds(sid) })
}

func (item held) permissions() Permissions {
	accounts := make([]string, 0, len(item.grantees))
	for _, sid := range item.grantees {
		if name := accountName(sid); !slices.Contains(accounts, name) {
			accounts = append(accounts, name)
		}
	}
	return Permissions{Owner: accountName(item.owner), Accounts: accounts, Inherited: item.inherited}
}

// accountName is the account as Windows resolves the SID, DOMAIN\name, or the SID's own text.
func accountName(sid *windows.SID) string {
	name, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return sid.String()
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
	if err := checkFolderRules(folder); err != nil {
		return nil, err
	}
	directory, err := os.Open(folder) //nolint:gosec // the path hadv-setup was given
	if err != nil {
		return nil, fmt.Errorf("bootstrap: opening %s: %w", folder, err)
	}
	defer func() { _ = directory.Close() }() //nolint:errcheck // nothing to flush on a read-only handle
	names, err := directory.Readdirnames(maxFolderEntries)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("bootstrap: reading the folder: %w", err)
	}
	items := map[string]Item{folder: ItemFolder}
	for _, name := range names {
		items[filepath.Join(folder, name)] = itemOf(name)
	}

	findings := []Finding{}
	for path, item := range items {
		found, ok, err := readFileHeld(path, item)
		if err != nil {
			return nil, err
		}
		if ok && found.looserThan(allowed) {
			findings = append(findings, Finding{Item: item, Path: path, Found: found.permissions(), Rule: ruleFor(account)})
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

// readFileHeld reads a file or the folder through the handle it opens. A link, or a
// directory where a file should be, is not read: ok is false.
func readFileHeld(path string, item Item) (result held, ok bool, err error) {
	handle, err := openItem(path, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return held{}, false, fmt.Errorf("bootstrap: opening %s: %w", path, err)
	}
	defer func() { _ = windows.CloseHandle(handle) }() //nolint:errcheck // nothing to flush on a read-only handle
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return held{}, false, fmt.Errorf("bootstrap: reading %s: %w", path, err)
	}
	isDirectory := information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	// ponytail: a link or a directory in the folder is skipped; unlocking refuses a link.
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || isDirectory != (item == ItemFolder) {
		return held{}, false, nil
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, ownerAndDACL)
	if err != nil {
		return held{}, false, fmt.Errorf("bootstrap: reading the access list of %s: %w", path, err)
	}
	result, err = readHeld(descriptor)
	return result, err == nil, err
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

// checkFolderRules judges the folder rules, the link and the file system on the folder's own
// handle.
func checkFolderRules(folder string) error {
	refuse := func(rule FolderRule) error { return &Refusal{Cause: FolderRefused, Path: folder, Rule: rule} }
	if !filepath.IsAbs(folder) {
		return refuse(NotAbsolute)
	}
	if isNetworkPath(folder) {
		return refuse(NetworkShare)
	}
	handle, err := openItem(folder, windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return fmt.Errorf("bootstrap: opening %s: %w", folder, err)
	}
	defer func() { _ = windows.CloseHandle(handle) }() //nolint:errcheck // nothing to flush on a read-only handle
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return fmt.Errorf("bootstrap: reading %s: %w", folder, err)
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return refuse(FolderLink)
	}
	switch driveType(folder) {
	case windows.DRIVE_REMOTE:
		return refuse(NetworkShare)
	case windows.DRIVE_REMOVABLE, windows.DRIVE_CDROM:
		return refuse(Removable)
	}
	var filesystem [windows.MAX_PATH + 1]uint16
	if err := windows.GetVolumeInformationByHandle(handle, nil, 0, nil, nil, nil, &filesystem[0], uint32(len(filesystem))); err != nil {
		return fmt.Errorf("bootstrap: reading the file system of %s: %w", folder, err)
	}
	if name := windows.UTF16ToString(filesystem[:]); !strings.EqualFold(name, "NTFS") && !strings.EqualFold(name, "ReFS") {
		return refuse(FileSystem)
	}
	return nil
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

// driveType is what Windows reports for the volume the path is on.
func driveType(path string) uint32 {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.DRIVE_UNKNOWN
	}
	var root [windows.MAX_PATH + 1]uint16
	if err := windows.GetVolumePathName(name, &root[0], uint32(len(root))); err != nil {
		return windows.DRIVE_UNKNOWN
	}
	return windows.GetDriveType(&root[0])
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
	result, err := readHeld((*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&buffer[0]))) //nolint:gosec // the key store returns a self-relative security descriptor
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
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	enableRestorePrivileges()
	handle, err := openItem(finding.Path, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES|windows.WRITE_DAC|windows.WRITE_OWNER)
	if err != nil {
		return fmt.Errorf("bootstrap: opening %s: %w", finding.Path, err)
	}
	defer func() { _ = windows.CloseHandle(handle) }() //nolint:errcheck // nothing to flush on a read-only handle
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return fmt.Errorf("bootstrap: reading %s: %w", finding.Path, err)
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return &Refusal{Cause: Link, Path: finding.Path}
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, ownerAndDACL|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil); err != nil {
		return fmt.Errorf("bootstrap: setting the access list of %s: %w", finding.Path, err)
	}
	return nil
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

// enableRestorePrivileges turns on the privileges that let an administrator open an item whose
// access list leaves the administrators out and give it another owner; an administrator's
// token holds them disabled. Without one the open fails and says so.
func enableRestorePrivileges() {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return
	}
	defer func() { _ = token.Close() }() //nolint:errcheck // nothing to flush on a read-only handle
	for _, name := range []string{"SeRestorePrivilege", "SeBackupPrivilege", "SeTakeOwnershipPrivilege"} {
		var privileges windows.Tokenprivileges
		privileges.PrivilegeCount = 1
		privileges.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
		if windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &privileges.Privileges[0].Luid) == nil {
			_ = windows.AdjustTokenPrivileges(token, false, &privileges, 0, nil, nil) //nolint:errcheck // best effort: the open that follows reports what is missing
		}
	}
}

// call makes a key store call and returns its status. The error a LazyProc returns is the
// thread's last error, not the status, so it is not read.
func call(procedure *windows.LazyProc, arguments ...uintptr) uintptr {
	status, _, _ := procedure.Call(arguments...) //nolint:errcheck // the error is the thread's last error, not the status
	return status
}
