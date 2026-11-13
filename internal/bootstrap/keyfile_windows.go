// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"io/fs"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// aceBytesBeforeAccount is an entry's header and access mask, which come before the account.
	aceBytesBeforeAccount = 8
	// accountFixedBytes is the fixed start of an account: its revision, sub-authority count and
	// 6-byte authority.
	accountFixedBytes = 8

	aceAllow = windows.ACCESS_ALLOWED_ACE_TYPE
	// The four kinds of entry that deny: plain, object, callback and callback object.
	aceDeny               = windows.ACCESS_DENIED_ACE_TYPE
	aceDenyObject         = 6
	aceDenyCallback       = 10
	aceDenyCallbackObject = 12
)

// checkKeyFile judges the owner and the access list of the key file from one read on the opened
// file's handle, so a name swapped after the open changes nothing.
func checkKeyFile(file *os.File, _ fs.FileInfo) error {
	descriptor, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ErrKeyFilePermissions
	}
	return judgeAccess(descriptor, ErrKeyFilePermissions, ErrKeyFileReachable)
}

// judgeAccess judges a descriptor's owner and access list. Everything is read before anything is
// judged, so an access list it cannot confirm, which gives unconfirmed, is told from one that is
// reachable, which gives reachable.
func judgeAccess(descriptor *windows.SECURITY_DESCRIPTOR, unconfirmed, reachable error) error {
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return unconfirmed
	}
	allowed, err := allowedAccounts()
	if err != nil {
		return unconfirmed
	}
	// The library gives one error for an absent list and for a failed read, so the control bits
	// tell them apart.
	control, _, err := descriptor.Control()
	if err != nil {
		return unconfirmed
	}
	if control&windows.SE_DACL_PRESENT == 0 {
		return reachable
	}
	list, _, err := descriptor.DACL()
	if err != nil {
		return unconfirmed
	}
	if list == nil {
		return reachable
	}
	accounts := []*windows.SID{owner}
	for index := range uint32(list.AceCount) {
		var entry *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(list, index, &entry); err != nil {
			return unconfirmed
		}
		switch entry.Header.AceType {
		case aceAllow:
			account, ok := accountOf(entry)
			if !ok {
				return unconfirmed
			}
			accounts = append(accounts, account)
		case aceDeny, aceDenyObject, aceDenyCallback, aceDenyCallbackObject:
		default:
			return unconfirmed
		}
	}
	for _, account := range accounts {
		if !isOneOf(account, allowed) {
			return reachable
		}
	}
	return nil
}

// allowedAccounts are the only accounts that may own or reach the key file or the key store key;
// the engine's own user is read from its token, since no name stands for it.
func allowedAccounts() ([]*windows.SID, error) {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return []*windows.SID{system, administrators, user.User.Sid}, nil
}

// accountOf reaches the account a plain allow entry names, which starts where the entry's SidStart
// does: the conversion golang.org/x/sys/windows's own tests use. Nothing checks that the account
// lies inside the entry, so it is confirmed here before anything reads it.
func accountOf(entry *windows.ACCESS_ALLOWED_ACE) (*windows.SID, bool) {
	if int(entry.Header.AceSize) < aceBytesBeforeAccount+accountFixedBytes {
		return nil, false
	}
	account := (*windows.SID)(unsafe.Pointer(&entry.SidStart))
	if !account.IsValid() || account.Len() > int(entry.Header.AceSize)-aceBytesBeforeAccount {
		return nil, false
	}
	return account, true
}

func isOneOf(account *windows.SID, allowed []*windows.SID) bool {
	for _, candidate := range allowed {
		if account.Equals(candidate) {
			return true
		}
	}
	return false
}
