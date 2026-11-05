// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// The well-known accounts an access list names, in the SDDL the rows write access lists in.
const (
	sddlSystem         = "SY"
	sddlAdministrators = "BA"
	sddlUsers          = "BU"
	sddlEveryone       = "WD"
	usersSID           = "S-1-5-32-545"
)

// runnerSID is the user of this process's own token: the account the engine runs as when a row
// calls Open.
func runnerSID(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("reading this process's user: %v", err)
	}
	return user.User.Sid.String()
}

// setAccessList replaces a file's or folder's access list with the one sddl gives, such as
// "D:P(A;;FA;;;SY)", by its name, from outside Open.
func setAccessList(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("reading the access list %q: %v", sddl, err)
	}
	list, _, err := descriptor.DACL()
	if err != nil {
		t.Fatalf("taking the access list from %q: %v", sddl, err)
	}
	information := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if !strings.HasPrefix(sddl, "D:P") {
		information = windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, information, nil, nil, list, nil); err != nil {
		t.Fatalf("setting %s's access list to %q: %v", path, sddl, err)
	}
}

// removeAccessList gives a file no access list at all, a NULL DACL, which lets anyone do
// anything with it: not an empty list, which grants no one access.
func removeAccessList(t *testing.T, path string) {
	t.Helper()
	information := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, information, nil, nil, nil, nil); err != nil {
		t.Fatalf("removing %s's access list: %v", path, err)
	}
}

// openToOthers gives the key file no access list, which lets anyone reach it: a key file Open
// refuses as reachable once it reaches that check.
func openToOthers(t *testing.T, path string) {
	t.Helper()
	removeAccessList(t, path)
}

// protectKeyFile gives a key file the access list of a good one on Windows: protected from the
// folder's, with one entry, allowing the runner's own user full control.
func protectKeyFile(t *testing.T, path string) {
	t.Helper()
	setAccessList(t, path, "D:P(A;;FA;;;"+runnerSID(t)+")")
}

// makeUnopenable holds a file or folder open with no sharing until the row ends, so Open cannot
// open it. An access list cannot do this on CI: its elevated runner opens a file or folder whose
// access list is empty. Its token holds the backup privilege, enabled, and Go opens every file
// with backup intent, which gets past a hold that only reads; a hold that reads and writes
// refuses it. A folder held for reading refuses os.OpenRoot there (all seen on CI, 2026-11-03).
func makeUnopenable(t *testing.T, path string) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatalf("naming %s: %v", path, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("reading what %s is: %v", path, err)
	}
	var access uint32 = windows.GENERIC_READ
	if !info.IsDir() {
		access |= windows.GENERIC_WRITE
	}
	handle, err := windows.CreateFile(name, access, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatalf("holding %s open with no sharing: %v", path, err)
	}
	t.Cleanup(func() {
		if err := windows.CloseHandle(handle); err != nil {
			t.Errorf("closing %s: %v", path, err)
		}
	})
}

// linkOutside puts at link a junction to a folder outside the bootstrap folder: the link a
// Windows account makes without any privilege. A junction can lead only to a folder; the elevated
// rows link to a file outside with a symbolic link.
func linkOutside(t *testing.T, link string, contents []byte) {
	t.Helper()
	// cmd reads a comma as a space, and a row's folder carries its name's commas: mklink is given
	// names relative to a folder outside the bootstrap folder, never a full path.
	base := t.TempDir()
	target := filepath.Join(base, "outside")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("making the folder outside: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, filepath.Base(link)), contents, 0o600); err != nil {
		t.Fatalf("writing the file outside: %v", err)
	}
	relative, err := filepath.Rel(base, link)
	if err != nil {
		t.Fatalf("naming %s from %s: %v", link, base, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), testrun.Patient(testrun.HangBound))
	defer cancel()
	command := exec.CommandContext(ctx, "cmd", "/c", "mklink", "/J", relative, "outside")
	command.Dir = base
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("making a junction at %s: %v: %s", link, err, strings.TrimSpace(string(output)))
	}
}

// linkKinds names the way linkOutside links, for the rows' names.
const linkKinds = "a junction"

// setOwner makes the account sid a file's owner with icacls, from outside Open. Making another
// account the owner needs an elevated process.
func setOwner(t *testing.T, path, sid string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testrun.Patient(testrun.HangBound))
	defer cancel()
	if output, err := exec.CommandContext(ctx, "icacls", path, "/setowner", "*"+sid).CombinedOutput(); err != nil {
		t.Fatalf("making %s the owner of %s: %v: %s", sid, path, err, strings.TrimSpace(string(output)))
	}
}

// lockWhole holds an exclusive byte-range lock on the whole file through a handle of its own
// until the row ends: another handle then opens the file, but its read fails.
func lockWhole(t *testing.T, path string) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening %s to lock it: %v", path, err)
	}
	handle := windows.Handle(file.Fd())
	whole := uint32(0xFFFFFFFF)
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0,
		whole, whole, &windows.Overlapped{}); err != nil {
		_ = file.Close()
		t.Fatalf("locking %s: %v", path, err)
	}
	t.Cleanup(func() {
		if err := windows.UnlockFileEx(handle, 0, whole, whole, &windows.Overlapped{}); err != nil {
			t.Errorf("unlocking %s: %v", path, err)
		}
		if err := file.Close(); err != nil {
			t.Errorf("closing %s: %v", path, err)
		}
	})
}
