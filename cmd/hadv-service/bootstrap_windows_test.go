// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main_test

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// The well-known accounts the rows name to icacls, by their SIDs.
const (
	systemSID         = "S-1-5-18"
	administratorsSID = "S-1-5-32-544"
	usersSID          = "S-1-5-32-545"
	everyoneSID       = "S-1-1-0"
)

// runnerSID is the SID of the account this test runs as, which the program it starts runs as
// too.
func runnerSID(t *testing.T) string {
	t.Helper()
	current, err := user.Current()
	if err != nil {
		t.Fatalf("reading this account: %v", err)
	}
	return current.Uid
}

// icacls runs icacls on path with the arguments given.
func icacls(t *testing.T, path string, arguments ...string) {
	t.Helper()
	runSystemTool(t, "icacls", append([]string{path}, arguments...)...)
}

// protectKeyFile gives a key file the access list of a good one on Windows: its inherited entries
// removed, and one entry allowing the runner's own account full control.
func protectKeyFile(t *testing.T, path string) {
	t.Helper()
	icacls(t, path, "/inheritance:r", "/grant:r", "*"+runnerSID(t)+":(F)")
}

// makeUnopenable holds a file or folder open with no sharing until the row ends, so the program
// cannot open it, whatever its account. An access list cannot do this on CI: its elevated runner
// opens a file or folder whose access list is empty (seen on CI, 2026-11-03).
func makeUnopenable(t *testing.T, path string) {
	t.Helper()
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatalf("naming %s: %v", path, err)
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ, 0, nil, syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatalf("holding %s open with no sharing: %v", path, err)
	}
	t.Cleanup(func() {
		if err := syscall.CloseHandle(handle); err != nil {
			t.Errorf("closing %s: %v", path, err)
		}
	})
}

// openToOthers gives the key file no access list at all, a NULL DACL, which lets anyone do
// anything with it.
func openToOthers(t *testing.T, path string) {
	t.Helper()
	setAccessList(t, path, "D:NO_ACCESS_CONTROL")
}

// setAccessList replaces a file's access list with the one sddl gives, for the lists icacls
// cannot write: none at all, or one holding a conditional entry. .NET's access list objects can,
// from PowerShell, given the path and the list in the environment, so no quoting is needed. Only
// the access list is read and written: Set-Acl writes the audit list too, which needs a privilege
// the runner's account lacks unelevated.
func setAccessList(t *testing.T, path, sddl string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testrun.Patient(testrun.HangBound))
	defer cancel()
	script := "$file = [System.IO.FileInfo]::new($env:HADV_KEY_FILE); " +
		"$list = $file.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access); " +
		"$list.SetSecurityDescriptorSddlForm($env:HADV_ACCESS_LIST, 'Access'); " +
		"$file.SetAccessControl($list)"
	command := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	command.Env = append(os.Environ(), "HADV_KEY_FILE="+path, "HADV_ACCESS_LIST="+sddl)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("setting %s's access list to %q: %v: %s", path, sddl, err, strings.TrimSpace(string(output)))
	}
}

// linkOutside puts at link a junction to a folder outside the bootstrap folder: the link a
// Windows account makes without any privilege. A junction can lead only to a folder.
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
