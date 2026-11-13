// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The program and its key file on Windows: the key file's owner and access list, set from
// outside with icacls and PowerShell, and a symbolic link to a file outside the folder.
package main_test

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsBootstrapProgram(t *testing.T) {
	t.Parallel()

	t.Run("If the bootstrap file's key holder is the key file and, on Windows, the key file's owner, or any entry of its access list that allows access, names anyone but SYSTEM, Administrators or the account the engine runs as, or the key file has no access list, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("an entry allowing Users to read, beside the account's own: one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			made := goodFolder(t)
			icacls(t, made.keyFile, "/grant", "*"+usersSID+":(R)")
			expectOwnReason(t, made.refused(t), keyMissingReason(t), "a missing key file")
		})
		t.Run("an entry allowing Everyone to read, inherited from the folder: one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			made := goodFolder(t)
			icacls(t, made.path, "/grant", "*"+everyoneSID+":(OI)(CI)(R)")
			removeFile(t, made.keyFile)
			if err := os.WriteFile(made.keyFile, []byte(made.keyText), 0o600); err != nil {
				t.Fatalf("writing the key file: %v", err)
			}
			expectOwnReason(t, made.refused(t), keyMissingReason(t), "a missing key file")
		})
		t.Run("no access list at all: one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			made := goodFolder(t)
			openToOthers(t, made.keyFile)
			expectOwnReason(t, made.refused(t), keyMissingReason(t), "a missing key file")
		})
		t.Run("SYSTEM, Administrators and the account, each allowed full control: it starts", func(t *testing.T) {
			t.Parallel()
			made := goodFolder(t)
			icacls(t, made.keyFile, "/grant", "*"+systemSID+":(F)", "*"+administratorsSID+":(F)")
			made.starts(t)
		})
		t.Run("the account alone, and an entry denying Everyone the right to delete: it starts", func(t *testing.T) {
			t.Parallel()
			made := goodFolder(t)
			icacls(t, made.keyFile, "/deny", "*"+everyoneSID+":(DE)")
			made.starts(t)
		})
	})

	t.Run("If the bootstrap file's key holder is the key file and the engine is unable to confirm that no account but those above has access to the key file, such as on Windows an access-list entry of a kind it does not judge, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("a conditional entry allowing Everyone to read when a member of Administrators, beside the account's own: one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			made := goodFolder(t)
			setAccessList(t, made.keyFile, conditionalAllow(t))
			reason := made.refused(t)
			expectOwnReason(t, reason, keyMissingReason(t), "a missing key file")
			reachable := goodFolder(t)
			icacls(t, reachable.keyFile, "/grant", "*"+usersSID+":(R)")
			expectOwnReason(t, reason, reachable.refused(t), "a key file Users may read")
		})
	})
}

// conditionalAllow is a key file's access list holding the account's own full control and a
// conditional entry allowing Everyone to read when a member of Administrators: an entry of a kind
// other than a plain allow entry.
func conditionalAllow(t *testing.T) string {
	t.Helper()
	return "D:P(A;;FA;;;" + runnerSID(t) + ")(XA;;FR;;;WD;(Member_of {SID(BA)}))"
}

// TestWindowsElevatedBootstrapProgram holds the rows only an elevated process can set up: another
// account as the key file's owner, and a symbolic link to a file. CI's Windows runner is
// elevated.
func TestWindowsElevatedBootstrapProgram(t *testing.T) {
	t.Parallel()

	t.Run("If the bootstrap file's key holder is the key file and, on Windows, the key file's owner, or any entry of its access list that allows access, names anyone but SYSTEM, Administrators or the account the engine runs as, or the key file has no access list, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("Users the owner, the access list the account's alone: one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			made := goodFolder(t)
			icacls(t, made.keyFile, "/setowner", "*"+usersSID)
			expectOwnReason(t, made.refused(t), keyMissingReason(t), "a missing key file")
		})
	})

	t.Run("If the bootstrap folder is missing or unreadable, the bootstrap file in it is missing, unreadable or a link leading out of the bootstrap folder, or, when the bootstrap file's key holder is the key file, the key file is, then the engine shall write one `start_failed` line saying which, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("the bootstrap file a symbolic link to a good one outside: one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			made := goodFolder(t)
			sealed, err := os.ReadFile(made.file)
			if err != nil {
				t.Fatalf("reading the bootstrap file: %v", err)
			}
			removeFile(t, made.file)
			symlinkOutside(t, made.file, sealed)
			expectOwnReason(t, made.refused(t), keyMissingReason(t), "a missing key file")
		})
		t.Run("the key file a symbolic link to a good one outside: one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			made := goodFolder(t)
			removeFile(t, made.keyFile)
			protectKeyFile(t, symlinkOutside(t, made.keyFile, []byte(made.keyText)))
			expectOwnReason(t, made.refused(t), fileMissingReason(t), "a missing bootstrap file")
		})
	})
}

// symlinkOutside puts at link a symbolic link to a file outside the bootstrap folder holding
// contents, and returns the file's path. Making one needs a privilege only an elevated process
// holds here.
func symlinkOutside(t *testing.T, link string, contents []byte) string {
	t.Helper()
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, contents, 0o600); err != nil {
		t.Fatalf("writing the file outside: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("linking %s to a file outside: %v", link, err)
	}
	return target
}
