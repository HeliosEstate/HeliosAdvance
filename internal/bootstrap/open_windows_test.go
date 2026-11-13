// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Open's lines on Windows: the key file's owner and access list, a read that fails after the
// open, a link to a file outside the folder, and the folder and files closed on return. The
// access lists are set from outside Open, by name, as SDDL.
package bootstrap_test

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/heliosestate/heliosadvance/internal/bootstrap"
)

// writeKeyAsIs writes the key file's text and leaves its access list as the folder gives it.
func (made *layout) writeKeyAsIs(t *testing.T, text string) {
	t.Helper()
	if err := os.WriteFile(made.keyFile, []byte(text), 0o600); err != nil {
		t.Fatalf("writing the key file: %v", err)
	}
}

func TestWindowsOpen(t *testing.T) {
	t.Parallel()

	t.Run("If, on Windows, the key file's owner, or any entry of its access list that allows access, whether the file's own or inherited, names anyone but SYSTEM (S-1-5-18), Administrators (S-1-5-32-544) or the user of the engine's own token, or the key file has no access list, then Open shall return ErrKeyFileReachable. An entry that denies access is not counted.", func(t *testing.T) {
		t.Parallel()
		t.Run("an entry allowing Users to read, beside the user's own: ErrKeyFileReachable", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			setAccessList(t, made.keyFile, "D:P(A;;FA;;;"+runnerSID(t)+")(A;;FR;;;"+sddlUsers+")")
			made.expectRefused(t, bootstrap.ErrKeyFileReachable)
		})
		t.Run("an entry allowing Everyone to read, inherited from the folder: ErrKeyFileReachable", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			setAccessList(t, made.folder, "D:P(A;OICI;FA;;;"+runnerSID(t)+")(A;OICI;FR;;;"+sddlEveryone+")")
			remove(t, made.keyFile)
			made.writeKeyAsIs(t, made.keyText)
			made.expectRefused(t, bootstrap.ErrKeyFileReachable)
		})
		t.Run("no access list at all: ErrKeyFileReachable", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			removeAccessList(t, made.keyFile)
			made.expectRefused(t, bootstrap.ErrKeyFileReachable)
		})
		t.Run("SYSTEM, Administrators and the user, each allowed full control: opens", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			setAccessList(t, made.keyFile, "D:P(A;;FA;;;"+sddlSystem+")(A;;FA;;;"+sddlAdministrators+")(A;;FA;;;"+runnerSID(t)+")")
			made.expectOpened(t)
		})
		t.Run("the user alone, and an entry denying Everyone the right to delete: opens", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			setAccessList(t, made.keyFile, "D:P(D;;SD;;;"+sddlEveryone+")(A;;FA;;;"+runnerSID(t)+")")
			made.expectOpened(t)
		})
	})

	t.Run("If reading the key file's owner or permissions fails, or, on Windows, an entry of its access list that allows access is of a kind other than a plain allow entry, such as a conditional entry, then Open shall return ErrKeyFilePermissions.", func(t *testing.T) {
		t.Parallel()
		t.Run("a conditional entry allowing Everyone to read when a member of Administrators, beside the user's own: ErrKeyFilePermissions", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			setAccessList(t, made.keyFile, "D:P(A;;FA;;;"+runnerSID(t)+")(XA;;FR;;;"+sddlEveryone+";(Member_of {SID("+sddlAdministrators+")}))")
			made.expectRefused(t, bootstrap.ErrKeyFilePermissions)
		})
		t.Run("a conditional entry denying Everyone the right to delete, beside the user's own: an entry that denies is not judged, opens", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			setAccessList(t, made.keyFile, "D:P(XD;;SD;;;"+sddlEveryone+";(Member_of {SID("+sddlUsers+")}))(A;;FA;;;"+runnerSID(t)+")")
			made.expectOpened(t)
		})
	})

	t.Run("Open shall check in the order of these lines and return the first refusal that applies.", func(t *testing.T) {
		t.Parallel()
		t.Run("a conditional entry and an entry allowing Users to read: ErrKeyFilePermissions, not ErrKeyFileReachable", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			setAccessList(t, made.keyFile, "D:P(A;;FA;;;"+runnerSID(t)+")(A;;FR;;;"+sddlUsers+")(XA;;FR;;;"+sddlEveryone+";(Member_of {SID("+sddlAdministrators+")}))")
			made.expectRefused(t, bootstrap.ErrKeyFilePermissions)
		})
		t.Run("the key file with no access list and locked by another handle: ErrKeyFileReachable, not ErrKeyFileUnreadable", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			removeAccessList(t, made.keyFile)
			lockWhole(t, made.keyFile)
			made.expectRefused(t, bootstrap.ErrKeyFileReachable)
		})
	})

	t.Run("If the bootstrap file will not open or read, is not a regular file, or is a link leading out of the bootstrap folder, then Open shall return ErrFileUnreadable.", func(t *testing.T) {
		t.Parallel()
		t.Run("a good bootstrap file that opens but will not read, locked by another handle: ErrFileUnreadable", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			lockWhole(t, made.file)
			made.expectRefused(t, bootstrap.ErrFileUnreadable)
		})
	})

	t.Run("If reading the key file fails, then Open shall return ErrKeyFileUnreadable.", func(t *testing.T) {
		t.Parallel()
		t.Run("a good key file that opens but will not read, locked by another handle: ErrKeyFileUnreadable", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			lockWhole(t, made.keyFile)
			made.expectRefused(t, bootstrap.ErrKeyFileUnreadable)
		})
	})

	t.Run("When it returns, Open shall have closed the bootstrap folder and the files it opened, and freed every key store handle it opened.", func(t *testing.T) {
		t.Parallel()
		for name, way := range closingOutcomes() {
			t.Run(name+": the folder and each file there open with no sharing at once", func(t *testing.T) {
				t.Parallel()
				made := way.reach(t)
				for _, path := range []string{made.folder, made.file, made.keyFile} {
					if _, err := os.Lstat(path); err != nil {
						continue
					}
					if err := openAlone(path); err != nil {
						t.Fatalf("%s is still open after Open returned: %v", filepath.Base(path), err)
					}
				}
			})
		}
	})
}

// openAlone opens path, a file or a folder, with no sharing at all, and closes it: it fails while
// any other handle is open on it, however that handle shares (probe, 2026-11-03).
func openAlone(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	return windows.CloseHandle(handle)
}

// TestWindowsElevatedOpen holds the rows only an elevated process can set up: another account as
// the key file's owner, and a symbolic link to a file. CI's Windows runner is elevated.
func TestWindowsElevatedOpen(t *testing.T) {
	t.Parallel()

	t.Run("If, on Windows, the key file's owner, or any entry of its access list that allows access, whether the file's own or inherited, names anyone but SYSTEM (S-1-5-18), Administrators (S-1-5-32-544) or the user of the engine's own token, or the key file has no access list, then Open shall return ErrKeyFileReachable. An entry that denies access is not counted.", func(t *testing.T) {
		t.Parallel()
		t.Run("Users the owner, the access list the user's alone: ErrKeyFileReachable", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			setOwner(t, made.keyFile, usersSID)
			made.expectRefused(t, bootstrap.ErrKeyFileReachable)
		})
	})

	t.Run("If the bootstrap file will not open or read, is not a regular file, or is a link leading out of the bootstrap folder, then Open shall return ErrFileUnreadable.", func(t *testing.T) {
		t.Parallel()
		t.Run("a symbolic link to a good bootstrap file outside the folder: ErrFileUnreadable", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			sealed := made.sealed
			remove(t, made.file)
			symlinkOutside(t, made.file, sealed)
			made.expectRefused(t, bootstrap.ErrFileUnreadable)
		})
	})

	t.Run("If the key file will not open, is not a regular file, or is a link leading out of the bootstrap folder, then Open shall return ErrKeyFileUnreadable.", func(t *testing.T) {
		t.Parallel()
		t.Run("a symbolic link to a good key file outside the folder: ErrKeyFileUnreadable", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			remove(t, made.keyFile)
			outside := symlinkOutside(t, made.keyFile, []byte(made.keyText))
			protectKeyFile(t, outside)
			made.expectRefused(t, bootstrap.ErrKeyFileUnreadable)
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
