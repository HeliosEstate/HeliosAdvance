// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// The accounts a scheduled task runs a child as: the rows' service account, LOCAL SERVICE,
// and another, NETWORK SERVICE, as schtasks spells them.
const (
	taskServiceAccount = `NT AUTHORITY\LOCALSERVICE`
	taskOtherAccount   = `NT AUTHORITY\NETWORKSERVICE`
)

// heldKeyPairFunctions sets the access list of the machine key pair of the package's name in
// whichever provider holds it.
const heldKeyPairFunctions = `
function Set-HeldKeyPair($sddl) {
    $key = @(Get-KeyPairs)[0]
    $descriptor = New-Object Security.AccessControl.RawSecurityDescriptor $sddl
    $bytes = New-Object byte[] $descriptor.BinaryLength
    $descriptor.GetBinaryForm($bytes, 0)
    $key.SetProperty((New-Object Security.Cryptography.CngProperty 'Security Descr', $bytes, ([Security.Cryptography.CngPropertyOptions]5)))
    $key.Dispose()
}
`

// taskNumber keeps each child's scheduled task name its own.
var taskNumber atomic.Int64

// serviceBinary copies this test binary where the service accounts can run it: the copy
// Go built sits in the running account's own temporary folder.
func serviceBinary(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	folder := t.TempDir()
	binary := filepath.Join(folder, "bootstrap.test.exe")
	if err := os.WriteFile(binary, data, 0o700); err != nil { //nolint:gosec // a program the service accounts run
		t.Fatal(err)
	}
	powerShell(t, "Invoke-Icacls '"+folder+"' /grant '*"+serviceAccountSID+":(OI)(CI)RX' '*"+otherAccountSID+":(OI)(CI)RX'\n")
	return binary
}

// launchAs starts the binary as the account through a scheduled task of its own, made, run
// and deleted by this elevated process. A task's output goes nowhere, so there is none to read.
func launchAs(t *testing.T, binary, account, address string) func() string {
	t.Helper()
	name := fmt.Sprintf("helios-row-%d-%d", os.Getpid(), taskNumber.Add(1))
	command := `"` + binary + `" -test.run ^TestUnlockServiceChild$ -bootstrap.child=` + address
	if out, err := exec.CommandContext(t.Context(), "schtasks", "/Create", "/TN", name, "/TR", command,
		"/SC", "ONCE", "/ST", "00:00", "/RU", account, "/F").CombinedOutput(); err != nil {
		t.Fatalf("schtasks /Create: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("schtasks", "/Delete", "/TN", name, "/F").Run() //nolint:noctx // a cleanup runs after the test's context has ended
	})
	if out, err := exec.CommandContext(t.Context(), "schtasks", "/Run", "/TN", name).CombinedOutput(); err != nil {
		t.Fatalf("schtasks /Run: %v\n%s", err, out)
	}
	return func() string { return "" }
}

// serviceFolder is a folder as Build leaves it on Windows, every item set to its rule for the
// service account: the machine key pair, the bootstrap key sealed under it, the bootstrap file,
// and no lock.
func serviceFolder(t *testing.T) string {
	t.Helper()
	folder := sealedFolder(t)
	powerShell(t, "Set-Rule '"+folder+"' '"+serviceAccountSID+"' $true\n"+
		"Set-Rule '"+filepath.Join(folder, nameFile)+"' '"+serviceAccountSID+"' $false\n"+
		"Set-Rule '"+filepath.Join(folder, nameSealedKey)+"' '"+serviceAccountSID+"' $false\n")
	return folder
}

// writeAtRule writes a file in the folder, set to its rule for the service account.
func writeAtRule(t *testing.T, folder, name, contents string) string {
	t.Helper()
	path := filepath.Join(folder, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	powerShell(t, "Set-Rule '"+path+"' '"+serviceAccountSID+"' $false\n")
	return path
}

// TestWindowsElevatedUnlockService is the Windows rows. It runs on GitHub's Windows runner,
// whose job fails before the tests when the runner is not elevated, and on any elevated
// machine: making a folder at its rule, and a scheduled task, need an administrator. The rows
// run one after another: the machine key pair is one per machine.
//
//nolint:paralleltest // the machine key pair is one per machine
func TestWindowsElevatedUnlockService(t *testing.T) {
	if !elevated(t) {
		t.Skip("needs an elevated process: runs on GitHub's Windows runner, whose job fails when it is not elevated")
	}
	binary := serviceBinary(t)
	asService := func(t *testing.T, folder string, mode KeyMode) *serviceProcess {
		t.Helper()
		return startService(t, binary, taskServiceAccount, folder, mode)
	}

	t.Run(lineServiceOrder, func(t *testing.T) {
		t.Run("elevated, the lock held: WrongAccount before InUse", func(t *testing.T) {
			folder := serviceFolder(t)
			wantServiceUnlocked(t, asService(t, folder, ModeMachineKeyPair))
			handle, err := New().UnlockForService(t.Context(), folder, ModeMachineKeyPair)
			if handle != nil {
				handle.Close()
			}
			wantRefusal(t, err, WrongAccount)
		})
		t.Run("the lock held and the folder open to Users: InUse before LooserThanRule", func(t *testing.T) {
			folder := serviceFolder(t)
			wantServiceUnlocked(t, asService(t, folder, ModeMachineKeyPair))
			powerShell(t, "Invoke-Icacls '"+folder+"' /grant '*S-1-5-32-545:(OI)(CI)R'\n")
			wantServiceRefused(t, asService(t, folder, ModeMachineKeyPair), InUse)
		})
		t.Run("the bootstrap file a symbolic link and the folder open to Users: Link before LooserThanRule", func(t *testing.T) {
			folder := serviceFolder(t)
			linkInPlace(t, filepath.Join(folder, nameFile), false)
			powerShell(t, "Invoke-Icacls '"+folder+"' /grant '*S-1-5-32-545:(OI)(CI)R'\n")
			wantServiceRefused(t, asService(t, folder, ModeMachineKeyPair), Link)
		})
		t.Run("the folder open to Users and a half-made file: LooserThanRule, the half-made file kept", func(t *testing.T) {
			folder := serviceFolder(t)
			halfMade := writeAtRule(t, folder, nameFile+".new", "a half-made bootstrap file")
			powerShell(t, "Invoke-Icacls '"+folder+"' /grant '*S-1-5-32-545:(OI)(CI)R'\n")
			wantLooserNaming(t, asService(t, folder, ModeMachineKeyPair), ItemFolder, folder)
			wantStillThere(t, halfMade)
		})
		t.Run("a half-made file and no sealed key: the half-made file deleted, then KeyNotFound", func(t *testing.T) {
			folder := serviceFolder(t)
			halfMade := writeAtRule(t, folder, nameFile+".new", "a half-made bootstrap file")
			removeItem(t, filepath.Join(folder, nameSealedKey))
			wantServiceRefused(t, asService(t, folder, ModeMachineKeyPair), KeyNotFound)
			wantGone(t, halfMade)
		})
	})

	t.Run(lineServiceElevated, func(t *testing.T) {
		handle, err := New().UnlockForService(t.Context(), serviceFolder(t), ModeMachineKeyPair)
		if handle != nil {
			handle.Close()
		}
		wantRefusal(t, err, WrongAccount)
	})

	t.Run(lineServiceAccountWindows, func(t *testing.T) {
		t.Run("as NETWORK SERVICE, which the list does not name", func(t *testing.T) {
			wantServiceRefused(t, startService(t, binary, taskOtherAccount, serviceFolder(t), ModeMachineKeyPair), WrongAccount)
		})
		t.Run("as NETWORK SERVICE, the folder open to Users, which it belongs to: named only through a group", func(t *testing.T) {
			folder := serviceFolder(t)
			powerShell(t, "Invoke-Icacls '"+folder+"' /grant '*S-1-5-32-545:(OI)(CI)R'\n")
			wantServiceRefused(t, startService(t, binary, taskOtherAccount, folder, ModeMachineKeyPair), WrongAccount)
		})
		t.Run("let through this check: as NETWORK SERVICE, added by hand to every item's list", func(t *testing.T) {
			// Every item is then looser than its rule, so the permission check refuses: past
			// this line's check, and every item readable to judge.
			folder := serviceFolder(t)
			powerShell(t, keyStoreFunctions+heldKeyPairFunctions+"$folder = '"+folder+"'\n"+
				"Invoke-Icacls $folder /grant '*"+otherAccountSID+":(OI)(CI)F'\n"+
				"foreach ($name in 'bootstrap.hadv', 'bootstrap-key.sealed') { Invoke-Icacls (Join-Path $folder $name) /grant '*"+otherAccountSID+":F' }\n"+
				"Set-HeldKeyPair 'O:BAD:P(A;;GA;;;"+serviceAccountSID+")(A;;GA;;;"+otherAccountSID+")(A;;GA;;;SY)(A;;GA;;;BA)'\n")
			wantServiceRefused(t, startService(t, binary, taskOtherAccount, folder, ModeMachineKeyPair), LooserThanRule)
		})
		t.Run("let through: as LOCAL SERVICE, which the list names", func(t *testing.T) {
			wantServiceUnlocked(t, asService(t, serviceFolder(t), ModeMachineKeyPair))
		})
	})

	t.Run(lineServiceInUse, func(t *testing.T) {
		t.Run("another handle open", func(t *testing.T) {
			folder := serviceFolder(t)
			wantServiceUnlocked(t, asService(t, folder, ModeMachineKeyPair))
			wantServiceRefused(t, asService(t, folder, ModeMachineKeyPair), InUse)
		})
		t.Run("the lock held by another process every usual way", func(t *testing.T) {
			folder := serviceFolder(t)
			release := holdWindowsLock(t, writeAtRule(t, folder, nameLock, ""))
			defer release()
			wantServiceRefused(t, asService(t, folder, ModeMachineKeyPair), InUse)
		})
	})

	t.Run(lineServiceLockMade, func(t *testing.T) {
		folder := serviceFolder(t)
		process := asService(t, folder, ModeMachineKeyPair)
		wantServiceUnlocked(t, process)
		process.close(t)
		lock := filepath.Join(folder, nameLock)
		holdsWindowsRule(t, readItems(t, windowsFolder{path: folder, items: map[string]Item{lock: ItemOtherFile}}, "")[lock], serviceAccount)
	})

	t.Run(lineServiceLink, func(t *testing.T) {
		for _, row := range []struct {
			name string
			hard bool
		}{{"the bootstrap file a symbolic link", false}, {"the bootstrap file with a second name", true}} {
			t.Run(row.name, func(t *testing.T) {
				folder := serviceFolder(t)
				linkInPlace(t, filepath.Join(folder, nameFile), row.hard)
				wantServiceRefused(t, asService(t, folder, ModeMachineKeyPair), Link)
			})
		}
		t.Run("let through: the bootstrap file with one name", func(t *testing.T) {
			wantServiceUnlocked(t, asService(t, serviceFolder(t), ModeMachineKeyPair))
		})
	})

	t.Run(lineServiceLooser, func(t *testing.T) {
		for _, row := range []struct {
			name   string
			change string // PowerShell, with $folder set
			item   Item
			path   func(folder string) string
		}{
			{"the folder open to Users", "Invoke-Icacls $folder /grant '*S-1-5-32-545:(OI)(CI)R'", ItemFolder,
				func(folder string) string { return folder }},
			{"the bootstrap file inheriting", "Invoke-Icacls (Join-Path $folder 'bootstrap.hadv') /inheritance:e", ItemFile,
				func(folder string) string { return filepath.Join(folder, nameFile) }},
			{"the sealed-key file owned by NETWORK SERVICE", "Invoke-Icacls (Join-Path $folder 'bootstrap-key.sealed') /setowner '*S-1-5-20'", ItemOtherFile,
				func(folder string) string { return filepath.Join(folder, nameSealedKey) }},
			{"the lock open to Users", "Invoke-Icacls (Join-Path $folder 'bootstrap.lock') /grant '*S-1-5-32-545:R'", ItemOtherFile,
				func(folder string) string { return filepath.Join(folder, nameLock) }},
			{"the machine key pair open to Users", "Set-HeldKeyPair 'O:BAD:P(A;;GA;;;" + serviceAccountSID + ")(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;BU)'", ItemMachineKeyPair,
				func(string) string { return keyPairName }},
		} {
			t.Run(row.name, func(t *testing.T) {
				folder := serviceFolder(t)
				writeAtRule(t, folder, nameLock, "")
				powerShell(t, keyStoreFunctions+heldKeyPairFunctions+"$folder = '"+folder+"'\n"+row.change+"\n")
				wantLooserNaming(t, asService(t, folder, ModeMachineKeyPair), row.item, row.path(folder))
			})
		}
		for _, row := range []struct{ name, owner string }{
			{"let through: the bootstrap file owned by SYSTEM", "S-1-5-18"},
			{"let through: the bootstrap file owned by the account", serviceAccountSID},
		} {
			t.Run(row.name, func(t *testing.T) {
				folder := serviceFolder(t)
				powerShell(t, "Invoke-Icacls '"+filepath.Join(folder, nameFile)+"' /setowner '*"+row.owner+"'\n")
				wantServiceUnlocked(t, asService(t, folder, ModeMachineKeyPair))
			})
		}
	})

	t.Run(lineServiceNotWritable, func(t *testing.T) {
		t.Run("the bootstrap file granting the account read only", func(t *testing.T) {
			folder := serviceFolder(t)
			file := filepath.Join(folder, nameFile)
			powerShell(t, "Invoke-Icacls '"+file+"' /grant:r '*"+serviceAccountSID+":R'\n")
			wantNotWritableNaming(t, asService(t, folder, ModeMachineKeyPair), file)
		})
		t.Run("the folder granting the account read only", func(t *testing.T) {
			// The lock is there already, so taking it needs nothing written in the folder.
			folder := serviceFolder(t)
			writeAtRule(t, folder, nameLock, "")
			powerShell(t, "Invoke-Icacls '"+folder+"' /grant:r '*"+serviceAccountSID+":(OI)(CI)R'\n")
			wantNotWritableNaming(t, asService(t, folder, ModeMachineKeyPair), folder)
		})
	})

	t.Run(lineServiceHalfMade, func(t *testing.T) {
		folder := serviceFolder(t)
		halfMade := writeAtRule(t, folder, nameFile+".new", "a half-made bootstrap file")
		wantServiceUnlocked(t, asService(t, folder, ModeMachineKeyPair))
		wantGone(t, halfMade)
	})

	t.Run(lineServiceMode, func(t *testing.T) {
		for _, row := range []struct {
			name string
			mode KeyMode
		}{
			{"ModeKeyFile on Windows", ModeKeyFile},
			{"ModeContainer on Windows", ModeContainer},
			{"ModeSystemdAtStart on Windows", ModeSystemdAtStart},
			{"ModeSystemdPerUse on Windows", ModeSystemdPerUse},
		} {
			t.Run(row.name, func(t *testing.T) {
				wantServiceRefused(t, asService(t, serviceFolder(t), row.mode), SourceRefused)
			})
		}
		t.Run("let through: ModeMachineKeyPair on Windows", func(t *testing.T) {
			wantServiceUnlocked(t, asService(t, serviceFolder(t), ModeMachineKeyPair))
		})
	})

	t.Run(lineServiceKeyNotFound, func(t *testing.T) {
		folder := serviceFolder(t)
		removeItem(t, filepath.Join(folder, nameSealedKey))
		wantServiceRefused(t, asService(t, folder, ModeMachineKeyPair), KeyNotFound)
	})

	t.Run(lineServiceNotUnsealed, func(t *testing.T) {
		t.Run("the sealed key altered", func(t *testing.T) {
			folder := serviceFolder(t)
			sealed := filepath.Join(folder, nameSealedKey)
			data, err := os.ReadFile(sealed)
			if err != nil {
				t.Fatal(err)
			}
			data[len(data)/2] ^= 1
			if err := os.WriteFile(sealed, data, 0o600); err != nil {
				t.Fatal(err)
			}
			wantServiceRefused(t, asService(t, folder, ModeMachineKeyPair), KeyNotUnsealed)
		})
		t.Run("the machine key pair gone, the sealed key there", func(t *testing.T) {
			folder := serviceFolder(t)
			removeKeyPairs(t)
			wantServiceRefused(t, asService(t, folder, ModeMachineKeyPair), KeyNotUnsealed)
		})
	})

	t.Run(lineServiceFileNotFound, func(t *testing.T) {
		folder := serviceFolder(t)
		removeItem(t, filepath.Join(folder, nameFile))
		wantServiceRefused(t, asService(t, folder, ModeMachineKeyPair), FileNotFound)
	})

	t.Run(lineServiceHeldWindows, func(t *testing.T) {
		want, name := HeldInSoftwareKeyStore, "HeldInSoftwareKeyStore"
		if hasTPM(t) {
			want, name = HeldInTPM, "HeldInTPM"
		}
		wantServiceHolding(t, asService(t, serviceFolder(t), ModeMachineKeyPair), want, name)
	})

	t.Run(lineServiceHandle, func(t *testing.T) {
		folder := serviceFolder(t)
		first := asService(t, folder, ModeMachineKeyPair)
		wantServiceUnlocked(t, first)
		wantServiceRefused(t, asService(t, folder, ModeMachineKeyPair), InUse)
		first.close(t)
		wantServiceUnlocked(t, asService(t, folder, ModeMachineKeyPair))
	})
}
