// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// sealingFunctions makes what Build leaves on Windows, by the CNG key store itself: the machine
// key pair of the package's name, in the Platform Crypto Provider where there is a TPM and the
// Software Key Storage Provider where there is none, its access list naming the account,
// SYSTEM and Administrators, and the key sealed under it with RSA-OAEP SHA-256.
const sealingFunctions = `
function New-SealedKey($sealedPath, $keyBase64, $accountSid) {
    $parameters = New-Object Security.Cryptography.CngKeyCreationParameters
    $parameters.Provider = if ((Get-Tpm).TpmPresent) { New-Object Security.Cryptography.CngProvider 'Microsoft Platform Crypto Provider' } else { [Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider }
    $parameters.KeyCreationOptions = [Security.Cryptography.CngKeyCreationOptions]::MachineKey
    $parameters.Parameters.Add((New-Object Security.Cryptography.CngProperty 'Length', ([BitConverter]::GetBytes(2048)), ([Security.Cryptography.CngPropertyOptions]::None)))
    $key = [Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::Rsa, $keyName, $parameters)
    $descriptor = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:P(A;;GA;;;$accountSid)(A;;GA;;;SY)(A;;GA;;;BA)"
    $bytes = New-Object byte[] $descriptor.BinaryLength
    $descriptor.GetBinaryForm($bytes, 0)
    $key.SetProperty((New-Object Security.Cryptography.CngProperty 'Security Descr', $bytes, ([Security.Cryptography.CngPropertyOptions]5)))
    $rsa = New-Object Security.Cryptography.RSACng $key
    [IO.File]::WriteAllBytes($sealedPath, $rsa.Encrypt([Convert]::FromBase64String($keyBase64), [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256))
    $key.Dispose()
}
`

// sealedFolder is a folder on NTFS as Build leaves it on Windows: a machine key pair, the
// bootstrap key sealed under it, and a bootstrap file sealed under that key. Every machine key
// pair of the package's name is removed before and after the row.
func sealedFolder(t *testing.T) string {
	t.Helper()
	removeKeyPairs(t)
	t.Cleanup(func() { removeKeyPairs(t) })
	folder := filepath.Join(t.TempDir(), "folder")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	key := rowKey(2)
	powerShell(t, keyStoreFunctions+sealingFunctions+"New-SealedKey '"+filepath.Join(folder, nameSealedKey)+"' '"+
		base64.StdEncoding.EncodeToString(key)+"' '"+serviceAccountSID+"'\n")
	writeGoodFile(t, filepath.Join(folder, nameFile), key)
	return folder
}

// holdsWindowsRule fails the row unless the item holds its rule for the account: the account,
// SYSTEM and Administrators only, no inherited access, owned by one of the three.
func holdsWindowsRule(t *testing.T, got Permissions, account string) {
	t.Helper()
	want := windowsRule(account)
	owners := []string{account, accountSystem, accountAdmins}
	if !slices.Contains(owners, got.Owner) || got.Inherited ||
		!slices.Equal(slices.Sorted(slices.Values(got.Accounts)), slices.Sorted(slices.Values(want.Accounts))) {
		t.Errorf("found %+v, want its rule: %v only, not inherited, owned by one of them", got, want.Accounts)
	}
}

// TestWindowsNotElevatedUnlockSetup runs where the process is not elevated: the loop's machine
// and the developer's, from a limited task. GitHub's runner is elevated, so it skips there.
func TestWindowsNotElevatedUnlockSetup(t *testing.T) {
	t.Parallel()
	if elevated(t) {
		t.Skip("needs a process that is not elevated: runs on the loop's machine and the developer's")
	}
	t.Run(lineSetupNotElevated, func(t *testing.T) {
		t.Parallel()
		folder := filepath.Join(t.TempDir(), "folder")
		if err := os.Mkdir(folder, 0o700); err != nil {
			t.Fatal(err)
		}
		writeGoodFile(t, filepath.Join(folder, nameFile), rowKey(2))
		if err := os.WriteFile(filepath.Join(folder, nameSealedKey), make([]byte, 256), 0o600); err != nil {
			t.Fatal(err)
		}
		handle, err := unlockSetup(t, folder, ModeMachineKeyPair)
		wantRefused(t, handle, err, NotElevated)
	})
}

// TestWindowsElevatedUnlockSetup is the Windows rows. It runs on GitHub's Windows runner, whose
// job fails before the tests when the runner is not elevated, and on any elevated machine. The
// rows run one after another: the machine key pair is one per machine.
//
//nolint:paralleltest // the machine key pair is one per machine
func TestWindowsElevatedUnlockSetup(t *testing.T) {
	if !elevated(t) {
		t.Skip("needs an elevated process: runs on GitHub's Windows runner, whose job fails when it is not elevated")
	}

	t.Run(lineHandleHolding, func(t *testing.T) {
		folder := sealedFolder(t)
		want, name := HeldInSoftwareKeyStore, "HeldInSoftwareKeyStore"
		if hasTPM(t) {
			want, name = HeldInTPM, "HeldInTPM"
		}
		handle, err := unlockSetup(t, folder, ModeMachineKeyPair)
		if got := wantUnlocked(t, handle, err).Holding(); got != want {
			t.Errorf("Holding is %d, want %s (%d)", got, name, want)
		}
	})

	t.Run(lineSetupHandle, func(t *testing.T) {
		folder := sealedFolder(t)
		handle, err := unlockSetup(t, folder, ModeMachineKeyPair)
		handle = wantUnlocked(t, handle, err)
		other, err := unlockSetup(t, folder, ModeMachineKeyPair)
		wantRefused(t, other, err, InUse)
		handle.Close()
		after, err := unlockSetup(t, folder, ModeMachineKeyPair)
		wantUnlocked(t, after, err)
	})

	t.Run(lineSetupLockMade, func(t *testing.T) {
		// The folder is set to its rule for the service account and has no lock, as Build
		// leaves it on Windows. The lock's rule is for the account given, whoever else the
		// folder's list names: a folder open to Everyone is looser than its rule and not refused.
		// Windows keeps the list sorted, and Everyone comes before the account in it.
		for _, row := range []struct{ name, loosen string }{
			{"the folder at its rule", ""},
			{"the folder also open to Everyone", "Invoke-Icacls $folder /grant '*S-1-1-0:(OI)(CI)R'\n"},
		} {
			t.Run(row.name, func(t *testing.T) {
				folder := sealedFolder(t)
				powerShell(t, "$folder = '"+folder+"'\nSet-Rule $folder '"+serviceAccountSID+"' $true\n"+row.loosen)
				handle, err := unlockSetup(t, folder, ModeMachineKeyPair)
				wantUnlocked(t, handle, err).Close()
				lock := filepath.Join(folder, nameLock)
				got := readItems(t, windowsFolder{path: folder, items: map[string]Item{lock: ItemOtherFile}}, "")[lock]
				holdsWindowsRule(t, got, serviceAccount)
			})
		}
	})

	t.Run(lineSetupLink, func(t *testing.T) {
		for _, row := range []struct {
			name string
			hard bool
		}{{"the bootstrap file a symbolic link", false}, {"the bootstrap file with a second name", true}} {
			t.Run(row.name, func(t *testing.T) {
				folder := sealedFolder(t)
				item := filepath.Join(folder, nameFile)
				elsewhere := filepath.Join(t.TempDir(), "elsewhere")
				if err := os.Rename(item, elsewhere); err != nil {
					t.Fatal(err)
				}
				link := os.Symlink
				if row.hard {
					link = os.Link
				}
				if err := link(elsewhere, item); err != nil {
					t.Fatal(err)
				}
				handle, err := unlockSetup(t, folder, ModeMachineKeyPair)
				wantRefused(t, handle, err, Link)
			})
		}
	})

	t.Run(lineSetupLooser, func(t *testing.T) {
		folder := sealedFolder(t)
		powerShell(t, "Invoke-Icacls '"+filepath.Join(folder, nameFile)+"' /grant '*S-1-5-32-545:R'\n")
		handle, err := unlockSetup(t, folder, ModeMachineKeyPair)
		wantUnlocked(t, handle, err)
	})

	t.Run(lineSetupHalfMade, func(t *testing.T) {
		folder := sealedFolder(t)
		halfMade := filepath.Join(folder, nameFile+".new")
		if err := os.WriteFile(halfMade, []byte("a half-made bootstrap file"), 0o600); err != nil {
			t.Fatal(err)
		}
		handle, err := unlockSetup(t, folder, ModeMachineKeyPair)
		wantUnlocked(t, handle, err)
		if _, err := os.Lstat(halfMade); err == nil {
			t.Error("bootstrap.hadv.new is still in the folder")
		}
	})

	t.Run(lineSetupMode, func(t *testing.T) {
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
				handle, err := unlockSetup(t, sealedFolder(t), row.mode)
				wantRefused(t, handle, err, SourceRefused)
			})
		}
		t.Run("let through: ModeMachineKeyPair on Windows", func(t *testing.T) {
			handle, err := unlockSetup(t, sealedFolder(t), ModeMachineKeyPair)
			wantUnlocked(t, handle, err)
		})
	})

	t.Run(lineSetupKeyNotFound, func(t *testing.T) {
		folder := sealedFolder(t)
		if err := os.Remove(filepath.Join(folder, nameSealedKey)); err != nil {
			t.Fatal(err)
		}
		handle, err := unlockSetup(t, folder, ModeMachineKeyPair)
		wantRefused(t, handle, err, KeyNotFound)
	})

	t.Run(lineSetupNotUnsealed, func(t *testing.T) {
		t.Run("the sealed key altered", func(t *testing.T) {
			folder := sealedFolder(t)
			sealed := filepath.Join(folder, nameSealedKey)
			data, err := os.ReadFile(sealed)
			if err != nil {
				t.Fatal(err)
			}
			data[len(data)/2] ^= 1
			if err := os.WriteFile(sealed, data, 0o600); err != nil {
				t.Fatal(err)
			}
			handle, err := unlockSetup(t, folder, ModeMachineKeyPair)
			wantRefused(t, handle, err, KeyNotUnsealed)
		})
		t.Run("the machine key pair gone, the sealed key there", func(t *testing.T) {
			folder := sealedFolder(t)
			removeKeyPairs(t)
			handle, err := unlockSetup(t, folder, ModeMachineKeyPair)
			wantRefused(t, handle, err, KeyNotUnsealed)
		})
	})

	t.Run(lineSetupFileNotFound, func(t *testing.T) {
		folder := sealedFolder(t)
		if err := os.Remove(filepath.Join(folder, nameFile)); err != nil {
			t.Fatal(err)
		}
		handle, err := unlockSetup(t, folder, ModeMachineKeyPair)
		wantRefused(t, handle, err, FileNotFound)
	})
}
