// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"
)

// keyStoreFunctions is the PowerShell the Windows rows read the CNG key store with: the
// machine key pair of the package's name in either provider, and opening a sealed key with
// it. A key pair is named by its public half, so a replaced one is told from the old.
const keyStoreFunctions = `
$providers = 'Microsoft Software Key Storage Provider', 'Microsoft Platform Crypto Provider'
function Get-KeyPairs {
    foreach ($name in $providers) {
        $provider = New-Object Security.Cryptography.CngProvider $name
        $exists = $false
        try { $exists = [Security.Cryptography.CngKey]::Exists($keyName, $provider, [Security.Cryptography.CngKeyOpenOptions]::MachineKey) } catch { }
        if ($exists) { [Security.Cryptography.CngKey]::Open($keyName, $provider, [Security.Cryptography.CngKeyOpenOptions]::MachineKey) }
    }
}
function Write-KeyPairs {
    $found = @(foreach ($key in Get-KeyPairs) {
        $descriptor = New-Object Security.AccessControl.RawSecurityDescriptor ($key.GetProperty('Security Descr', [Security.Cryptography.CngPropertyOptions]5).GetValue()), 0
        $allowed = @($descriptor.DiscretionaryAcl | Where-Object { $_.AceQualifier -eq 'AccessAllowed' } | ForEach-Object { $_.SecurityIdentifier.Value })
        New-Object PSObject -Property @{
            provider = $key.Provider.Provider; size = $key.KeySize; exportPolicy = [int]$key.ExportPolicy; allowed = @($allowed | Sort-Object -Unique)
            publicHalf = [Convert]::ToBase64String($key.Export([Security.Cryptography.CngKeyBlobFormat]::GenericPublicBlob))
        }
        $key.Dispose()
    })
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $found -Compress -Depth 3))
}
function Remove-KeyPairs { foreach ($key in Get-KeyPairs) { $key.Delete() } }
function New-OldKeyPair {
    $parameters = New-Object Security.Cryptography.CngKeyCreationParameters
    $parameters.Provider = [Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
    $parameters.KeyCreationOptions = [Security.Cryptography.CngKeyCreationOptions]::MachineKey
    $parameters.Parameters.Add((New-Object Security.Cryptography.CngProperty 'Length', ([BitConverter]::GetBytes(2048)), ([Security.Cryptography.CngPropertyOptions]::None)))
    [Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::Rsa, $keyName, $parameters).Dispose()
}
function Open-Sealed($path) {
    $key = @(Get-KeyPairs)[0]
    $rsa = New-Object Security.Cryptography.RSACng $key
    [Console]::Out.WriteLine([Convert]::ToBase64String($rsa.Decrypt([IO.File]::ReadAllBytes($path), [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)))
}
function Write-HasTpm { [Console]::Out.WriteLine((Get-Tpm).TpmPresent) }
`

// hasTPM reports whether this machine has a TPM, which decides the provider a machine key
// pair is made in.
func hasTPM(t *testing.T) bool {
	t.Helper()
	return saysTrue(powerShell(t, keyStoreFunctions+"Write-HasTpm\n"))
}

// storedKeyPair is one machine key pair of the package's name, as the key store reports it.
type storedKeyPair struct {
	Provider     string   `json:"provider"`
	Size         int      `json:"size"`
	ExportPolicy int      `json:"exportPolicy"`
	Allowed      []string `json:"allowed"`
	PublicHalf   string   `json:"publicHalf"`
}

// keyPairs is every machine key pair of the package's name, in either provider.
func keyPairs(t *testing.T) []storedKeyPair {
	t.Helper()
	var found []storedKeyPair
	if err := json.Unmarshal(powerShell(t, keyStoreFunctions+"Write-KeyPairs\n"), &found); err != nil {
		t.Fatalf("reading the key store: %v", err)
	}
	return found
}

// theKeyPair is the one machine key pair of the package's name, failing the row unless there
// is exactly one.
func theKeyPair(t *testing.T) storedKeyPair {
	t.Helper()
	found := keyPairs(t)
	if len(found) != 1 {
		t.Fatalf("found %d machine key pairs of the package's name, want 1: %+v", len(found), found)
	}
	return found[0]
}

// removeKeyPairs deletes every machine key pair of the package's name, in either provider.
// It runs as a cleanup too, after the test's context has ended, so it takes no context.
func removeKeyPairs(t *testing.T) {
	t.Helper()
	units := utf16.Encode([]rune(oracleFunctions + keyStoreFunctions + "Remove-KeyPairs\n"))
	encoded := make([]byte, 2*len(units))
	for i, unit := range units {
		binary.LittleEndian.PutUint16(encoded[2*i:], unit)
	}
	command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded)) //nolint:noctx // a cleanup runs after the test's context has ended
	command.Env = windowsPowerShellEnvironment()
	if out, err := command.CombinedOutput(); err != nil {
		t.Errorf("deleting the machine key pairs: %v\n%s", err, out)
	}
}

// buildWindowsStore builds from the OS credential store in a folder of its own, with no
// machine key pair of the package's name beforehand unless old is set, and removes every one
// when the row ends.
func buildWindowsStore(t *testing.T, path BuildPath, old bool) (string, KeyMode, error) {
	t.Helper()
	removeKeyPairs(t)
	t.Cleanup(func() { removeKeyPairs(t) })
	if old {
		powerShell(t, keyStoreFunctions+"New-OldKeyPair\n")
	}
	folder := filepath.Join(t.TempDir(), "folder")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	mode, err := build(t, folder, rowFields(), path, FromOSStore)
	return folder, mode, err
}

// TestWindowsElevatedBuildStore is the Windows rows. It runs on GitHub's Windows runner, whose
// job fails before the tests when the runner is not elevated, and on any elevated machine. The
// rows run one after another: the machine key pair is one per machine.
//
//nolint:paralleltest // the machine key pair is one per machine
func TestWindowsElevatedBuildStore(t *testing.T) {
	if !elevated(t) {
		t.Skip("needs an elevated process: runs on GitHub's Windows runner, whose job fails when it is not elevated")
	}

	t.Run(lineStoreWindowsMode, func(t *testing.T) {
		_, mode, err := buildWindowsStore(t, FirstSetup, false)
		if err != nil {
			t.Fatalf("refused: %v", err)
		}
		if mode != ModeMachineKeyPair {
			t.Errorf("returned mode %d, want %d", mode, ModeMachineKeyPair)
		}
	})

	t.Run(lineStoreRSA, func(t *testing.T) {
		if _, _, err := buildWindowsStore(t, FirstSetup, false); err != nil {
			t.Fatalf("refused: %v", err)
		}
		key := theKeyPair(t)
		if key.Size != 2048 {
			t.Errorf("a key of %d bits, want 2048", key.Size)
		}
		if key.ExportPolicy != 0 {
			t.Errorf("export policy %d, want none (0)", key.ExportPolicy)
		}
	})

	t.Run(lineStoreSoftware, func(t *testing.T) {
		if hasTPM(t) {
			t.Skip("this machine has a TPM: the row runs on GitHub's Windows runner, which has none")
		}
		if _, _, err := buildWindowsStore(t, FirstSetup, false); err != nil {
			t.Fatalf("refused: %v", err)
		}
		if key := theKeyPair(t); key.Provider != "Microsoft Software Key Storage Provider" {
			t.Errorf("made in %q, want the Microsoft Software Key Storage Provider", key.Provider)
		}
	})

	t.Run(lineStoreAccess, func(t *testing.T) {
		if _, _, err := buildWindowsStore(t, FirstSetup, false); err != nil {
			t.Fatalf("refused: %v", err)
		}
		want := []string{"S-1-5-18", serviceAccountSID, "S-1-5-32-544"}
		slices.Sort(want)
		if got := theKeyPair(t).Allowed; !slices.Equal(got, want) {
			t.Errorf("the access list names %v, want only %v (the account, SYSTEM, Administrators)", got, want)
		}
	})

	t.Run(lineStoreSealed, func(t *testing.T) {
		folder, _, err := buildWindowsStore(t, FirstSetup, false)
		if err != nil {
			t.Fatalf("refused: %v", err)
		}
		sealed := filepath.Join(folder, nameSealedKey)
		data, err := os.ReadFile(sealed)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) != 256 {
			t.Fatalf("%s holds %d bytes, want 256", sealed, len(data))
		}
		opened := strings.TrimSpace(string(powerShell(t, keyStoreFunctions+"Open-Sealed '"+sealed+"'\n")))
		key, err := base64.StdEncoding.DecodeString(opened)
		if err != nil || len(key) != 32 {
			t.Fatalf("the key store opened %d bytes, want the 32-byte bootstrap key: %v", len(key), err)
		}
		// The bootstrap file opens under what the sealed key holds, read by the format's
		// own reader, which the oracle's samples prove; Windows runs no containers.
		file, err := os.ReadFile(filepath.Join(folder, nameFile))
		if err != nil {
			t.Fatal(err)
		}
		opener, err := openFile(bytes.NewReader(file), int64(len(file)), key)
		if err != nil {
			t.Fatalf("the bootstrap file does not open under the sealed key: %v", err)
		}
		sameFields(t, opener.fields(), rowFields())
	})

	t.Run(lineStoreExists, func(t *testing.T) {
		for _, path := range []struct {
			name string
			path BuildPath
		}{{"FirstSetup", FirstSetup}, {"Joining", Joining}} {
			t.Run(path.name, func(t *testing.T) {
				_, _, err := buildWindowsStore(t, path.path, true)
				wantRefusal(t, err, MachineKeyPairExists)
			})
		}
	})

	t.Run(lineStoreReplace, func(t *testing.T) {
		for _, path := range []struct {
			name string
			path BuildPath
		}{{"JoiningAgain", JoiningAgain}, {"Restore", Restore}} {
			t.Run(path.name, func(t *testing.T) {
				removeKeyPairs(t)
				t.Cleanup(func() { removeKeyPairs(t) })
				powerShell(t, keyStoreFunctions+"New-OldKeyPair\n")
				old := theKeyPair(t).PublicHalf
				folder := filepath.Join(t.TempDir(), "folder")
				if err := os.Mkdir(folder, 0o700); err != nil {
					t.Fatal(err)
				}
				if _, err := build(t, folder, rowFields(), path.path, FromOSStore); err != nil {
					t.Fatalf("refused: %v", err)
				}
				if theKeyPair(t).PublicHalf == old {
					t.Error("the old machine key pair is still the one of the package's name")
				}
			})
		}
	})
}
