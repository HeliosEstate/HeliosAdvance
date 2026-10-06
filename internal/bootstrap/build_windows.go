// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

const sealedKeyFileName = "bootstrap-key.sealed"

func buildOnPlatform(ctx context.Context, folder string, fields Fields, path BuildPath, account string, source KeySource) (KeyMode, error) {
	if !isElevated() {
		return 0, &Refusal{Cause: NotElevated}
	}
	if source == FromKeyFile || source == FromContainer || (source != FromOSStore) {
		return 0, &Refusal{Cause: SourceRefused}
	}
	if err := validateFields(fields); err != nil {
		return 0, err
	}
	directory, err := openFolder(folder)
	if err != nil {
		return 0, err
	}
	defer func() { _ = directory.Close() }() //nolint:errcheck // no writes are buffered on the folder handle
	if err := setToRule(Finding{Item: ItemFolder, Path: folder}, account); err != nil {
		return 0, err
	}
	service, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return 0, fmt.Errorf("bootstrap: the account %s: %w", account, err)
	}
	keyPair, exists, err := openKeyPair()
	if err != nil {
		return 0, err
	}
	if exists {
		keyPair.close()
		if path == FirstSetup || path == Joining {
			return 0, &Refusal{Cause: MachineKeyPairExists}
		}
		if err := windowsKeyPair(ctx, "remove", "", ""); err != nil {
			return 0, err
		}
	}
	if _, err := os.Lstat(filepath.Join(folder, bootstrapFileName)); err == nil && (path == FirstSetup || path == Joining) {
		return 0, &Refusal{Cause: FileExists}
	} else if err != nil && !os.IsNotExist(err) {
		return 0, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return 0, fmt.Errorf("bootstrap: making the bootstrap key: %w", err)
	}
	defer clear(key)
	sealed := filepath.Join(folder, sealedKeyFileName)
	keyFile, err := os.CreateTemp(folder, ".bootstrap-key-")
	if err != nil {
		return 0, err
	}
	keyPath := keyFile.Name()
	defer func() { _ = os.Remove(keyPath) }() //nolint:errcheck // the temporary plaintext key must not remain
	if err := keyFile.Chmod(0o600); err != nil {
		_ = keyFile.Close() //nolint:errcheck // return the chmod error
		return 0, err
	}
	if _, err := keyFile.Write(key); err != nil {
		_ = keyFile.Close() //nolint:errcheck // return the write error
		return 0, err
	}
	if err := keyFile.Close(); err != nil {
		return 0, err
	}
	sealedFile, err := os.OpenFile(sealed, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // the folder was opened and checked above
	if err != nil {
		return 0, err
	}
	if err := sealedFile.Close(); err != nil {
		return 0, err
	}
	keyPairMade, sealedMade := false, true
	defer func(cleanupContext context.Context) {
		if keyPairMade {
			_ = windowsKeyPair(cleanupContext, "remove", "", "") //nolint:errcheck // preserve the build error
		}
		if sealedMade {
			_ = os.Remove(sealed) //nolint:errcheck // a failed build must not leave the sealed key
		}
	}(context.WithoutCancel(ctx))
	if err := setToRule(Finding{Item: ItemOtherFile, Path: sealed}, account); err != nil {
		return 0, err
	}
	if err := windowsKeyPair(ctx, "create", keyPath, service.String()); err != nil {
		return 0, err
	}
	keyPairMade = true
	file := &bootstrapFile{}
	file.setFields(fields)
	newPath := filepath.Join(folder, bootstrapFileName+".new")
	output, err := os.OpenFile(newPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600) //nolint:gosec // the folder was opened and checked above
	if err != nil {
		return 0, err
	}
	removeNew := true
	defer func() {
		if removeNew {
			_ = os.Remove(newPath) //nolint:errcheck // remove the incomplete build file
		}
	}()
	if err := setToRule(Finding{Item: ItemOtherFile, Path: newPath}, account); err != nil {
		_ = output.Close() //nolint:errcheck // return the ACL error
		return 0, err
	}
	if err := file.writeTo(output, key); err != nil {
		_ = output.Close() //nolint:errcheck // return the write error
		return 0, &Refusal{Cause: RewriteFailed}
	}
	if err := output.Sync(); err != nil {
		_ = output.Close() //nolint:errcheck // return the sync error
		return 0, &Refusal{Cause: RewriteFailed}
	}
	info, err := output.Stat()
	if err == nil {
		_, err = output.Seek(0, 0)
	}
	if err == nil {
		_, err = openFile(output, info.Size(), key)
	}
	_ = output.Close() //nolint:errcheck // read-back is complete
	if err != nil {
		return 0, &Refusal{Cause: RewriteFailed}
	}
	if err := os.Rename(newPath, filepath.Join(folder, bootstrapFileName)); err != nil {
		return 0, &Refusal{Cause: RewriteFailed}
	}
	removeNew, keyPairMade, sealedMade = false, false, false
	return ModeMachineKeyPair, nil
}

func windowsKeyPair(ctx context.Context, action, keyPath, accountSID string) error {
	const script = `$ErrorActionPreference = 'Stop'
$keyName = 'heliosadvance-bootstrap-key'
$providers = 'Microsoft Software Key Storage Provider', 'Microsoft Platform Crypto Provider'
foreach ($name in $providers) {
    $provider = New-Object Security.Cryptography.CngProvider $name
    if ([Security.Cryptography.CngKey]::Exists($keyName, $provider, [Security.Cryptography.CngKeyOpenOptions]::MachineKey)) {
        $old = [Security.Cryptography.CngKey]::Open($keyName, $provider, [Security.Cryptography.CngKeyOpenOptions]::MachineKey)
        if ($env:HELIOS_ACTION -eq 'remove') { $old.Delete(); continue }
        throw 'machine key pair already exists'
    }
}
if ($env:HELIOS_ACTION -eq 'remove') { exit 0 }
$providerName = 'Microsoft Software Key Storage Provider'
if ((Get-Tpm -ErrorAction SilentlyContinue).TpmPresent) { $providerName = 'Microsoft Platform Crypto Provider' }
$parameters = New-Object Security.Cryptography.CngKeyCreationParameters
$parameters.Provider = New-Object Security.Cryptography.CngProvider $providerName
$parameters.KeyCreationOptions = [Security.Cryptography.CngKeyCreationOptions]::MachineKey
$parameters.Parameters.Add((New-Object Security.Cryptography.CngProperty 'Length', ([BitConverter]::GetBytes(2048)), ([Security.Cryptography.CngPropertyOptions]::None)))
$key = [Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::Rsa, $keyName, $parameters)
try {
    $descriptor = New-Object Security.AccessControl.RawSecurityDescriptor ("O:BAD:P(A;;GA;;;" + $env:HELIOS_ACCOUNT_SID + ")(A;;GA;;;SY)(A;;GA;;;BA)")
    $bytes = New-Object byte[] $descriptor.BinaryLength
    $descriptor.GetBinaryForm($bytes, 0)
    $key.SetProperty((New-Object Security.Cryptography.CngProperty 'Security Descr', $bytes, ([Security.Cryptography.CngPropertyOptions]5)))
    $rsa = New-Object Security.Cryptography.RSACng $key
    [IO.File]::WriteAllBytes($env:HELIOS_SEALED_PATH, $rsa.Encrypt([IO.File]::ReadAllBytes($env:HELIOS_KEY_PATH), [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256))
} catch { $key.Delete(); throw } finally { $key.Dispose() }
`
	units := utf16.Encode([]rune(script))
	encoded := make([]byte, 2*len(units))
	for index, unit := range units {
		binary.LittleEndian.PutUint16(encoded[index*2:], unit)
	}
	command := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded)) //nolint:gosec // fixed program; input data is passed through environment variables
	command.Env = append(os.Environ(), "HELIOS_ACTION="+action, "HELIOS_ACCOUNT_SID="+accountSID, "HELIOS_KEY_PATH="+keyPath, "HELIOS_SEALED_PATH="+filepath.Join(filepath.Dir(keyPath), sealedKeyFileName))
	if output, err := command.CombinedOutput(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("bootstrap: Windows machine key operation failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
