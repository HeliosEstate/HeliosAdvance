// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
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
	folderHandle := windows.Handle(directory.Fd())
	keyPair, exists, err := openKeyPair()
	if err != nil {
		return 0, err
	}
	if exists {
		keyPair.close()
		if path == FirstSetup || path == Joining {
			return 0, &Refusal{Cause: MachineKeyPairExists}
		}
	}
	oldFile, err := openChild(folderHandle, bootstrapFileName, windows.FILE_READ_ATTRIBUTES)
	if err == nil {
		linkErr := checkWindowsHandle(oldFile, filepath.Join(folder, bootstrapFileName))
		_ = windows.CloseHandle(oldFile) //nolint:errcheck // nothing to flush on a read-only handle
		if linkErr != nil {
			return 0, linkErr
		}
		if path == FirstSetup || path == Joining {
			return 0, &Refusal{Cause: FileExists}
		}
	} else if !windowsMissingItem(err) {
		return 0, err
	}
	if exists {
		if _, err := windowsKeyPair(ctx, "remove", ""); err != nil {
			return 0, err
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return 0, fmt.Errorf("bootstrap: making the bootstrap key: %w", err)
	}
	defer clear(key)
	sealedFile, err := createChild(folderHandle, folder, sealedKeyFileName, service)
	if err != nil {
		return 0, err
	}
	keyPairMade, sealedMade := false, true
	defer func(cleanupContext context.Context) {
		if keyPairMade {
			_, _ = windowsKeyPair(cleanupContext, "remove", "") //nolint:errcheck // preserve the build error
		}
		if sealedMade {
			_ = sealedFile.Close()                           //nolint:errcheck // closed already after a good write; the delete needs the share
			_ = deleteChild(folderHandle, sealedKeyFileName) //nolint:errcheck // a failed build must not leave the sealed key
		}
	}(context.WithoutCancel(ctx))
	publicKey, err := windowsKeyPair(ctx, "create", service.String())
	if err != nil {
		return 0, err
	}
	keyPairMade = true
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, key, nil)
	if err != nil {
		return 0, fmt.Errorf("bootstrap: sealing the bootstrap key: %w", err)
	}
	if _, err := sealedFile.Write(ciphertext); err != nil {
		return 0, err
	}
	if err := sealedFile.Close(); err != nil {
		return 0, err
	}
	file := &bootstrapFile{}
	file.setFields(fields)
	newName := bootstrapFileName + ".new"
	output, err := createChild(folderHandle, folder, newName, service)
	if err != nil {
		return 0, err
	}
	removeNew := true
	defer func() {
		if removeNew {
			_ = output.Close()                     //nolint:errcheck // the delete needs the share
			_ = deleteChild(folderHandle, newName) //nolint:errcheck // remove the incomplete build file
		}
	}()
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
	if err != nil {
		return 0, &Refusal{Cause: RewriteFailed}
	}
	err = renameOver(output, folderHandle, bootstrapFileName)
	_ = output.Close() //nolint:errcheck // read-back is complete
	if err != nil {
		return 0, &Refusal{Cause: RewriteFailed}
	}
	removeNew, keyPairMade, sealedMade = false, false, false
	return ModeMachineKeyPair, nil
}

func windowsKeyPair(ctx context.Context, action, accountSID string) (*rsa.PublicKey, error) {
	const script = `$ErrorActionPreference = 'Stop'
$keyName = 'heliosadvance-bootstrap-key'
$providers = 'Microsoft Software Key Storage Provider', 'Microsoft Platform Crypto Provider'
foreach ($name in $providers) {
    $provider = New-Object Security.Cryptography.CngProvider $name
    $exists = $false
    try { $exists = [Security.Cryptography.CngKey]::Exists($keyName, $provider, [Security.Cryptography.CngKeyOpenOptions]::MachineKey) } catch { }
    if ($exists) {
        $old = [Security.Cryptography.CngKey]::Open($keyName, $provider, [Security.Cryptography.CngKeyOpenOptions]::MachineKey)
        if ($env:HELIOS_ACTION -eq 'remove') { $old.Delete(); continue }
        throw 'machine key pair already exists'
    }
}
if ($env:HELIOS_ACTION -eq 'remove') { exit 0 }
$providerName = 'Microsoft Software Key Storage Provider'
$tpm = Get-Tpm -ErrorAction Stop
if ($tpm.TpmPresent) { $providerName = 'Microsoft Platform Crypto Provider' }
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
    $public = $rsa.ExportParameters($false)
    [Console]::Out.WriteLine('HELIOS_PUBLIC_KEY=' + [Convert]::ToBase64String($public.Modulus) + ' ' + [Convert]::ToBase64String($public.Exponent))
} catch { $key.Delete(); throw } finally { $key.Dispose() }
`
	units := utf16.Encode([]rune(script))
	encoded := make([]byte, 2*len(units))
	for index, unit := range units {
		binary.LittleEndian.PutUint16(encoded[index*2:], unit)
	}
	command := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded)) //nolint:gosec // fixed program; input data is passed through environment variables
	command.Env = append(os.Environ(), "HELIOS_ACTION="+action, "HELIOS_ACCOUNT_SID="+accountSID)
	env := command.Env[:0]
	for _, value := range command.Env {
		if !strings.HasPrefix(value, "PSModulePath=") {
			env = append(env, value)
		}
	}
	command.Env = env
	output, err := command.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("bootstrap: Windows machine key operation failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if action != "create" {
		return nil, nil
	}
	var parts []string
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "HELIOS_PUBLIC_KEY=") {
			parts = strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "HELIOS_PUBLIC_KEY="))
			break
		}
	}
	if len(parts) != 2 {
		return nil, fmt.Errorf("bootstrap: Windows returned invalid public key")
	}
	modulus, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	exponentBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	exponent := 0
	for _, value := range exponentBytes {
		exponent = exponent<<8 | int(value)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}, nil
}
