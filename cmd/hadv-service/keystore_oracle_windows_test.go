// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The key store oracle for the program's rows: Windows' own key stores, driven from outside the
// program through Windows PowerShell and .NET's CngKey and RSACng, which make each key store key
// with the access list a row gives, wrap the bytes a row gives under it and delete the key. Making
// a machine key needs an elevated process.
package main_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	endian "encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"
)

// The two key stores, by the names Windows gives them, and the key holder that names each in the
// bootstrap file's header: the test's own copy, as the page states them.
const (
	softwareStore = "Microsoft Software Key Storage Provider"
	tpmStore      = "Microsoft Platform Crypto Provider"
)

// holderOf is the header's key holder for each key store.
var holderOf = map[string]int{tpmStore: 2, softwareStore: 3}

// What the oracle may take, a hang bound for each store and never a verdict on time: making an
// RSA-2048 key in the TPM took 0.4 to 24.4 seconds on the TPM it was measured on, and each
// unwrap there about 0.4 seconds, where the software store took well under a second for each.
const (
	softwareOracleBound = 60 * time.Second
	tpmOracleBound      = 3 * time.Minute
)

// keyOracleSlots bounds how many PowerShell processes the rows start at once, so a loaded
// runner's oracle is slow rather than starved; tpmTurn makes the TPM's keys one at a time, since a
// TPM serves one command at a time and its keys take seconds each.
var (
	keyOracleSlots = make(chan struct{}, 4)
	tpmTurn        sync.Mutex
)

// keyOracleScript reads its request as JSON from the environment and writes its answer as JSON.
// A key store's answer is the HRESULT .NET carries, as an unsigned number, 0 for none. A failure
// is written to standard error as plain text, and progress not at all, so a row's message says
// why. The TPM store's unique name for a key is its file's full path, the software store's the
// file's name alone.
const keyOracleScript = `
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
trap { [Console]::Error.WriteLine($_.Exception.ToString()); exit 1 }
$request = $env:HADV_KEY_REQUEST | ConvertFrom-Json
$provider = New-Object System.Security.Cryptography.CngProvider($request.store)
$options = [System.Security.Cryptography.CngKeyOpenOptions]::Silent
if ($request.machine) { $options = $options -bor [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey }
function Descriptor([string]$sddl) {
	$raw = New-Object System.Security.AccessControl.RawSecurityDescriptor($sddl)
	$bytes = New-Object byte[] $raw.BinaryLength
	$raw.GetBinaryForm($bytes, 0)
	return ,$bytes
}
function Status($record) {
	$e = $record.Exception
	while ($e.InnerException) { $e = $e.InnerException }
	return [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$e.HResult), 0)
}
function Padding([string]$name) {
	switch ($name) {
		'oaep-sha256' { return [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256 }
		'oaep-sha1' { return [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1 }
		'pkcs1' { return [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1 }
	}
	throw "no padding named $name"
}
switch ($request.action) {
	'make' {
		$parameters = New-Object System.Security.Cryptography.CngKeyCreationParameters
		$parameters.Provider = $provider
		if ($request.machine) { $parameters.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::MachineKey }
		$parameters.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
		$parameters.Parameters.Add((New-Object System.Security.Cryptography.CngProperty('Length', [BitConverter]::GetBytes(2048), [System.Security.Cryptography.CngPropertyOptions]::None)))
		if ($request.list) {
			$parameters.Parameters.Add((New-Object System.Security.Cryptography.CngProperty('Security Descr', (Descriptor $request.list), [System.Security.Cryptography.CngPropertyOptions][int]$request.information)))
		}
		$key = [System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::Rsa, $request.name, $parameters)
		$rsa = New-Object System.Security.Cryptography.RSACng($key)
		$public = $rsa.ExportParameters($false)
		$wraps = @()
		$answers = @()
		foreach ($wrap in @($request.wraps)) {
			$wrapped = $rsa.Encrypt([Convert]::FromBase64String($wrap.data), (Padding $wrap.padding))
			if ($wrap.flip -ge 0) { $wrapped[$wrap.flip] = $wrapped[$wrap.flip] -bxor 1 }
			$answer = 0
			try { [void]$rsa.Decrypt($wrapped, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256) } catch { $answer = Status $_ }
			$wraps += [Convert]::ToBase64String($wrapped)
			$answers += $answer
		}
		if ($request.later) {
			$key.SetProperty((New-Object System.Security.Cryptography.CngProperty('Security Descr', (Descriptor $request.later), [System.Security.Cryptography.CngPropertyOptions][int]$request.laterInformation)))
		}
		$unique = $key.UniqueName
		$rsa.Dispose()
		$key.Dispose()
		@{ unique = $unique; modulus = [Convert]::ToBase64String($public.Modulus); exponent = [Convert]::ToBase64String($public.Exponent); wraps = $wraps; answers = $answers } | ConvertTo-Json -Compress
	}
	'open' {
		$status = 0
		try { ([System.Security.Cryptography.CngKey]::Open($request.name, $provider, $options)).Dispose() } catch { $status = Status $_ }
		@{ status = $status } | ConvertTo-Json -Compress
	}
	'delete' {
		$key = $null
		try { $key = [System.Security.Cryptography.CngKey]::Open($request.name, $provider, $options) } catch {
			$status = Status $_
			if ($status -eq 2148073494) { @{ status = $status } | ConvertTo-Json -Compress; return }
			if (-not $request.unique) { throw }
			foreach ($folder in @((Join-Path $env:ProgramData 'Microsoft\Crypto\PCPKSP'), (Join-Path $env:ProgramData 'Microsoft\Crypto\Keys'))) {
				Get-ChildItem -LiteralPath $folder -Recurse -File -Filter ((Split-Path -Leaf $request.unique) + '*') -ErrorAction SilentlyContinue | ForEach-Object { [void](& icacls.exe $_.FullName /grant '*S-1-5-32-544:F') }
			}
			$key = [System.Security.Cryptography.CngKey]::Open($request.name, $provider, $options)
		}
		$key.Delete()
		@{ status = 0 } | ConvertTo-Json -Compress
	}
	default { throw "no action named $($request.action)" }
}
`

// wrapRequest asks the oracle to wrap data under the key it makes, with OAEP and SHA-256, the
// wrap the engine takes.
type wrapRequest struct {
	Padding string `json:"padding"`
	Data    []byte `json:"data"`
	Flip    int    `json:"flip"`
}

// oaep is the wrap the engine takes, of data, unchanged.
func oaep(data []byte) wrapRequest {
	return wrapRequest{Padding: "oaep-sha256", Data: data, Flip: -1}
}

// keyRequest is one call of the oracle.
type keyRequest struct {
	Action           string        `json:"action"`
	Store            string        `json:"store"`
	Name             string        `json:"name"`
	Machine          bool          `json:"machine"`
	List             string        `json:"list,omitempty"`
	Information      int32         `json:"information"`
	Wraps            []wrapRequest `json:"wraps"`
	Later            string        `json:"later,omitempty"`
	LaterInformation int32         `json:"laterInformation"`
	Unique           string        `json:"unique,omitempty"`
}

// keyAnswer is what the oracle wrote back, the parts the program's rows read.
type keyAnswer struct {
	Unique string   `json:"unique"`
	Wraps  []string `json:"wraps"`
}

// askKeyOracle runs one call of the oracle within its store's bound. It returns why the call
// failed rather than failing the row, so a cleanup can report it too.
func askKeyOracle(request keyRequest) (keyAnswer, error) {
	keyOracleSlots <- struct{}{}
	defer func() { <-keyOracleSlots }()
	bound := softwareOracleBound
	if request.Store == tpmStore {
		tpmTurn.Lock()
		defer tpmTurn.Unlock()
		bound = tpmOracleBound
	}
	if request.Wraps == nil {
		request.Wraps = []wrapRequest{}
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return keyAnswer{}, err
	}
	script := utf16.Encode([]rune(keyOracleScript))
	scriptBytes := make([]byte, 2*len(script))
	for index, unit := range script {
		endian.LittleEndian.PutUint16(scriptBytes[2*index:], unit)
	}
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()
	command := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", base64.StdEncoding.EncodeToString(scriptBytes))
	command.Env = append(os.Environ(), "HADV_KEY_REQUEST="+string(encoded))
	var standardError bytes.Buffer
	command.Stderr = &standardError
	output, err := command.Output()
	if err != nil {
		return keyAnswer{}, fmt.Errorf("the key store oracle's %s of %s: %w: %s", request.Action, request.Name, err, strings.TrimSpace(standardError.String()))
	}
	var answer keyAnswer
	if err := json.Unmarshal(bytes.TrimSpace(output), &answer); err != nil {
		return keyAnswer{}, fmt.Errorf("the key store oracle's %s of %s: %w: %s", request.Action, request.Name, err, strings.TrimSpace(string(output)))
	}
	return answer, nil
}

// storeKey is one key the oracle made: its store, its name and its wraps in the order asked.
type storeKey struct {
	store string
	name  string
	wraps [][]byte
}

// newKeyName is a key store key's name in its form: "hadv-" and 32 random lower-case hex digits.
func newKeyName(t *testing.T) string {
	t.Helper()
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("making a key name: %v", err)
	}
	return "hadv-" + hex.EncodeToString(random)
}

// securityInformation is which parts of a security descriptor the SDDL sets: the owner when it
// names one (1), the access list (4), and whether the list is protected from inheriting
// (0x80000000).
func securityInformation(sddl string) int32 {
	information := uint32(4)
	if strings.HasPrefix(sddl, "O:") {
		information |= 1
	}
	if strings.Contains(sddl, "D:P") {
		information |= 0x80000000
	}
	return int32(information)
}

// makeStoreKey has the oracle make a machine key in store, or a key made without the machine-key
// flag when userKey, with the access list as SDDL (empty for the store's default) and another set
// after it is made (empty for none), wrapping each of wraps under it, and deletes it when the row
// ends.
func makeStoreKey(t *testing.T, store string, userKey bool, list, later string, wraps ...wrapRequest) *storeKey {
	t.Helper()
	made := &storeKey{store: store, name: newKeyName(t)}
	unique := ""
	// Registered before the key exists, so a make that fails partway leaves nothing behind.
	t.Cleanup(func() {
		if _, err := askKeyOracle(keyRequest{Action: "delete", Store: store, Name: made.name, Machine: !userKey, Unique: unique}); err != nil {
			t.Errorf("deleting the key store key %s: %v", made.name, err)
		}
	})
	request := keyRequest{Action: "make", Store: store, Name: made.name, Machine: !userKey, Wraps: wraps}
	if list != "" {
		request.List, request.Information = list, securityInformation(list)
	}
	if later != "" {
		request.Later, request.LaterInformation = later, securityInformation(later)
	}
	answer, err := askKeyOracle(request)
	if err != nil {
		t.Fatalf("%v", err)
	}
	unique = answer.Unique
	if len(answer.Wraps) != len(wraps) {
		t.Fatalf("the oracle made %d wraps for %d asked: a fault in the test", len(answer.Wraps), len(wraps))
	}
	for index, wrapped := range answer.Wraps {
		raw, err := base64.StdEncoding.DecodeString(wrapped)
		if err != nil || len(raw) != 256 {
			t.Fatalf("the oracle's wrap %d is not 256 bytes (%d, %v): a fault in the test", index, len(raw), err)
		}
		made.wraps = append(made.wraps, raw)
	}
	return made
}

// goodList is a key store key's access list as hadv-setup would give it: owned by
// Administrators, and SYSTEM, Administrators and the runner's own account each allowed
// everything.
func goodList(t *testing.T) string {
	t.Helper()
	return "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + runnerSID(t) + ")"
}

// storeBootstrapFolder makes a bootstrap folder for a row of its own on the shared board, whose
// bootstrap file, sealed under the key in keyText, names the key store key name under holder with
// wrapped as its wrapped key, broken further as edits says. It holds no key file.
func storeBootstrapFolder(t *testing.T, holder int, name string, wrapped, key []byte, keyText, edits string) *bootstrapFolder {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bootstrap")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("making the bootstrap folder: %v", err)
	}
	plaintext := []byte(sharedRowSettings(t).text(t))
	made := &bootstrapFolder{path: path, file: filepath.Join(path, bootstrapFileName), keyFile: filepath.Join(path, keyFileName),
		key: key, keyText: keyText, plaintext: plaintext}
	if holder == holderOf[tpmStore] {
		made.turn = &tpmTurn
	}
	sealed := fmt.Sprintf("holder %d\nsealed hex:%s hex:%s\n", holder, hex.EncodeToString([]byte(name)), hex.EncodeToString(wrapped))
	made.writeFile(t, sealBootstrap(t, keyText, plaintext, sealed+edits))
	return made
}

// keyStoreFolder has the oracle make a machine key in store with the access list given, wrapping
// a fresh key under it, and returns a good bootstrap folder for it, broken further as edits says.
func keyStoreFolder(t *testing.T, store, list, edits string) (*storeKey, *bootstrapFolder) {
	t.Helper()
	key, keyText := newBootstrapKey(t)
	made := makeStoreKey(t, store, false, list, "", oaep(key))
	return made, storeBootstrapFolder(t, holderOf[store], made.name, made.wraps[0], key, keyText, edits)
}
