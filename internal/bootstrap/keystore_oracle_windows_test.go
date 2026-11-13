// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The key store oracle: Windows' own key stores, driven from outside Open through Windows
// PowerShell and .NET's CngKey and RSACng, which make each key store key with the access list a
// row gives, wrap the bytes a row gives under it, say what the key store answers when the same
// key is opened or unwrapped with, and delete the key. Making a machine key needs an elevated
// process; asking what opening a key answers does not.
package bootstrap_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
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

// wrapRequest asks the oracle to wrap data under the key it makes, with one of RSA's paddings
// ("oaep-sha256", "oaep-sha1" or "pkcs1"), and to change the low bit of the wrapped byte at
// flip, or none when flip is negative.
type wrapRequest struct {
	Padding string `json:"padding"`
	Data    []byte `json:"data"`
	Flip    int    `json:"flip"`
}

// oaep is the wrap Open takes, of data, unchanged.
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

// keyAnswer is what the oracle wrote back.
type keyAnswer struct {
	Unique   string          `json:"unique"`
	Modulus  string          `json:"modulus"`
	Exponent string          `json:"exponent"`
	Wraps    []string        `json:"wraps"`
	Answers  []windows.Errno `json:"answers"`
	Status   windows.Errno   `json:"status"`
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
		binary.LittleEndian.PutUint16(scriptBytes[2*index:], unit)
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
		return keyAnswer{}, &keyOracleError{action: request.Action, name: request.Name, err: err, said: strings.TrimSpace(standardError.String())}
	}
	var answer keyAnswer
	if err := json.Unmarshal(bytes.TrimSpace(output), &answer); err != nil {
		return keyAnswer{}, &keyOracleError{action: request.Action, name: request.Name, err: err, said: strings.TrimSpace(string(output))}
	}
	return answer, nil
}

// keyOracleError is a call of the oracle that failed, with what it said.
type keyOracleError struct {
	action string
	name   string
	err    error
	said   string
}

func (failure *keyOracleError) Error() string {
	return "the key store oracle's " + failure.action + " of " + failure.name + ": " + failure.err.Error() + ": " + failure.said
}

// keySpec is the key a row asks the oracle for: in which store, a machine key unless userKey, the
// access list it is made with as SDDL (owner and list; empty for the store's own default), one
// set after it is made (empty for none), and what to wrap under it.
type keySpec struct {
	store   string
	userKey bool
	list    string
	later   string
	wraps   []wrapRequest
}

// storeKey is one key the oracle made: its store and name, the name of its file in the store,
// its public half, each wrap in the order asked, and what the key store answered when the oracle
// unwrapped each with OAEP and SHA-256 itself, 0 for none.
type storeKey struct {
	store   string
	machine bool
	name    string
	unique  string
	public  *rsa.PublicKey
	wraps   [][]byte
	answers []windows.Errno
}

// newKeyName is a key store key's name in its form: "hadv-" and 32 random lower-case hex digits,
// at least one of them a letter, so a name in capitals differs from it.
func newKeyName(t *testing.T) string {
	t.Helper()
	random := make([]byte, 16)
	for {
		if _, err := rand.Read(random); err != nil {
			t.Fatalf("making a key name: %v", err)
		}
		digits := hex.EncodeToString(random)
		if strings.ContainsAny(digits, "abcdef") {
			return "hadv-" + digits
		}
	}
}

// securityInformation is which parts of a security descriptor the SDDL sets, as the key store
// takes them with its access list: the owner when it names one, the access list, and whether the
// list is protected from inheriting.
func securityInformation(sddl string) int32 {
	information := uint32(windows.DACL_SECURITY_INFORMATION)
	if strings.HasPrefix(sddl, "O:") {
		information |= windows.OWNER_SECURITY_INFORMATION
	}
	if strings.Contains(sddl, "D:P") {
		information |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	return int32(information)
}

// makeKey has the oracle make the key spec asks for, and deletes it when the row ends. Every list
// a row gives keeps the elevated runner's right to delete the key, but one set after the key is
// made: that one is deleted through its file, given back to Administrators first.
func makeKey(t *testing.T, spec keySpec) *storeKey {
	t.Helper()
	made := &storeKey{store: spec.store, machine: !spec.userKey, name: newKeyName(t)}
	// Registered before the key exists, so a make that fails partway leaves nothing behind.
	t.Cleanup(func() {
		_, err := askKeyOracle(keyRequest{Action: "delete", Store: made.store, Name: made.name, Machine: made.machine, Unique: made.unique})
		if err != nil {
			t.Errorf("deleting the key store key %s: %v", made.name, err)
		}
	})
	request := keyRequest{Action: "make", Store: spec.store, Name: made.name, Machine: made.machine, Wraps: spec.wraps}
	if spec.list != "" {
		request.List, request.Information = spec.list, securityInformation(spec.list)
	}
	if spec.later != "" {
		request.Later, request.LaterInformation = spec.later, securityInformation(spec.later)
	}
	answer, err := askKeyOracle(request)
	if err != nil {
		t.Fatalf("%v", err)
	}
	made.unique = answer.Unique
	if len(answer.Wraps) != len(spec.wraps) || len(answer.Answers) != len(spec.wraps) {
		t.Fatalf("the oracle made %d wraps and %d answers for %d asked: a fault in the test", len(answer.Wraps), len(answer.Answers), len(spec.wraps))
	}
	for index, wrapped := range answer.Wraps {
		raw, err := base64.StdEncoding.DecodeString(wrapped)
		if err != nil || len(raw) != 256 {
			t.Fatalf("the oracle's wrap %d is not 256 bytes (%d, %v): a fault in the test", index, len(raw), err)
		}
		made.wraps = append(made.wraps, raw)
		made.answers = append(made.answers, answer.Answers[index])
	}
	modulus, errModulus := base64.StdEncoding.DecodeString(answer.Modulus)
	exponent, errExponent := base64.StdEncoding.DecodeString(answer.Exponent)
	if errModulus != nil || errExponent != nil || len(modulus) != 256 {
		t.Fatalf("the oracle's public key is not RSA-2048's: a fault in the test")
	}
	made.public = &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(new(big.Int).SetBytes(exponent).Int64())}
	return made
}

// openAnswer is what the key store answers when the oracle opens the named machine key, silently,
// in store: the answer a row expects beneath ErrKeyStore when Open asks for the same key. It
// fails the row when the oracle opens it, since every such row names a key it cannot open.
func openAnswer(t *testing.T, store, name string) windows.Errno {
	t.Helper()
	answer, err := askKeyOracle(keyRequest{Action: "open", Store: store, Name: name, Machine: true})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if answer.Status == 0 {
		t.Fatalf("the oracle opened %s in %s, a key the row names because it cannot be opened: a fault in the test", name, store)
	}
	return answer.Status
}

// goodList is a key store key's access list as hadv-setup would give it: owned by
// Administrators, and SYSTEM, Administrators and the runner's own user each allowed everything.
func goodList(t *testing.T) string {
	t.Helper()
	return "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + runnerSID(t) + ")"
}
