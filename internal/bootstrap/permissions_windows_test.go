// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// The accounts in the Windows rows, which every Windows machine has: the service account,
// and another. Each by its SID for icacls and by its name as Windows resolves it.
const (
	serviceAccount    = `NT AUTHORITY\LOCAL SERVICE`
	serviceAccountSID = "S-1-5-19"
	otherAccount      = `NT AUTHORITY\NETWORK SERVICE`
	otherAccountSID   = "S-1-5-20"
	accountSystem     = `NT AUTHORITY\SYSTEM`
	accountAdmins     = `BUILTIN\Administrators`
)

// windowsRule is every Windows item's rule for the account, as the permission table gives
// it: the account, SYSTEM and Administrators only, no inherited access, owned by
// Administrators.
func windowsRule(account string) Permissions {
	return Permissions{Owner: accountAdmins, Accounts: []string{account, accountSystem, accountAdmins}}
}

// elevated reports whether this process is elevated: whether Windows counts it in the
// Administrators role, which an administrator's filtered token is not. PowerShell, not
// whoami, since Git Bash puts a whoami without /groups first on the path.
func elevated(t *testing.T) bool {
	t.Helper()
	out := powerShell(t, "[Console]::Out.WriteLine((New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))")
	return strings.TrimSpace(string(out)) == "True"
}

// oracleFunctions is the PowerShell the rows set up and read items with. Read-Item reports
// an item as the contract's Permissions holds it: the owner and every account an allow
// entry names, as Windows resolves them, and whether the access list inherits.
const oracleFunctions = `
$ErrorActionPreference = 'Stop'
$keyName = 'heliosadvance-bootstrap-key'
$provider = [Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
function Invoke-Icacls { & icacls @args | Out-Null; if ($LASTEXITCODE) { throw "icacls $args" } }
function Set-Rule($path, $sid, $isFolder) {
    $flags = if ($isFolder) { '(OI)(CI)' } else { '' }
    Invoke-Icacls $path /inheritance:r /grant:r "*${sid}:${flags}F" "*S-1-5-18:${flags}F" "*S-1-5-32-544:${flags}F"
    # icacls can keep the running account's own entry when it removes inheritance (it does on
    # GitHub's Windows runner), so any account the rule does not name is removed after it.
    $named = $sid, 'S-1-5-18', 'S-1-5-32-544'
    foreach ($entry in (Get-Acl -LiteralPath $path).Access) {
        $other = $entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($named -notcontains $other) { Invoke-Icacls $path /remove:g "*$other" }
    }
    Invoke-Icacls $path /setowner '*S-1-5-32-544'
}
function Set-KeyPair($sddl) {
    $key = [Security.Cryptography.CngKey]::Open($keyName, $provider, [Security.Cryptography.CngKeyOpenOptions]::MachineKey)
    $descriptor = New-Object Security.AccessControl.RawSecurityDescriptor $sddl
    $bytes = New-Object byte[] $descriptor.BinaryLength
    $descriptor.GetBinaryForm($bytes, 0)
    $key.SetProperty((New-Object Security.Cryptography.CngProperty 'Security Descr', $bytes, ([Security.Cryptography.CngPropertyOptions]5)))
    $key.Dispose()
}
function New-Baseline($folder, $sid) {
    New-Item -ItemType Directory -Force $folder | Out-Null
    $names = 'bootstrap.hadv', 'bootstrap.lock', 'bootstrap-key.sealed'
    foreach ($name in $names) { Set-Content -LiteralPath (Join-Path $folder $name) $name -NoNewline }
    Set-Rule $folder $sid $true
    foreach ($name in $names) { Set-Rule (Join-Path $folder $name) $sid $false }
    $parameters = New-Object Security.Cryptography.CngKeyCreationParameters
    $parameters.Provider = $provider
    $parameters.KeyCreationOptions = [Security.Cryptography.CngKeyCreationOptions]'MachineKey, OverwriteExistingKey'
    $parameters.Parameters.Add((New-Object Security.Cryptography.CngProperty 'Length', ([BitConverter]::GetBytes(2048)), ([Security.Cryptography.CngPropertyOptions]::None)))
    [Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::Rsa, $keyName, $parameters).Dispose()
    Set-KeyPair "O:BAD:P(A;;GA;;;$sid)(A;;GA;;;SY)(A;;GA;;;BA)"
}
function Remove-KeyPair {
    if ([Security.Cryptography.CngKey]::Exists($keyName, $provider, [Security.Cryptography.CngKeyOpenOptions]::MachineKey)) {
        [Security.Cryptography.CngKey]::Open($keyName, $provider, [Security.Cryptography.CngKeyOpenOptions]::MachineKey).Delete()
    }
}
function Read-Item($path) {
    if ($path -eq $keyName) {
        $key = [Security.Cryptography.CngKey]::Open($keyName, $provider, [Security.Cryptography.CngKeyOpenOptions]::MachineKey)
        $descriptor = New-Object Security.AccessControl.RawSecurityDescriptor ($key.GetProperty('Security Descr', [Security.Cryptography.CngPropertyOptions]5).GetValue()), 0
        $key.Dispose()
        $owner = $descriptor.Owner.Translate([Security.Principal.NTAccount]).Value
        $accounts = @($descriptor.DiscretionaryAcl | Where-Object { $_.AceQualifier -eq 'AccessAllowed' } | ForEach-Object { $_.SecurityIdentifier.Translate([Security.Principal.NTAccount]).Value })
        $inherited = -not (($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0)
    } else {
        $acl = Get-Acl -LiteralPath $path
        $owner = $acl.Owner
        $accounts = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' } | ForEach-Object { $_.IdentityReference.Value })
        $inherited = -not $acl.AreAccessRulesProtected
    }
    New-Object PSObject -Property @{ path = $path; owner = $owner; accounts = @($accounts | Sort-Object -Unique); inherited = $inherited }
}
function Write-Items($paths) {
    $items = @(foreach ($path in $paths) { Read-Item $path })
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $items -Compress -Depth 3))
}
`

// windowsPowerShellEnvironment is this process's environment without PSModulePath: Windows
// PowerShell started from PowerShell 7 inherits 7's module path and cannot load Get-Acl's
// module, and without the variable it builds its own.
func windowsPowerShellEnvironment() []string {
	return slices.DeleteFunc(os.Environ(), func(variable string) bool {
		return strings.HasPrefix(strings.ToUpper(variable), "PSMODULEPATH=")
	})
}

// powerShell runs a script under Windows PowerShell with the oracle's functions, passed
// encoded so that no quoting is lost on the way, and returns what it writes.
func powerShell(t *testing.T, script string) []byte {
	t.Helper()
	units := utf16.Encode([]rune(oracleFunctions + script))
	encoded := make([]byte, 2*len(units))
	for i, unit := range units {
		binary.LittleEndian.PutUint16(encoded[2*i:], unit)
	}
	command := exec.CommandContext(t.Context(), "powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded))
	command.Env = windowsPowerShellEnvironment()
	out, err := command.Output()
	if err != nil {
		var stderr string
		if exitError, ok := err.(*exec.ExitError); ok { //nolint:errorlint // Output returns *exec.ExitError itself
			stderr = string(exitError.Stderr)
		}
		t.Fatalf("the PowerShell oracle failed: %v\n%s\n%s", err, out, stderr)
	}
	return out
}

// windowsFolder is a bootstrap folder for the rows under ModeMachineKeyPair: its path and
// every item, the machine key pair by its name.
type windowsFolder struct {
	path  string
	items map[string]Item
}

func (folder windowsFolder) itemPaths() []string {
	paths := make([]string, 0, len(folder.items))
	for path := range folder.items {
		paths = append(paths, path)
	}
	return paths
}

func newWindowsFolder(t *testing.T) windowsFolder {
	t.Helper()
	path := filepath.Join(t.TempDir(), "folder")
	return windowsFolder{path: path, items: map[string]Item{
		path:                               ItemFolder,
		filepath.Join(path, nameFile):      ItemFile,
		filepath.Join(path, nameLock):      ItemOtherFile,
		filepath.Join(path, nameSealedKey): ItemOtherFile,
		keyPairName:                        ItemMachineKeyPair,
	}}
}

// setUp makes the folder and the machine key pair, every item set to its rule for the
// account, runs the row's change, and reads every item afterwards: one oracle run.
func setUp(t *testing.T, folder windowsFolder, accountSID, change string) map[string]Permissions {
	t.Helper()
	t.Cleanup(func() { removeKeyPair(t) })
	return readItems(t, folder, "$folder = '"+folder.path+"'\nNew-Baseline $folder '"+accountSID+"'\n"+change)
}

// readItems runs the script, then reads every item in the folder.
func readItems(t *testing.T, folder windowsFolder, script string) map[string]Permissions {
	t.Helper()
	quoted := make([]string, 0, len(folder.items))
	for _, path := range folder.itemPaths() {
		quoted = append(quoted, "'"+path+"'")
	}
	out := powerShell(t, script+"\nWrite-Items @("+strings.Join(quoted, ", ")+")\n")
	var items []struct {
		Path      string   `json:"path"`
		Owner     string   `json:"owner"`
		Accounts  []string `json:"accounts"`
		Inherited bool     `json:"inherited"`
	}
	if err := json.Unmarshal(out, &items); err != nil {
		t.Fatalf("reading the oracle's report: %v\n%s", err, out)
	}
	found := map[string]Permissions{}
	for _, item := range items {
		found[item.Path] = Permissions{Owner: item.Owner, Accounts: item.Accounts, Inherited: item.Inherited}
	}
	return found
}

func removeKeyPair(t *testing.T) {
	t.Helper()
	command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", //nolint:noctx // a cleanup runs after the test's context has ended
		"$keyName = 'heliosadvance-bootstrap-key'; $provider = [Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider; "+
			"if ([Security.Cryptography.CngKey]::Exists($keyName, $provider, [Security.Cryptography.CngKeyOpenOptions]::MachineKey)) "+
			"{ [Security.Cryptography.CngKey]::Open($keyName, $provider, [Security.Cryptography.CngKeyOpenOptions]::MachineKey).Delete() }")
	command.Env = windowsPowerShellEnvironment()
	if out, err := command.CombinedOutput(); err != nil {
		t.Errorf("deleting the machine key pair: %v\n%s", err, out)
	}
}

// filesUnchanged reads every file's bytes in the folder.
func fileContents(t *testing.T, folder windowsFolder) map[string]string {
	t.Helper()
	contents := map[string]string{}
	for path, item := range folder.items {
		if item == ItemFile || item == ItemOtherFile {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			contents[path] = string(data)
		}
	}
	return contents
}

// sameExceptWindows fails the row when anything in before but the path given has changed.
func sameExceptWindows(t *testing.T, before, after map[string]Permissions, except string) {
	t.Helper()
	for path, was := range before {
		if path != except && !samePermissions(after[path], was) {
			t.Errorf("%s changed: %+v, was %+v", path, after[path], was)
		}
	}
}

// TestWindowsNotElevated runs where the process is not elevated: the loop's machine and the
// developer's. GitHub's runner is elevated, so it skips there.
func TestWindowsNotElevated(t *testing.T) {
	t.Parallel()
	if elevated(t) {
		t.Skip("needs a process that is not elevated: runs on the loop's machine and the developer's")
	}
	folder := filepath.Join(t.TempDir(), "folder")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{nameFile, nameLock, nameSealedKey} {
		if err := os.WriteFile(filepath.Join(folder, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Run(lineCheckNotElevated, func(t *testing.T) {
		t.Parallel()
		_, err := New().Check(folder, ModeMachineKeyPair, serviceAccount)
		wantRefusal(t, err, NotElevated)
	})
	t.Run(lineSetToRuleNotElevated, func(t *testing.T) {
		t.Parallel()
		err := New().SetToRule(Finding{Item: ItemFile, Path: filepath.Join(folder, nameFile)}, serviceAccount)
		wantRefusal(t, err, NotElevated)
	})
}

// TestWindowsElevated is every Windows row but NotElevated. It runs on GitHub's Windows
// runner, whose job fails before the tests when the runner is not elevated, so its skip
// elsewhere cannot pass there unseen. The rows run one after another: the machine key pair
// and the VHD's drive letter are one per machine.
//
//nolint:paralleltest // the machine key pair is one per machine
func TestWindowsElevated(t *testing.T) {
	if !elevated(t) {
		t.Skip("needs an elevated process: runs on GitHub's Windows runner, whose job fails when it is not elevated")
	}

	t.Run(lineCheckFolder, func(t *testing.T) {
		good := newWindowsFolder(t)
		setUp(t, good, serviceAccountSID, "")
		links := t.TempDir()
		junction, symlink := filepath.Join(links, "junction"), filepath.Join(links, "symlink")
		powerShell(t, "$good = '"+good.path+"'\n$junction = '"+junction+"'\n$symlink = '"+symlink+"'\n"+
			"New-Item -ItemType Junction -Path $junction -Target $good | Out-Null\nNew-Item -ItemType SymbolicLink -Path $symlink -Target $good | Out-Null\n")
		fat := fatFolder(t)
		share := `\\localhost\` + good.path[:1] + "$" + good.path[2:]
		for _, row := range []struct {
			name   string
			folder string
			rule   FolderRule
		}{
			{"a relative path", "bootstrap", NotAbsolute},
			{"a junction to a good folder", junction, FolderLink},
			{"a symbolic link to a good folder", symlink, FolderLink},
			{"a folder on FAT32", fat, FileSystem},
			{"the good folder through the administrative share", share, NetworkShare},
		} {
			t.Run(row.name, func(t *testing.T) {
				_, err := New().Check(row.folder, ModeMachineKeyPair, serviceAccount)
				wantFolderRefused(t, err, row.rule)
			})
		}
		t.Run("let through: a folder on NTFS", func(t *testing.T) {
			findings, err := New().Check(good.path, ModeMachineKeyPair, serviceAccount)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			sameFindings(t, findings, nil)
		})
	})

	t.Run(lineCheckFinding, func(t *testing.T) {
		for _, row := range []struct {
			name    string
			change  string
			loosens []string // the names loosened, "" for the folder
		}{
			{"the folder inheriting", "Invoke-Icacls $folder /inheritance:e", []string{""}},
			{"the folder granting Users", "Invoke-Icacls $folder /grant '*S-1-5-32-545:(R)'", []string{""}},
			{"the folder owned by NETWORK SERVICE", "Invoke-Icacls $folder /setowner '*S-1-5-20'", []string{""}},
			{"the bootstrap file granting Everyone", "Invoke-Icacls (Join-Path $folder 'bootstrap.hadv') /grant '*S-1-1-0:(R)'", []string{nameFile}},
			{"the sealed-key file granting Users", "Invoke-Icacls (Join-Path $folder 'bootstrap-key.sealed') /grant '*S-1-5-32-545:(R)'", []string{nameSealedKey}},
			{"the lock inheriting", "Invoke-Icacls (Join-Path $folder 'bootstrap.lock') /inheritance:e", []string{nameLock}},
			{"the machine key pair usable by Users", "Set-KeyPair 'O:BAD:P(A;;GA;;;LS)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;BU)'", []string{keyPairName}},
			{"two at once: the folder granting Users and the bootstrap file granting Everyone",
				"Invoke-Icacls $folder /grant '*S-1-5-32-545:(R)'\nInvoke-Icacls (Join-Path $folder 'bootstrap.hadv') /grant '*S-1-1-0:(R)'", []string{"", nameFile}},
		} {
			t.Run(row.name, func(t *testing.T) {
				folder := newWindowsFolder(t)
				found := setUp(t, folder, serviceAccountSID, row.change)
				var want []Finding
				for _, name := range row.loosens {
					path := folder.path
					switch name {
					case "":
					case keyPairName:
						path = keyPairName
					default:
						path = filepath.Join(folder.path, name)
					}
					want = append(want, Finding{Item: folder.items[path], Path: path, Found: found[path], Rule: windowsRule(serviceAccount)})
				}
				findings, err := New().Check(folder.path, ModeMachineKeyPair, serviceAccount)
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				sameFindings(t, findings, want)
			})
		}
	})

	t.Run(lineCheckNoFinding, func(t *testing.T) {
		for _, row := range []struct {
			name   string
			change string
		}{
			{"every item at its rule", ""},
			{"let through: the bootstrap file owned by SYSTEM", "Invoke-Icacls (Join-Path $folder 'bootstrap.hadv') /setowner '*S-1-5-18'"},
			{"let through: the bootstrap file owned by the account", "Invoke-Icacls (Join-Path $folder 'bootstrap.hadv') /setowner '*S-1-5-19'"},
			{"let through, stricter than the rule: the account with read only on the bootstrap file", "Invoke-Icacls (Join-Path $folder 'bootstrap.hadv') /grant:r '*S-1-5-19:(R)'"},
		} {
			t.Run(row.name, func(t *testing.T) {
				folder := newWindowsFolder(t)
				setUp(t, folder, serviceAccountSID, row.change)
				findings, err := New().Check(folder.path, ModeMachineKeyPair, serviceAccount)
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				sameFindings(t, findings, nil)
			})
		}
	})

	t.Run(lineCheckAccount, func(t *testing.T) {
		t.Run("every item set for LOCAL SERVICE, checked as NETWORK SERVICE", func(t *testing.T) {
			folder := newWindowsFolder(t)
			found := setUp(t, folder, serviceAccountSID, "")
			var want []Finding
			for path, item := range folder.items {
				want = append(want, Finding{Item: item, Path: path, Found: found[path], Rule: windowsRule(otherAccount)})
			}
			findings, err := New().Check(folder.path, ModeMachineKeyPair, otherAccount)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			sameFindings(t, findings, want)
		})
	})

	t.Run(lineCheckLock, func(t *testing.T) {
		t.Run("the lock held by another process, with no sharing and a byte-range lock", func(t *testing.T) {
			folder := newWindowsFolder(t)
			setUp(t, folder, serviceAccountSID, "")
			release := holdWindowsLock(t, filepath.Join(folder.path, nameLock))
			defer release()
			done := make(chan error, 1)
			go func() {
				_, err := New().Check(folder.path, ModeMachineKeyPair, serviceAccount)
				done <- err
			}()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Check did not return within 10 seconds while another process held the lock")
			}
		})
	})

	t.Run(lineSetToRuleSets, func(t *testing.T) {
		for _, row := range []struct {
			name   string
			change string
			item   string // the name set to its rule, "" for the folder
		}{
			{"the folder granting Users", "Invoke-Icacls $folder /grant '*S-1-5-32-545:(R)'", ""},
			{"the bootstrap file inheriting", "Invoke-Icacls (Join-Path $folder 'bootstrap.hadv') /inheritance:e", nameFile},
			{"the sealed-key file owned by NETWORK SERVICE", "Invoke-Icacls (Join-Path $folder 'bootstrap-key.sealed') /setowner '*S-1-5-20'", nameSealedKey},
			{"the machine key pair usable by Users", "Set-KeyPair 'O:BAD:P(A;;GA;;;LS)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;BU)'", keyPairName},
		} {
			t.Run(row.name, func(t *testing.T) {
				folder := newWindowsFolder(t)
				before := setUp(t, folder, serviceAccountSID, row.change)
				contents := fileContents(t, folder)
				path := folder.path
				switch row.item {
				case "":
				case keyPairName:
					path = keyPairName
				default:
					path = filepath.Join(folder.path, row.item)
				}
				if err := New().SetToRule(Finding{Item: folder.items[path], Path: path}, serviceAccount); err != nil {
					t.Fatalf("refused: %v", err)
				}
				after := readItems(t, folder, "")
				if got, want := after[path], windowsRule(serviceAccount); !samePermissions(got, want) {
					t.Errorf("%s is %+v after SetToRule, want its rule %+v", path, got, want)
				}
				sameExceptWindows(t, before, after, path)
				for file, was := range fileContents(t, folder) {
					if contents[file] != was {
						t.Errorf("%s's bytes changed", file)
					}
				}
			})
		}
	})

	t.Run(lineSetToRuleLink, func(t *testing.T) {
		for _, row := range []struct {
			name string
			item Item
			make string // makes $link to $target
		}{
			{"the bootstrap file, a symbolic link to a file granting Users", ItemFile, "New-Item -ItemType SymbolicLink -Path $link -Target $target | Out-Null"},
			{"the folder, a junction to a folder granting Users", ItemFolder, "New-Item -ItemType Junction -Path $link -Target $target | Out-Null"},
		} {
			t.Run(row.name, func(t *testing.T) {
				folder := newWindowsFolder(t)
				target, link := filepath.Join(folder.path, nameFile), filepath.Join(folder.path, "link")
				if row.item == ItemFolder {
					target, link = folder.path, filepath.Join(t.TempDir(), "link")
				}
				before := setUp(t, folder, serviceAccountSID,
					"$target = '"+target+"'\n$link = '"+link+"'\nInvoke-Icacls $target /grant '*S-1-5-32-545:(R)'\n"+row.make)
				wantRefusal(t, New().SetToRule(Finding{Item: row.item, Path: link}, serviceAccount), Link)
				sameExceptWindows(t, before, readItems(t, folder, ""), "")
			})
		}
	})

	t.Run(lineSetToRuleSwarm, func(t *testing.T) {
		t.Run("a file named as the Swarm secret, granting Users", func(t *testing.T) {
			folder := newWindowsFolder(t)
			secret := filepath.Join(t.TempDir(), "heliosadvance-bootstrap-key")
			folder.items[secret] = ItemSwarmSecret
			before := setUp(t, folder, serviceAccountSID, "Set-Content -LiteralPath '"+secret+"' 'secret' -NoNewline\nInvoke-Icacls '"+secret+"' /grant '*S-1-5-32-545:(R)'")
			wantRefusal(t, New().SetToRule(Finding{Item: ItemSwarmSecret, Path: secret}, serviceAccount), LooserThanRule)
			sameExceptWindows(t, before, readItems(t, folder, ""), "")
		})
	})
}

// fatFolder makes a bootstrap folder on a FAT32 volume: a VHDX made, formatted and attached
// by diskpart, detached by Dismount-DiskImage when the row ends. Not by diskpart: given the
// temp folder's short name, which GitHub's runner has, it answers "already detached".
func fatFolder(t *testing.T) string {
	t.Helper()
	vhd := filepath.Join(t.TempDir(), "fat32.vhdx")
	script := "$vhd = '" + vhd + "'\n" + `$steps = Join-Path (Split-Path $vhd) 'diskpart.txt'
Set-Content $steps @("create vdisk file=""$vhd"" maximum=64 type=expandable", "select vdisk file=""$vhd""", 'attach vdisk', 'create partition primary', 'format fs=fat32 quick', 'assign')
diskpart /s $steps | Out-Null
if ($LASTEXITCODE) { throw "diskpart: $LASTEXITCODE" }
$letter = (Get-DiskImage -ImagePath $vhd | Get-Disk | Get-Partition | Get-Volume).DriveLetter
$folder = "${letter}:\folder"
New-Item -ItemType Directory $folder | Out-Null
foreach ($name in 'bootstrap.hadv', 'bootstrap.lock', 'bootstrap-key.sealed') { Set-Content -LiteralPath (Join-Path $folder $name) $name -NoNewline }
[Console]::Out.WriteLine($folder)
`
	t.Cleanup(func() {
		command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference = 'Stop'; Dismount-DiskImage -ImagePath '"+vhd+"' | Out-Null") //nolint:noctx // a cleanup runs after the test's context has ended
		command.Env = windowsPowerShellEnvironment()
		if out, err := command.CombinedOutput(); err != nil {
			t.Errorf("detaching the VHDX: %v\n%s", err, out)
		}
	})
	return strings.TrimSpace(string(powerShell(t, script)))
}

// holdWindowsLock has another process hold the file every usual way, opened with no sharing
// and a byte locked, until release.
func holdWindowsLock(t *testing.T, path string) (release func()) {
	t.Helper()
	child := exec.CommandContext(t.Context(), "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"$file = [IO.File]::Open('"+path+"', 'Open', 'ReadWrite', 'None'); $file.Lock(0, 1); "+
			"[Console]::Out.WriteLine('held'); [Console]::Out.Flush(); [void][Console]::In.ReadLine(); $file.Dispose()")
	child.Env = windowsPowerShellEnvironment()
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	lines := bufio.NewScanner(stdout)
	for lines.Scan() && strings.TrimSpace(lines.Text()) != "held" {
	}
	if lines.Err() != nil {
		t.Fatal(lines.Err())
	}
	return func() {
		_ = stdin.Close()
		_ = child.Wait()
	}
}
