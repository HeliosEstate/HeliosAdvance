// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The approved tests for issue #86, Check and SetToRule, written by the QA session from the
// issue's behavior lines. Each group of rows quotes, word for word, the line its rows prove.
// The oracle is the OS's own tools: stat on Linux, Get-Acl, icacls and the CNG key store
// through PowerShell on Windows. Every row needs administrator or root rights but the
// NotElevated rows, which need their absence, so the rows run where those rights are:
// Linux rows as root in a container, from any machine with Docker, through
// TestLinuxRowsInContainer; Windows rows on an elevated machine (GitHub's Windows runner,
// whose job fails when it is not elevated), and the Windows NotElevated rows on one that is
// not. Docker is required, not optional: a missing docker is a failure, never a skip.
package bootstrap

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// The image the Linux rows run in, pinned: Debian's coreutils give stat, util-linux gives
// setpriv, and its passwd file gives the accounts nobody (the service account in the rows)
// and daemon (another account).
const rowImage = "debian@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818"

// The lines, word for word.
const (
	lineCheckNotElevated     = "If the process is neither elevated nor root, then Check shall refuse with NotElevated."
	lineCheckFolder          = "If the folder breaks a folder rule, then Check shall refuse with FolderRefused, naming the rule."
	lineCheckFinding         = "Check shall return one finding for each item set looser than its rule, with its path, what it found and its rule."
	lineCheckNoFinding       = "If every item holds to its rule, then Check shall return no finding."
	lineCheckAccount         = "Check shall judge which account owns each item, and each access list, against the account it is given."
	lineCheckLock            = "Check shall run without the lock."
	lineSetToRuleNotElevated = "If the process is neither elevated nor root, then SetToRule shall refuse with NotElevated."
	lineSetToRuleSets        = "SetToRule shall set the finding's item to its rule for the account it is given, and change nothing else."
	lineSetToRuleLink        = "If the finding's item is a symbolic link, a junction, or a file with more than one name, then SetToRule shall refuse with Link."
	lineCheckLink            = "If an item in the folder is a file with more than one name, then Check shall refuse with Link, naming the item."
	lineSetToRuleSwarm       = "If the finding's item is ItemSwarmSecret, then SetToRule shall refuse with LooserThanRule and change nothing."
)

// The rows every folder-rule line shares, by Check's, Build's and the unlocks' rows alike:
// one name for each case, so the same case reads the same under every line.
const (
	rowRelativePath = "a relative path"
	rowFolderLink   = "a symbolic link to a good folder"
	rowTmpfs        = "a folder on tmpfs"
	rowOverlayfs    = "a folder on overlayfs"
	rowFolder0755   = "the folder at 0755"
	relativeFolder  = "bootstrap" // a folder named by a relative path
)

// The bootstrap folder's file names, as the package comment lists them.
const (
	nameFile       = "bootstrap.hadv"
	nameLock       = "bootstrap.lock"
	nameSealedKey  = "bootstrap-key.sealed"
	nameSystemdKey = "bootstrap-key.cred"
	nameKeyFile    = "bootstrap.key"
	keyPairName    = "heliosadvance-bootstrap-key"
)

// TestLinuxRowsInContainer runs the Linux rows as root in a container: the package's tests
// built for Linux, a volume for the folders (ext4, which the FileSystem rule lets through),
// and a tmpfs mount that it refuses. The NotElevated rows run in the same container as the
// account nobody, through setpriv.
func TestLinuxRowsInContainer(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker is required for the Linux rows: %v", err)
	}
	architecture, err := exec.CommandContext(t.Context(), "docker", "version", "--format", "{{.Server.Arch}}").Output()
	if err != nil {
		t.Fatalf("docker version: %v", err)
	}
	dir := t.TempDir()
	// The account nobody runs the binary too, so the folder it is mounted from is readable.
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // nobody in the container reads the binary mounted from here
		t.Fatal(err)
	}
	build := exec.CommandContext(t.Context(), "go", "test", "-c", "-o", filepath.Join(dir, "bootstrap.test"), ".")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+strings.TrimSpace(string(architecture)), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the tests for Linux: %v\n%s", err, out)
	}
	script := `status=0
chmod 1777 /work
/t/bootstrap.test -test.v -test.count=1 -test.run '^TestLinuxAsRoot$' -bootstrap.container || status=1
setpriv --reuid=65534 --regid=65534 --clear-groups /t/bootstrap.test -test.v -test.count=1 -test.run '^TestLinuxNotElevated$' -bootstrap.container || status=1
exit $status`
	run := exec.CommandContext(t.Context(), "docker", "run", "--rm",
		"-v", dir+":/t:ro",
		"--mount", "type=volume,dst=/work",
		"--mount", "type=volume,dst=/var/lib/heliosadvance",
		"--tmpfs", "/mnt/tmpfs",
		rowImage, "sh", "-c", script)
	out, err := run.CombinedOutput()
	t.Logf("the Linux rows, as root and as nobody:\n%s", out)
	if err != nil {
		t.Fatalf("the Linux rows failed: %v", err)
	}
}

// refusalOf and wantRefusal are the file format's tests' own, in file_test.go: one package,
// one copy.

// wantFolderRefused fails the row unless err is a FolderRefused naming the rule given.
func wantFolderRefused(t *testing.T, err error, rule FolderRule) {
	t.Helper()
	refusal := refusalOf(err)
	if refusal == nil || refusal.Cause != FolderRefused {
		t.Fatalf("got %v, want a FolderRefused refusal", err)
	}
	if refusal.Rule != rule {
		t.Errorf("named rule %d, want %d", refusal.Rule, rule)
	}
}

// samePermissions compares two Permissions, the accounts in any order.
func samePermissions(got, want Permissions) bool {
	gotAccounts, wantAccounts := slices.Sorted(slices.Values(got.Accounts)), slices.Sorted(slices.Values(want.Accounts))
	return got.Owner == want.Owner && got.Mode == want.Mode && got.Inherited == want.Inherited &&
		slices.Equal(gotAccounts, wantAccounts)
}

// wantLinkNaming fails the row unless err refuses with Link, naming the item and its path.
func wantLinkNaming(t *testing.T, err error, item Item, path string) {
	t.Helper()
	refusal := refusalOf(err)
	if refusal == nil || refusal.Cause != Link || refusal.Item != item || refusal.Path != path {
		t.Errorf("got %v (%+v), want a refusal with Link naming item %d at %s", err, refusal, item, path)
	}
}

// sameFindings fails the row unless got holds exactly the findings in want, in any order.
func sameFindings(t *testing.T, got, want []Finding) {
	t.Helper()
	remaining := slices.Clone(want)
	for _, finding := range got {
		index := slices.IndexFunc(remaining, func(candidate Finding) bool {
			return candidate.Item == finding.Item && candidate.Path == finding.Path &&
				samePermissions(finding.Found, candidate.Found) && samePermissions(finding.Rule, candidate.Rule)
		})
		if index < 0 {
			t.Errorf("unexpected finding: %+v", finding)
			continue
		}
		remaining = slices.Delete(remaining, index, index+1)
	}
	for _, finding := range remaining {
		t.Errorf("missing finding: %+v", finding)
	}
	if t.Failed() {
		t.Logf("got %d findings, want %d (on %s)", len(got), len(want), runtime.GOOS)
	}
}
