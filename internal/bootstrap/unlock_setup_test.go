// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The approved tests for issue #89, UnlockForSetup and the handle it returns, written by the QA
// session from the issue's behavior lines. Each group of rows quotes, word for word, the line
// its rows prove. Each row makes its folder by hand, not through Build: the bootstrap file by
// the format's own writer, which the file format's rows prove against the oracle; a credential
// by systemd-creds; a machine key pair and its sealed key by the CNG key store through Windows
// PowerShell. UnlockForSetup needs administrator or root rights, so the rows run where Build's
// do: Linux rows as root in containers (no systemd, systemd 252 and 257 booted), through
// TestUnlockSetupRowsInContainer, and Windows rows elevated, with the NotElevated rows on a
// machine that is not. Docker is required, not optional: a missing docker is a failure, never
// a skip.
package bootstrap

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The lines, word for word.
const (
	lineHandleFields        = "Fields shall return the known fields in memory of their own, so that a change to what it returns changes nothing in the handle."
	lineHandleHolding       = "Holding shall return how the bootstrap key was held when the handle was unlocked."
	lineHandleCloseLock     = "Close shall release the lock."
	lineHandleCloseTwice    = "If Close is called a second time, then Close shall do nothing."
	lineSetupNotElevated    = "If the process is neither elevated nor root, then UnlockForSetup shall refuse with NotElevated."
	lineSetupInUse          = "If another handle holds the lock, then UnlockForSetup shall refuse with InUse."
	lineSetupLockMade       = "If bootstrap.lock is absent, then UnlockForSetup shall create it already set to its rule for the account it is given."
	lineSetupPerUseAccount  = "Where the mode is ModeSystemdPerUse, UnlockForSetup shall have systemd decrypt the credential scoped to the account it is given."
	lineSetupFolder         = "If the folder breaks a folder rule, then UnlockForSetup shall refuse with FolderRefused, naming the rule."
	lineSetupLink           = "If the bootstrap file or the key file is a symbolic link, a junction, or a file with more than one name, then UnlockForSetup shall refuse with Link."
	lineSetupLooser         = "UnlockForSetup shall not refuse an item set looser than its rule."
	lineSetupHalfMade       = "If bootstrap.hadv.new is in the folder, then UnlockForSetup shall delete it."
	lineSetupMode           = "If the mode is not one of this platform's, then UnlockForSetup shall refuse with SourceRefused."
	lineSetupNoKeySource    = "If the mode is ModeContainer and neither a Swarm secret nor a key file is present, then UnlockForSetup shall refuse with NoKeySource."
	lineSetupBothKeySources = "If the mode is ModeContainer and both a Swarm secret and a key file are present, then UnlockForSetup shall refuse with BothKeySources."
	lineSetupKeyNotFound    = "If the mode is not ModeContainer and the sealed-key file, the credential or the key file is absent, then UnlockForSetup shall refuse with KeyNotFound."
	lineSetupMalformed      = "If a key file or Swarm secret holds anything other than 32 bytes as base64 in 44 characters with at most one trailing newline, then UnlockForSetup shall refuse with KeyFileMalformed."
	lineSetupNotUnsealed    = "If the OS credential store does not unseal the bootstrap key, then UnlockForSetup shall refuse with KeyNotUnsealed."
	lineSetupFileNotFound   = "If the bootstrap file is absent, then UnlockForSetup shall refuse with FileNotFound."
	lineSetupSystemd        = "Where the server runs Linux with systemd, UnlockForSetup shall have systemd decrypt the credential itself, in either mode."
	lineSetupHandle         = "When UnlockForSetup unlocks the bootstrap file, it shall return a handle that holds the lock until Close."
)

// TestUnlockSetupRowsInContainer runs the Linux rows as root in containers: with no systemd
// (then the NotElevated row as nobody), and with systemd 252 and 257 booted.
func TestUnlockSetupRowsInContainer(t *testing.T) {
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
	t.Run("no systemd", func(t *testing.T) {
		t.Parallel()
		script := `status=0
chmod 1777 /work
/t/bootstrap.test -test.v -test.count=1 -test.run '^TestUnlockSetupLinuxAsRoot$' -bootstrap.container || status=1
setpriv --reuid=65534 --regid=65534 --clear-groups /t/bootstrap.test -test.v -test.count=1 -test.run '^TestUnlockSetupLinuxNotElevated$' -bootstrap.container || status=1
exit $status`
		runRows(t, "docker", "run", "--rm", "-v", dir+":/t:ro",
			"--mount", "type=volume,dst=/work", "--mount", "type=volume,dst=/var/lib/heliosadvance",
			"--tmpfs", "/mnt/tmpfs", rowImage, "sh", "-c", script)
	})
	for _, booted := range []struct{ image, under string }{
		{systemd252Image, systemdRunning252},
		{systemd257Image, systemdRunning257},
	} {
		t.Run("systemd "+strings.TrimPrefix(booted.under, "running-")+" running", func(t *testing.T) {
			t.Parallel()
			container := bootSystemd(t, booted.image, dir)
			runRows(t, "docker", "exec", container, "/t/bootstrap.test", "-test.v", "-test.count=1",
				"-test.run", "^TestUnlockSetupLinuxSystemd$", "-bootstrap.container", "-bootstrap.systemd="+booted.under)
		})
	}
}

// writeGoodFile writes a bootstrap file of rowFields under the key, by the format's own writer.
func writeGoodFile(t *testing.T, path string, key []byte) {
	t.Helper()
	file := &bootstrapFile{}
	file.setFields(rowFields())
	var sealed bytes.Buffer
	if err := file.writeTo(&sealed, key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, sealed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// wantUnlocked fails the row unless UnlockForSetup returned a handle holding rowFields, and
// closes it when the row ends.
func wantUnlocked(t *testing.T, handle SetupHandle, err error) SetupHandle {
	t.Helper()
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	if handle == nil {
		t.Fatal("no handle and no refusal")
	}
	t.Cleanup(handle.Close)
	sameFields(t, handle.Fields(), rowFields())
	return handle
}

// unlockSetup unlocks the folder in the mode, for hadv-setup, with the rows' service account.
func unlockSetup(t *testing.T, folder string, mode KeyMode) (SetupHandle, error) {
	t.Helper()
	return New().UnlockForSetup(t.Context(), folder, mode, serviceAccount)
}

// wantRefused fails the row unless the unlock was refused with the cause, closing a handle it
// returned instead.
func wantRefused(t *testing.T, handle SetupHandle, err error, cause Cause) {
	t.Helper()
	if handle != nil {
		handle.Close()
	}
	wantRefusal(t, err, cause)
}
