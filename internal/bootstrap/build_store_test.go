// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The approved tests for issue #88, Build with the OS credential store, written by the QA
// session from the issue's behavior lines. Each group of rows quotes, word for word, the line
// its rows prove. The oracles are the OS credential stores themselves: the CNG key store
// driven through Windows PowerShell, and systemd-creds in a container that boots real
// systemd, 252 for a system credential and 257 for one scoped to an account. What Build seals
// is opened by the store, and the bootstrap file is read under what comes out. On Windows the
// rows run elevated (GitHub's runner, which has no TPM, and any elevated machine); the
// Linux rows run as root in the booted containers, through TestBuildStoreRowsInContainer.
// Docker is required, not optional: a missing docker is a failure, never a skip.
package bootstrap

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The image the per-use rows run in, built from oracle/systemd-257, and what
// -bootstrap.systemd tells the rows about it.
const (
	systemd257Image   = "heliosestate/systemd-257-oracle:0.1"
	systemdRunning257 = "running-257"
)

// The lines, word for word.
const (
	lineStoreRSA         = "Where the server runs Windows, when the source is FromOSStore, Build shall make a 2048-bit RSA machine key pair that is not exportable."
	lineStoreSoftware    = "Where the server runs Windows without a TPM, Build shall make the machine key pair in the Microsoft Software Key Storage Provider."
	lineStoreAccess      = "Where the server runs Windows, Build shall give the machine key pair an access list naming only the account, SYSTEM and Administrators."
	lineStoreExists      = "If a machine key pair of this package's name exists and the path is FirstSetup or Joining, then Build shall refuse with MachineKeyPairExists."
	lineStoreReplace     = "When the path is JoiningAgain or Restore, Build shall delete any machine key pair of this package's name before it makes the new one."
	lineStoreSealed      = "Where the server runs Windows, Build shall write bootstrap-key.sealed as the bootstrap key encrypted with RSA-OAEP under the machine key pair, as this package comment gives it."
	lineStoreWindowsMode = "Where the server runs Windows, when the source is FromOSStore, Build shall return ModeMachineKeyPair."
	lineStorePerUse      = "Where the server runs Linux with systemd 256 or later, when the source is FromOSStore, Build shall seal the bootstrap key as a credential scoped to the account and return ModeSystemdPerUse."
	lineStoreAtStart     = "Where the server runs Linux with systemd 250 to 255, when the source is FromOSStore, Build shall seal the bootstrap key as a system credential and return ModeSystemdAtStart."
	lineStoreHostKey     = "Where the server runs Linux without a TPM, Build shall have systemd seal the bootstrap key under the host key."
	lineStoreName        = "Where the server runs Linux, Build shall name the credential heliosadvance-bootstrap-key."
)

// TestBuildStoreRowsInContainer runs the Linux rows as root in systemd 252 and 257, each booted
// as its container's first process, with the oracle's program beside the test binary.
func TestBuildStoreRowsInContainer(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker is required for the Linux rows: %v", err)
	}
	architecture, err := exec.CommandContext(t.Context(), "docker", "version", "--format", "{{.Server.Arch}}").Output()
	if err != nil {
		t.Fatalf("docker version: %v", err)
	}
	dir := t.TempDir()
	build := exec.CommandContext(t.Context(), "go", "test", "-c", "-o", filepath.Join(dir, "bootstrap.test"), ".")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+strings.TrimSpace(string(architecture)), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the tests for Linux: %v\n%s", err, out)
	}
	copyOracleProgram(t, dir)
	for _, booted := range []struct{ image, under string }{
		{systemd252Image, systemdRunning252},
		{systemd257Image, systemdRunning257},
	} {
		t.Run("systemd "+strings.TrimPrefix(booted.under, "running-")+" running", func(t *testing.T) {
			t.Parallel()
			container := bootSystemd(t, booted.image, dir)
			runRows(t, "docker", "exec", container, "/t/bootstrap.test", "-test.v", "-test.count=1",
				"-test.run", "^TestBuildStoreLinux$", "-bootstrap.container", "-bootstrap.systemd="+booted.under)
		})
	}
}
