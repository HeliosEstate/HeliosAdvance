// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The line for every file in the bootstrap folder, word for word.
const lineEveryFileThroughHandle = "The bootstrap package shall open every file in the bootstrap folder relative to the folder's handle and without following a link, create every file it creates exclusively, and refuse with Link any item in the folder that is a symbolic link, a junction or a file with more than one name before it reads it, writes it, changes its owner or mode, or puts a file in its place."

// decoyNames is every name Build touches in the bootstrap folder, on either platform.
var decoyNames = []string{nameFile, nameFile + ".new", nameLock, nameSealedKey, nameSystemdKey, nameSystemdKey + ".new"}

// makeDecoy makes a folder outside the bootstrap folder holding a file of every name Build
// touches, each holding its own name: where a link planted in the bootstrap folder points.
func makeDecoy(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range decoyNames {
		if err := os.WriteFile(filepath.Join(path, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// wantDecoyUnchanged fails the row unless the decoy holds exactly its files, each with its own
// name as its contents: Build wrote, renamed or deleted nothing outside the bootstrap folder.
func wantDecoyUnchanged(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatalf("reading the folder outside: %v", err)
	}
	found := []string{}
	for _, entry := range entries {
		found = append(found, entry.Name())
		data, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			t.Errorf("reading %s outside: %v", entry.Name(), err)
		} else if string(data) != entry.Name() {
			t.Errorf("%s outside the bootstrap folder was written: it holds %d bytes", entry.Name(), len(data))
		}
	}
	want := slices.Clone(decoyNames)
	slices.Sort(want)
	slices.Sort(found)
	if !slices.Equal(found, want) {
		t.Errorf("the folder outside holds %v, want %v: Build created, renamed or deleted a file there", found, want)
	}
}

// TestBuildHandleRowsInContainer runs the Linux rows for the line as root in systemd 252 and 257,
// each booted as its container's first process: 252 seals a system credential and 257 one scoped
// to the account, so both ways the credential is sealed are covered.
func TestBuildHandleRowsInContainer(t *testing.T) {
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
				"-test.run", "^TestBuildHandleLinux$", "-bootstrap.container", "-bootstrap.systemd="+booted.under)
		})
	}
}
