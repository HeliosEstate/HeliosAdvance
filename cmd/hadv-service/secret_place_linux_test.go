// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The Swarm secret's one place on the machine, /run/secrets, made and planted through sudo as
// Swarm would make it in a service's container. A run marks a /run/secrets it makes with a file of
// its own; one found with that mark is a dead run's and is taken, and one found without it is not
// the run's to touch, so a row that needs the place fails there as one that cannot run.
package main_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The test's own copy of the secret's place, as the page names it, and the mark a run leaves in a
// /run/secrets it makes.
const (
	secretFolder = "/run/secrets"
	madeMark     = "hadv-qa-made"
)

// ownOwner and rootOwner name who a planted file belongs to: the runner's own user, which the
// program runs as in these rows, or root, as Swarm's default gives it.
const (
	ownOwner  = "own"
	rootOwner = "root"
)

// secretPath is where the engine looks for the secret.
var secretPath = filepath.Join(secretFolder, heldKeyName)

// takeSecretFolder readies /run/secrets for the row: it takes a dead run's, and fails the row as
// one that cannot run when the machine has one that is not a run's. When create is true it makes
// the folder, root's at mode 0755 as Swarm makes it, marked as the run's; either way the row's end
// removes whatever it made.
func takeSecretFolder(t *testing.T, create bool) {
	t.Helper()
	if code, output := runSudo(t, "true"); code != 0 {
		t.Fatalf("these rows need root through sudo without a password: %s", output)
	}
	if code, _ := runSudo(t, "test", "-e", secretFolder); code == 0 {
		if code, _ := runSudo(t, "test", "-e", filepath.Join(secretFolder, madeMark)); code != 0 {
			t.Fatalf("%s is on this machine and is not a test run's, so this row cannot run here", secretFolder)
		}
		removeSecretFolder(t)
	}
	if !create {
		return
	}
	t.Cleanup(func() { removeSecretFolder(t) })
	sudo(t, "install", "-d", "-m", "0755", "-o", "root", "-g", "root", secretFolder)
	sudo(t, "touch", filepath.Join(secretFolder, madeMark))
}

// removeSecretFolder removes a /run/secrets a run made, first undoing anything mounted on a file in
// it. The folder itself is no mount point, so the mounts inside it are found in the whole list.
func removeSecretFolder(t *testing.T) {
	t.Helper()
	if code, output := runSudo(t, "findmnt", "-n", "-l", "-o", "TARGET"); code == 0 {
		for target := range strings.FieldsSeq(output) {
			if strings.HasPrefix(target, secretFolder+"/") {
				if code, output := runSudo(t, "umount", target); code != 0 {
					t.Errorf("unmounting %s: %s", target, output)
				}
			}
		}
	}
	if code, output := runSudo(t, "rm", "-rf", secretFolder); code != 0 {
		t.Errorf("removing %s: %s", secretFolder, output)
	}
}

// plantFile writes contents at path inside /run/secrets, with the mode and owner given.
func plantFile(t *testing.T, path string, contents []byte, mode os.FileMode, owner string) {
	t.Helper()
	source := filepath.Join(t.TempDir(), "planted")
	if err := os.WriteFile(source, contents, 0o600); err != nil {
		t.Fatalf("writing what is to be planted: %v", err)
	}
	user, group := strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid())
	if owner == rootOwner {
		user, group = "root", "root"
	}
	sudo(t, "install", "-m", strconv.FormatUint(uint64(mode), 8), "-o", user, "-g", group, source, path)
}

// plantSecret writes contents as the secret, with the mode and owner given, as Swarm would.
func plantSecret(t *testing.T, contents []byte, mode os.FileMode, owner string) {
	t.Helper()
	plantFile(t, secretPath, contents, mode, owner)
}
