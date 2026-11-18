// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The Swarm secret's one place on the machine, /run/secrets, made and planted through sudo as
// Swarm would make it in a service's container. A run marks a /run/secrets it makes with a file of
// its own; one found with that mark is a dead run's and is taken, and one found without it is not
// the run's to touch, so a row that needs the place fails there as one that cannot run.
package bootstrap_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// The test's own copy of the secret's place, as the page names it, and the mark a run leaves in a
// /run/secrets it made.
const (
	secretFolder = "/run/secrets"
	madeMark     = "hadv-qa-made"
)

// ownOwner and rootOwner name who a planted file belongs to: the runner's own user, which is the
// engine's account in these rows, or root, as Swarm's default gives it.
const (
	ownOwner  = "own"
	rootOwner = "root"
)

// secretPath is where Open looks for the secret.
var secretPath = filepath.Join(secretFolder, heldKeyName)

// asRoot runs a command through sudo without a password, bounded by the hang bound, and returns
// its exit code and output; a sudo that cannot be run at all fails the row.
func asRoot(t *testing.T, arguments ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testrun.Patient(testrun.HangBound))
	defer cancel()
	command := exec.CommandContext(ctx, "sudo", append([]string{"-n"}, arguments...)...)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("sudo %s had not ended within %v: %s", strings.Join(arguments, " "), testrun.Patient(testrun.HangBound), output)
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), string(output)
	}
	if err != nil {
		t.Fatalf("running sudo %s: %v", strings.Join(arguments, " "), err)
	}
	return 0, string(output)
}

// mustAsRoot is asRoot for a command that must succeed.
func mustAsRoot(t *testing.T, arguments ...string) {
	t.Helper()
	if code, output := asRoot(t, arguments...); code != 0 {
		t.Fatalf("sudo %s ended %d: %s", strings.Join(arguments, " "), code, output)
	}
}

// takeSecretFolder readies /run/secrets for the row: it takes a dead run's, and fails the row as
// one that cannot run when the machine has one that is not a run's. When create is true it makes
// the folder, root's at mode 0755 as Swarm makes it, marked as the run's; either way the row's end
// removes whatever it made.
func takeSecretFolder(t *testing.T, create bool) {
	t.Helper()
	if code, output := asRoot(t, "true"); code != 0 {
		t.Fatalf("these rows need root through sudo without a password: %s", output)
	}
	if code, _ := asRoot(t, "test", "-e", secretFolder); code == 0 {
		if code, _ := asRoot(t, "test", "-e", filepath.Join(secretFolder, madeMark)); code != 0 {
			t.Fatalf("%s is on this machine and is not a test run's, so this row cannot run here", secretFolder)
		}
		removeSecretFolder(t)
	}
	if !create {
		return
	}
	t.Cleanup(func() { removeSecretFolder(t) })
	mustAsRoot(t, "install", "-d", "-m", "0755", "-o", "root", "-g", "root", secretFolder)
	mustAsRoot(t, "touch", filepath.Join(secretFolder, madeMark))
}

// removeSecretFolder removes a /run/secrets a run made, first undoing anything mounted on a file in
// it. The folder itself is no mount point, so the mounts inside it are found in the whole list.
func removeSecretFolder(t *testing.T) {
	t.Helper()
	if code, output := asRoot(t, "findmnt", "-n", "-l", "-o", "TARGET"); code == 0 {
		for target := range strings.FieldsSeq(output) {
			if strings.HasPrefix(target, secretFolder+"/") {
				if code, output := asRoot(t, "umount", target); code != 0 {
					t.Errorf("unmounting %s: %s", target, output)
				}
			}
		}
	}
	if code, output := asRoot(t, "rm", "-rf", secretFolder); code != 0 {
		t.Errorf("removing %s: %s", secretFolder, output)
	}
}

// plantSecret writes contents as the secret, with the mode and owner given, as Swarm would.
func plantSecret(t *testing.T, contents []byte, mode os.FileMode, owner string) {
	t.Helper()
	plantFile(t, secretPath, contents, mode, owner)
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
	mustAsRoot(t, "install", "-m", strconv.FormatUint(uint64(mode), 8), "-o", user, "-g", group, source, path)
}

// bindOwnMemory puts this process's own memory file, /proc/<pid>/mem, at path, bound there through
// sudo, and takes it away when the row ends. This process opens it as a regular file, mode 0600,
// its own user's, and its first read fails: a file that opens and will not read. Another process
// may not open it at all.
func bindOwnMemory(t *testing.T, path string) {
	t.Helper()
	mustAsRoot(t, "touch", path)
	mustAsRoot(t, "mount", "--bind", "/proc/"+strconv.Itoa(os.Getpid())+"/mem", path)
	t.Cleanup(func() {
		if code, output := asRoot(t, "umount", path); code != 0 {
			t.Errorf("unmounting %s: %s", path, output)
		}
	})
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("this process's memory file at %s is not a regular file of mode 0600 (%v, %v): a fault in the test", path, info, err)
	}
}
