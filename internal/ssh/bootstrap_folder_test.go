// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The bootstrap folder every run of the program here is given: the bootstrap file sealed by the
// bootstrap file oracle, built once for the run from oracle/bootstrap-file with Free Pascal and
// self-tested, and the key file written by the test's own encoder, only the runner's account
// able to reach it.
package ssh_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// windowsOS is Windows as runtime.GOOS names it.
const windowsOS = "windows"

// bootstrapOraclePath is the built oracle, and bootstrapOracleFailure why it could not be built
// or failed its self-test: a missing oracle fails every row that starts the program.
var (
	bootstrapOraclePath    string
	bootstrapOracleFailure error
)

// writeBootstrapFolder makes a good bootstrap folder sealing text under a fresh key, and returns
// its path.
func writeBootstrapFolder(t *testing.T, text []byte) string {
	t.Helper()
	if bootstrapOracleFailure != nil {
		t.Fatalf("the bootstrap file oracle could not be built: %v", bootstrapOracleFailure)
	}
	key := make([]byte, 32)
	for bytes.Equal(key, make([]byte, 32)) {
		if _, err := rand.Read(key); err != nil {
			t.Fatalf("making a key: %v", err)
		}
	}
	work := t.TempDir()
	folder := filepath.Join(t.TempDir(), "bootstrap")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatalf("making the bootstrap folder: %v", err)
	}
	keyFile := filepath.Join(folder, "bootstrap.key")
	plainPath := filepath.Join(work, "plain")
	for path, contents := range map[string][]byte{keyFile: []byte(base64.StdEncoding.EncodeToString(key) + "\n"), plainPath: text} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
	}
	protectKeyFile(t, keyFile)
	ctx, cancel := context.WithTimeout(context.Background(), testrun.Patient(testrun.HangBound))
	defer cancel()
	output, err := exec.CommandContext(ctx, bootstrapOraclePath, "write", keyFile, plainPath,
		filepath.Join(folder, "bootstrap.hadv")).CombinedOutput()
	if err != nil {
		t.Fatalf("the oracle's write: %v: %s", err, strings.TrimSpace(string(output)))
	}
	return folder
}

// protectKeyFile gives a key file the permissions of a good one: on Linux mode 0600, the runner's
// own user its owner; on Windows its inherited entries removed and one entry allowing the
// runner's own account full control, set with icacls.
func protectKeyFile(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS != windowsOS {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatalf("protecting the key file: %v", err)
		}
		return
	}
	current, err := user.Current()
	if err != nil {
		t.Fatalf("reading this account: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), testrun.Patient(testrun.HangBound))
	defer cancel()
	output, err := exec.CommandContext(ctx, "icacls", path, "/inheritance:r", "/grant:r", "*"+current.Uid+":(F)").CombinedOutput()
	if err != nil {
		t.Fatalf("protecting the key file: %v: %s", err, strings.TrimSpace(string(output)))
	}
}
