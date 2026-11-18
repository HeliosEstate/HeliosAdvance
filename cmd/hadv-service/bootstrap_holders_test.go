// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main_test

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The test's own copy of where key holders 4 and 5 keep the key, as the page names it: the
// variable in which systemd names the credential folder, and the one name both holders use.
const (
	systemdFolderVariable = "CREDENTIALS_DIRECTORY"
	heldKeyName           = "hadv-bootstrap-key"
)

// writeCredentialFolder makes a folder of the row's own holding contents as systemd's credential,
// as systemd would hand it to the service, and returns the folder.
func writeCredentialFolder(t *testing.T, contents []byte) string {
	t.Helper()
	folder := filepath.Join(t.TempDir(), "credentials")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatalf("making the credential folder: %v", err)
	}
	if err := os.WriteFile(filepath.Join(folder, heldKeyName), contents, 0o600); err != nil {
		t.Fatalf("writing the credential: %v", err)
	}
	return folder
}

// namingFolder is the program's environment entry naming folder as the credential folder.
func namingFolder(folder string) string {
	return systemdFolderVariable + "=" + folder
}

// startWithEnvironment starts the program with the bootstrap folder at path and the entries given
// in its environment. Any credential folder this test process was given is taken out first, so a
// row that names none starts the program with none.
func startWithEnvironment(t *testing.T, path string, environment []string) *run {
	t.Helper()
	command := exec.CommandContext(t.Context(), programPath, databaseOption, path)
	command.Env = slices.DeleteFunc(cleanEnvironment(), func(entry string) bool {
		return strings.HasPrefix(entry, systemdFolderVariable+"=")
	})
	command.Env = append(command.Env, environment...)
	return startCommand(t, command)
}

// refusedWith is refused, the program started with the entries given in its environment: one
// start_failed line, a non-zero exit, neither a password nor the key in the log, nor any of what
// the row wrote as the credential or the secret; it returns the reason.
func (made *bootstrapFolder) refusedWith(t *testing.T, held []byte, environment ...string) string {
	t.Helper()
	program := startWithEnvironment(t, made.path, environment)
	reason := program.expectRefusal(t)
	expectNoPassword(t, program)
	made.expectKeyNotIn(t, program.text())
	expectHeldNotIn(t, program.text(), held)
	return reason
}

// expectHeldNotIn fails the row when the log holds what the row wrote as the credential or the
// secret: whole, in hex or in base64. Nothing written, nothing to look for.
func expectHeldNotIn(t *testing.T, log string, held []byte) {
	t.Helper()
	if len(held) == 0 {
		return
	}
	for name, secret := range map[string]string{
		"the credential or secret, whole":     string(held),
		"the credential or secret, in hex":    hex.EncodeToString(held),
		"the credential or secret, in base64": base64.StdEncoding.EncodeToString(held),
	} {
		if strings.TrimSpace(secret) != "" && strings.Contains(log, secret) {
			t.Fatalf("the local log holds %s:\n%s", name, log)
		}
	}
}
