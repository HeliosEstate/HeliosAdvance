// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap_test

import (
	"os"
	"path/filepath"
	"testing"
)

// The test's own copy of where key holders 4 and 5 keep the key, as the page names it: the
// variable in which systemd names the credential folder, and the one name both holders use.
const (
	systemdFolderVariable = "CREDENTIALS_DIRECTORY"
	heldKeyName           = "hadv-bootstrap-key"
)

// writeCredential makes a folder of the row's own holding contents as systemd's credential, as
// systemd would hand it to the service, and returns the folder.
func writeCredential(t *testing.T, contents []byte) string {
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

// nameCredential writes contents as systemd's credential in a folder of the row's own, names that
// folder in the variable for the row, and keeps it in the layout.
func (made *layout) nameCredential(t *testing.T, contents []byte) {
	t.Helper()
	made.credentialFolder = writeCredential(t, contents)
	t.Setenv(systemdFolderVariable, made.credentialFolder)
}
