// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The credential's name, as the contract gives it.
const credentialName = "heliosadvance-bootstrap-key" //nolint:gosec // a credential's name, not a secret

// The accounts the per-use rows decrypt as: the service account, and another, by their IDs.
const (
	serviceAccountID = "65534" // nobody
	otherAccountID   = "1"     // daemon
)

// credentialHeader is the first 16 bytes of a systemd credential, which name how it was
// sealed. systemd-creds writes base64 unless told otherwise, so a credential that decodes
// as base64 is read decoded.
func credentialHeader(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(data))); err == nil {
		data = decoded
	}
	if len(data) < 16 {
		t.Fatalf("%s holds %d bytes, too few for a credential", path, len(data))
	}
	return data[:16]
}

// sealedLikeThis is the header of a credential the oracle seals here, under the host key,
// scoped to the service account when scoped is set: what Build's credential must match.
func sealedLikeThis(t *testing.T, scoped bool) []byte {
	t.Helper()
	dir := t.TempDir()
	plain, sealed := filepath.Join(dir, "plain"), filepath.Join(dir, "sealed")
	if err := os.WriteFile(plain, rowKey(1), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"encrypt", "--name=" + credentialName, "--with-key=host", plain, sealed}
	if scoped {
		args = append([]string{"--user", "--uid=" + serviceAccount}, args...)
	}
	if out, err := exec.CommandContext(t.Context(), "systemd-creds", args...).CombinedOutput(); err != nil {
		t.Fatalf("the oracle's systemd-creds encrypt: %v\n%s", err, out)
	}
	return credentialHeader(t, sealed)
}

// readableCopy copies the credential where any account can read it, so that a refusal to
// decrypt it comes from the credential, not from the folder's permissions.
func readableCopy(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// t.TempDir's own parent is root's alone, so the copy goes in a folder of /tmp itself.
	dir, err := os.MkdirTemp("", "readable-") //nolint:usetesting // t.TempDir's parent keeps other accounts out
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // another account reads the copy; the refusal must come from the credential
		t.Fatal(err)
	}
	copied := filepath.Join(dir, "copy.cred")
	if err := os.WriteFile(copied, data, 0o644); err != nil { //nolint:gosec // as above
		t.Fatal(err)
	}
	return copied
}

// decrypt has systemd-creds decrypt the credential under the name: as root for a system
// credential when accountID is empty, or as that account for one scoped to an account.
func decrypt(t *testing.T, path, name, accountID string) ([]byte, error) {
	t.Helper()
	command := exec.CommandContext(t.Context(), "systemd-creds", "decrypt", "--name="+name, path, "-")
	if accountID != "" {
		command = exec.CommandContext(t.Context(), "setpriv", "--reuid="+accountID, "--regid="+accountID, "--clear-groups",
			"systemd-creds", "--user", "decrypt", "--name="+name, path, "-")
	}
	return command.Output()
}

// buildFromStore builds from the OS credential store in a folder of its own.
func buildFromStore(t *testing.T) (string, KeyMode, error) {
	t.Helper()
	folder := buildFolder(t, volume, "")
	mode, err := build(t, folder, rowFields(), FirstSetup, FromOSStore)
	return folder, mode, err
}

// TestBuildStoreLinux is the Linux rows, run in each booted systemd image: 252 seals a system
// credential and 257 one scoped to the account. Neither container has a TPM.
//
//nolint:paralleltest // the rows share the container's one systemd
func TestBuildStoreLinux(t *testing.T) {
	requireContainer(t)
	if os.Getuid() != 0 {
		t.Fatalf("the Linux rows run as root; running as uid %d", os.Getuid())
	}
	switch *systemdUnder {
	case systemdRunning252:
		t.Run(lineStoreAtStart, func(t *testing.T) {
			t.Run("systemd 252: a system credential, opened by systemd for root", func(t *testing.T) {
				folder, mode, err := buildFromStore(t)
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				credential := filepath.Join(folder, nameSystemdKey)
				key, err := decrypt(t, credential, credentialName, "")
				if err != nil || len(key) != 32 {
					t.Fatalf("systemd-creds did not open %s as a system credential to 32 bytes: %v (%d bytes)", credential, err, len(key))
				}
				if _, err := decrypt(t, readableCopy(t, credential), credentialName, serviceAccountID); err == nil {
					t.Error("the service account opened it as its own: scoped to an account, not a system credential")
				}
				wantBuilt(t, mode, nil, ModeSystemdAtStart, folder, key, rowFields())
			})
		})
		t.Run(lineStoreHostKey, func(t *testing.T) {
			t.Run("systemd 252, no TPM", func(t *testing.T) {
				folder, _, err := buildFromStore(t)
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if got, want := credentialHeader(t, filepath.Join(folder, nameSystemdKey)), sealedLikeThis(t, false); !bytes.Equal(got, want) {
					t.Errorf("sealed as %x, want %x, as systemd-creds seals under the host key", got, want)
				}
			})
		})
		t.Run(lineStoreName, func(t *testing.T) {
			t.Run("systemd 252: opened by its name and no other", func(t *testing.T) {
				folder, _, err := buildFromStore(t)
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				credential := filepath.Join(folder, nameSystemdKey)
				if _, err := decrypt(t, credential, credentialName, ""); err != nil {
					t.Errorf("not opened under the name %s: %v", credentialName, err)
				}
				if _, err := decrypt(t, credential, "another-name", ""); err == nil {
					t.Error("opened under another name")
				}
			})
		})
	case systemdRunning257:
		t.Run(lineStorePerUse, func(t *testing.T) {
			t.Run("systemd 257: scoped to the account, which alone opens it", func(t *testing.T) {
				folder, mode, err := buildFromStore(t)
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				credential := readableCopy(t, filepath.Join(folder, nameSystemdKey))
				key, err := decrypt(t, credential, credentialName, serviceAccountID)
				if err != nil || len(key) != 32 {
					t.Fatalf("the service account did not open it as its own to 32 bytes: %v (%d bytes)", err, len(key))
				}
				if _, err := decrypt(t, credential, credentialName, otherAccountID); err == nil {
					t.Error("another account opened it")
				}
				wantBuilt(t, mode, nil, ModeSystemdPerUse, folder, key, rowFields())
			})
		})
		t.Run(lineStoreHostKey, func(t *testing.T) {
			t.Run("systemd 257, no TPM", func(t *testing.T) {
				folder, _, err := buildFromStore(t)
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if got, want := credentialHeader(t, filepath.Join(folder, nameSystemdKey)), sealedLikeThis(t, true); !bytes.Equal(got, want) {
					t.Errorf("sealed as %x, want %x, as systemd-creds seals for the account under the host key", got, want)
				}
			})
		})
		t.Run(lineStoreName, func(t *testing.T) {
			t.Run("systemd 257: opened by its name and no other", func(t *testing.T) {
				folder, _, err := buildFromStore(t)
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				credential := readableCopy(t, filepath.Join(folder, nameSystemdKey))
				if _, err := decrypt(t, credential, credentialName, serviceAccountID); err != nil {
					t.Errorf("not opened under the name %s: %v", credentialName, err)
				}
				if _, err := decrypt(t, credential, "another-name", serviceAccountID); err == nil {
					t.Error("opened under another name")
				}
			})
		})
	default:
		t.Fatalf("-bootstrap.systemd is %q: these rows run under systemd 252 or 257", *systemdUnder)
	}
}
