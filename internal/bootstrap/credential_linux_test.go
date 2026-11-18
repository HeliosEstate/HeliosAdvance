// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Open under key holder 4, systemd's credential, on Linux: the variable systemd names the
// credential folder in is set to a folder the row made, which Open takes as given. Each bootstrap
// folder under key holder 4 that Open must refuse also holds a good key file with the very key the
// file is sealed under, so an Open that took the key from the key file would open it; each one Open
// must open holds no key file, or a key file Open would refuse. The rows set the process's
// environment, so they run alone, one after the other.
package bootstrap_test

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/bootstrap"
)

// holder4Layout makes a bootstrap folder under key holder 4 beside a good key file holding the very
// key it is sealed under, and names a folder of the row's own holding credential, which the layout
// records as a secret.
func holder4Layout(t *testing.T, credential []byte) *layout {
	t.Helper()
	made := makeFolderWith(t, plaintextOf(t, 64), "holder 4")
	made.credential = credential
	made.nameCredential(t, credential)
	return made
}

// credentialPath is where the credential is in the folder the row named.
func (made *layout) credentialPath() string {
	return filepath.Join(made.credentialFolder, heldKeyName)
}

// unsetCredentials takes the variable out of the process's environment for the row, and gives the
// value it had back when the row ends.
func unsetCredentials(t *testing.T) {
	t.Helper()
	t.Setenv(systemdFolderVariable, "")
	if err := os.Unsetenv(systemdFolderVariable); err != nil {
		t.Fatalf("unsetting %s: %v", systemdFolderVariable, err)
	}
}

// credentialOutcomes are the ways Open ends under key holder 4, each reached by a folder of its
// own, for the closing line's rows.
func credentialOutcomes() map[string]outcome {
	return map[string]outcome{
		"opened with the credential": {want: nil, make: func(t *testing.T) *layout {
			t.Helper()
			made := makeFolderWith(t, plaintextOf(t, 64), "holder 4")
			remove(t, made.keyFile)
			made.credential = made.key
			made.nameCredential(t, made.key)
			return made
		}},
		"ErrCredentialUnset": {want: bootstrap.ErrCredentialUnset, make: func(t *testing.T) *layout {
			t.Helper()
			made := makeFolderWith(t, plaintextOf(t, 64), "holder 4")
			unsetCredentials(t)
			return made
		}},
		"ErrCredentialMissing": {want: bootstrap.ErrCredentialMissing, make: func(t *testing.T) *layout {
			t.Helper()
			made := holder4Layout(t, nil)
			remove(t, made.credentialPath())
			return made
		}},
		"ErrCredentialUnreadable, a folder as the credential": {want: bootstrap.ErrCredentialUnreadable, make: func(t *testing.T) *layout {
			t.Helper()
			made := holder4Layout(t, nil)
			remove(t, made.credentialPath())
			if err := os.Mkdir(made.credentialPath(), 0o700); err != nil {
				t.Fatalf("making the folder: %v", err)
			}
			return made
		}},
		"ErrCredentialForm": {want: bootstrap.ErrCredentialForm, make: func(t *testing.T) *layout {
			t.Helper()
			key, _ := newKey(t)
			return holder4Layout(t, key[:31])
		}},
		"ErrUnseal, another key as the credential": {want: bootstrap.ErrUnseal, make: func(t *testing.T) *layout {
			t.Helper()
			other, _ := newKey(t)
			return holder4Layout(t, other)
		}},
	}
}

// TestLinuxRootCredential needs root through sudo, which CI's runner has, to give the credential
// another owner and to bind a file that will not read in its place; it sets the process's
// environment, so it runs alone.
func TestLinuxRootCredential(t *testing.T) { //nolint:paralleltest // it sets the process's environment
	if code, output := asRoot(t, "true"); code != 0 {
		t.Fatalf("these rows need root through sudo without a password: %s", output)
	}
	t.Run("Open shall judge no owner, permissions or link of the credential or its folder.", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
		t.Run("the credential root's, mode 0644, no key file: opens, the plaintext exact", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
			made := makeFolderWith(t, plaintextOf(t, 64), "holder 4")
			remove(t, made.keyFile)
			made.nameCredential(t, made.key)
			credential := made.credentialPath()
			mustAsRoot(t, "chown", "root:root", credential)
			mustAsRoot(t, "chmod", "0644", credential)
			t.Cleanup(func() {
				if code, output := asRoot(t, "rm", "-f", credential); code != 0 {
					t.Errorf("removing the root-owned credential: %s", output)
				}
			})
			made.expectOpened(t)
		})
	})
	t.Run("If the folder or the credential will not open or read, or the credential is not a regular file, then Open shall return ErrCredentialUnreadable.", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
		t.Run("a credential that opens and fails its first read, this process's own memory file bound in its place: ErrCredentialUnreadable", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
			made := holder4Layout(t, nil)
			bindOwnMemory(t, made.credentialPath())
			made.expectRefused(t, bootstrap.ErrCredentialUnreadable)
		})
	})
}

// TestLinuxCredential sets the process's environment, so it runs alone, its rows one after the
// other.
func TestLinuxCredential(t *testing.T) {
	t.Run("Under KeyHolderSystemd, Open shall take the key only from CredentialName in the folder named in CredentialsVariable.", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
		t.Run("the raw key at hadv-bootstrap-key, mode 0600, and no key file: opens, the plaintext exact", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
			made := makeFolderWith(t, plaintextOf(t, 64), "holder 4")
			remove(t, made.keyFile)
			made.credential = made.key
			made.nameCredential(t, made.key)
			made.expectOpened(t)
		})
		t.Run("another key at hadv-bootstrap-key, the right one beside it as bootstrap.key and as hadv-bootstrap-key.cred, and in the bootstrap folder's key file: ErrUnseal", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
			other, _ := newKey(t)
			made := holder4Layout(t, other)
			folder := filepath.Dir(made.credentialPath())
			for name, contents := range map[string][]byte{keyFileName: []byte(made.keyText), heldKeyName + ".cred": made.key} {
				if err := os.WriteFile(filepath.Join(folder, name), contents, 0o600); err != nil {
					t.Fatalf("writing %s beside the credential: %v", name, err)
				}
			}
			made.expectRefused(t, bootstrap.ErrUnseal)
		})
	})

	t.Run("If CredentialsVariable is unset or empty, then Open shall return ErrCredentialUnset.", func(t *testing.T) {
		t.Run("the variable unset, a good key file beside the bootstrap file: ErrCredentialUnset", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
			made := makeFolderWith(t, plaintextOf(t, 64), "holder 4")
			unsetCredentials(t)
			made.expectRefused(t, bootstrap.ErrCredentialUnset)
		})
		t.Run("the variable empty, a good key file beside the bootstrap file: ErrCredentialUnset", func(t *testing.T) {
			made := makeFolderWith(t, plaintextOf(t, 64), "holder 4")
			t.Setenv(systemdFolderVariable, "")
			made.expectRefused(t, bootstrap.ErrCredentialUnset)
		})
	})

	t.Run("If the folder CredentialsVariable names, or CredentialName in it, does not exist, then Open shall return ErrCredentialMissing.", func(t *testing.T) {
		t.Run("the folder it names not there: ErrCredentialMissing", func(t *testing.T) {
			made := makeFolderWith(t, plaintextOf(t, 64), "holder 4")
			t.Setenv(systemdFolderVariable, filepath.Join(t.TempDir(), "gone"))
			made.expectRefused(t, bootstrap.ErrCredentialMissing)
		})
		t.Run("the folder there without the credential: ErrCredentialMissing", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
			made := holder4Layout(t, nil)
			remove(t, made.credentialPath())
			made.expectRefused(t, bootstrap.ErrCredentialMissing)
		})
	})

	t.Run("If the folder or the credential will not open or read, or the credential is not a regular file, then Open shall return ErrCredentialUnreadable.", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
		t.Run("the folder mode 0000, no one may open it: ErrCredentialUnreadable", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
			made := holder4Layout(t, nil)
			makeUnopenable(t, filepath.Dir(made.credentialPath()))
			made.expectRefused(t, bootstrap.ErrCredentialUnreadable)
		})
		t.Run("the credential mode 0000, no one may open it: ErrCredentialUnreadable", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
			key, _ := newKey(t)
			made := holder4Layout(t, key)
			makeUnopenable(t, made.credentialPath())
			made.expectRefused(t, bootstrap.ErrCredentialUnreadable)
		})
		t.Run("a folder in the credential's place: ErrCredentialUnreadable", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
			made := holder4Layout(t, nil)
			remove(t, made.credentialPath())
			if err := os.Mkdir(made.credentialPath(), 0o700); err != nil {
				t.Fatalf("making the folder: %v", err)
			}
			made.expectRefused(t, bootstrap.ErrCredentialUnreadable)
		})
		t.Run("a named pipe in the credential's place, no writer: ErrCredentialUnreadable within the hang bound", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
			made := holder4Layout(t, nil)
			remove(t, made.credentialPath())
			makePipe(t, made.credentialPath())
			made.expectRefused(t, bootstrap.ErrCredentialUnreadable)
		})
	})

	t.Run("If the credential is not exactly KeyBytes bytes, or is KeyBytes zero bytes, then Open shall return ErrCredentialForm, having read at most KeyBytes and one byte more of it.", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
		for name, build := range map[string]func(made *layout) []byte{
			"31 bytes, the right key's first 31":      func(made *layout) []byte { return made.key[:31] },
			"33 bytes, the right key and a line feed": func(made *layout) []byte { return append(bytes.Clone(made.key), '\n') },
			"0 bytes": func(*layout) []byte { return []byte{} },
			"45 bytes, the right key in the key file's form": func(made *layout) []byte { return []byte(made.keyText) },
			"1 MiB, the right key then zeros": func(made *layout) []byte {
				return append(bytes.Clone(made.key), make([]byte, 1<<20-len(made.key))...)
			},
		} {
			t.Run(name+": ErrCredentialForm", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
				made := makeFolderWith(t, plaintextOf(t, 64), "holder 4")
				made.credential = build(made)
				made.nameCredential(t, made.credential)
				made.expectRefused(t, bootstrap.ErrCredentialForm)
			})
		}
		t.Run("the key of 32 zero bytes, the bootstrap file sealed under it by the oracle: ErrCredentialForm", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
			zero := base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
			made := makeFolderWith(t, plaintextOf(t, 64), "holder 4")
			made.writeFile(t, seal(t, zero, made.plaintext, "holder 4"))
			made.nameCredential(t, make([]byte, 32))
			made.expectRefused(t, bootstrap.ErrCredentialForm)
		})
		t.Run("exactly the 32 bytes of the key, no key file: opens, the plaintext exact", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
			made := makeFolderWith(t, plaintextOf(t, 64), "holder 4")
			remove(t, made.keyFile)
			made.nameCredential(t, made.key)
			made.expectOpened(t)
		})
	})

	t.Run("Open shall judge no owner, permissions or link of the credential or its folder.", func(t *testing.T) {
		for name, spoil := range map[string]func(t *testing.T, credential string){
			"the credential mode 0644": func(t *testing.T, credential string) { t.Helper(); setMode(t, credential, 0o644) },
			"the credential mode 0666": func(t *testing.T, credential string) { t.Helper(); setMode(t, credential, 0o666) },
			"the folder mode 0777": func(t *testing.T, credential string) {
				t.Helper()
				setMode(t, filepath.Dir(credential), 0o777)
			},
			"the credential a symbolic link to the key in a file outside the folder": func(t *testing.T, credential string) {
				t.Helper()
				key, err := os.ReadFile(credential)
				if err != nil {
					t.Fatalf("reading the credential: %v", err)
				}
				remove(t, credential)
				linkOutside(t, credential, key)
			},
			"the folder named a symbolic link to the folder": func(t *testing.T, credential string) {
				t.Helper()
				link := filepath.Join(t.TempDir(), "linked")
				if err := os.Symlink(filepath.Dir(credential), link); err != nil {
					t.Fatalf("linking to the credential folder: %v", err)
				}
				t.Setenv(systemdFolderVariable, link)
			},
		} {
			t.Run(name+", no key file: opens, the plaintext exact", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
				made := makeFolderWith(t, plaintextOf(t, 64), "holder 4")
				remove(t, made.keyFile)
				made.nameCredential(t, made.key)
				spoil(t, made.credentialPath())
				made.expectOpened(t)
			})
		}
	})

	t.Run("If the bootstrap file is shorter than HeaderBytes, NonceBytes and TagBytes together, or its first HeaderBytes are not Magic, FormatVersion, then KeyHolderKeyFile with a sealed-key length of 0, on Windows KeyHolderTPM or KeyHolderSoftwareKeyStore with a sealed-key length of SealedKeyBytes, or on Linux KeyHolderSystemd or KeyHolderSwarm with a sealed-key length of 0, or, under key holder 2 or 3, the file is too short for the sealed key, nonce and tag, or the sealed key's first KeyNameBytes are not KeyNamePrefix and 32 lower-case hex digits, then Open shall return ErrHeader before it opens the key file, asks a key store, or reads a credential or secret.", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
		for name, edits := range map[string]string{
			"key holder 4, 293 sealed bytes, a name in its form": "holder 4\nsealed \"hadv-0123456789abcdef0123456789abcdef\" random:256",
			"key holder 4, a sealed-key length of 1 that lies":   "holder 4\nsealed-length 1",
		} {
			t.Run(name+", a good credential named: ErrHeader", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
				made := makeFolderWith(t, plaintextOf(t, 64), edits)
				made.credential = made.key
				made.nameCredential(t, made.key)
				made.expectRefused(t, bootstrap.ErrHeader)
			})
			t.Run(name+", the variable unset: ErrHeader, not ErrCredentialUnset", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
				made := makeFolderWith(t, plaintextOf(t, 64), edits)
				unsetCredentials(t)
				made.expectRefused(t, bootstrap.ErrHeader)
			})
		}
	})

	t.Run("Open shall take the key under KeyHolderKeyFile by the lines on the key file, under KeyHolderTPM or KeyHolderSoftwareKeyStore by the lines on the key store key, under KeyHolderSystemd by the lines on systemd's credential, and under KeyHolderSwarm by the lines on the Swarm secret, never by another holder's; it shall open the key file only under key holder 1.", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
		t.Run("key holder 1, the key file missing, the right raw key as the credential named: ErrKeyFileMissing", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
			made := makeFolder(t)
			remove(t, made.keyFile)
			made.credential = made.key
			made.nameCredential(t, made.key)
			made.expectRefused(t, bootstrap.ErrKeyFileMissing)
		})
		for name, spoil := range map[string]func(t *testing.T, made *layout){
			"the key file missing":         func(t *testing.T, made *layout) { t.Helper(); remove(t, made.keyFile) },
			"the key file no one may open": func(t *testing.T, made *layout) { t.Helper(); makeUnopenable(t, made.keyFile) },
			"the key file open to others":  func(t *testing.T, made *layout) { t.Helper(); openToOthers(t, made.keyFile) },
			"the key file out of its form": func(t *testing.T, made *layout) { t.Helper(); made.writeKey(t, baseOf(made)[:43]) },
			"a folder in the key file's place": func(t *testing.T, made *layout) {
				t.Helper()
				remove(t, made.keyFile)
				if err := os.Mkdir(made.keyFile, 0o700); err != nil {
					t.Fatalf("making the folder: %v", err)
				}
			},
		} {
			t.Run("key holder 4, "+name+", the right raw key as the credential: opens, the plaintext exact", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
				made := makeFolderWith(t, plaintextOf(t, 64), "holder 4")
				made.nameCredential(t, made.key)
				spoil(t, made)
				made.expectOpened(t)
			})
		}
		t.Run("key holder 4, the credential missing, beside a good key file holding the very key: ErrCredentialMissing", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
			made := holder4Layout(t, nil)
			remove(t, made.credentialPath())
			made.expectRefused(t, bootstrap.ErrCredentialMissing)
		})
	})

	t.Run("Open shall check in the order of these lines and return the first refusal that applies.", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
		t.Run("the credential 33 bytes and a tag that does not verify: ErrCredentialForm", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
			made := makeFolderWith(t, plaintextOf(t, 64), "holder 4\nflip 60")
			made.credential = append(bytes.Clone(made.key), '\n')
			made.nameCredential(t, made.credential)
			made.expectRefused(t, bootstrap.ErrCredentialForm)
		})
		t.Run("the credential missing under a sealed-key length of 1 that lies: ErrHeader", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
			made := makeFolderWith(t, plaintextOf(t, 64), "holder 4\nsealed-length 1")
			made.nameCredential(t, nil)
			remove(t, made.credentialPath())
			made.expectRefused(t, bootstrap.ErrHeader)
		})
		t.Run("the credential missing and the bootstrap file missing: ErrFileMissing", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
			made := makeFolderWith(t, plaintextOf(t, 64), "holder 4")
			unsetCredentials(t)
			remove(t, made.file)
			made.expectRefused(t, bootstrap.ErrFileMissing)
		})
	})

	t.Run("No error the bootstrap package returns shall hold, in its text, the key or any part of what it reads: the bootstrap file, the key file, systemd's credential or the Swarm secret.", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
		// Every refusal row above checks its error's text the same way; this one puts a credential
		// of printable bytes where a careless error would quote it.
		t.Run("a credential of 32 printable bytes and a line feed: ErrCredentialForm, none of it in the error", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
			text := base64.StdEncoding.EncodeToString([]byte("foobarfoobarfoobarfoobarfoobarfo")) + "\n"
			made := makeFolderWith(t, plaintextOf(t, 64), "holder 4")
			made.key, made.keyText = []byte("foobarfoobarfoobarfoobarfoobarfo"), text
			made.writeFile(t, seal(t, text, made.plaintext, "holder 4"))
			made.credential = append(bytes.Clone(made.key), '\n')
			made.nameCredential(t, made.credential)
			made.expectRefused(t, bootstrap.ErrCredentialForm)
		})
	})

	t.Run("When it returns, Open shall have closed every folder and file it opened, and freed every key store handle it opened.", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
		for name, way := range credentialOutcomes() {
			t.Run("key holder 4, "+name+": no descriptor of this process leads into the bootstrap folder or the credential folder", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
				made := way.reach(t)
				left := descriptorsInto(t, made.folder)
				if made.credentialFolder != "" {
					left = append(left, descriptorsInto(t, made.credentialFolder)...)
				}
				if len(left) != 0 {
					t.Fatalf("still open after Open returned: %v", left)
				}
			})
		}
	})
}
