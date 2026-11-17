// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The program under key holder 4, systemd's credential, started by hand: the variable systemd
// names the credential folder in is set in the program's own environment to a folder the row made,
// as the page allows, since the engine takes the folder as given. Each bootstrap folder under key
// holder 4 also holds a good key file with the very key the file is sealed under, so a program that
// took the key from the key file would start where it must refuse; one that must start holds none,
// or one with another key. Each refusal is one start_failed line and a non-zero exit, its reason
// not the reason for a header the engine does not read, which the unbuilt engine gives every key
// holder 4 file; neither the key nor the credential is in the log.
package main_test

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// sealedUnderHolder4 is a header the engine does not read on any system: key holder 4 with a
// sealed key of key holder 2's length, its name in its form.
const sealedUnderHolder4 = "holder 4\nsealed \"hadv-0123456789abcdef0123456789abcdef\" random:256"

// holder4Folder makes a bootstrap folder under key holder 4 for a row of its own on the shared
// board, beside a good key file holding the very key it is sealed under.
func holder4Folder(t *testing.T) *bootstrapFolder {
	t.Helper()
	return brokenFolder(t, "holder 4")
}

// credentialReasons are the reasons the program gives under key holder 4 for each kind the lines
// tell apart, each from a folder of its own: no folder named, the folder missing, the credential
// unreadable, a credential that does not unseal the file, and a header the engine does not read.
type credentialReasons struct {
	unset, missing, unreadable, unseal, header string
}

// reasonsUnderHolder4 starts the program once for each kind.
func reasonsUnderHolder4(t *testing.T) credentialReasons {
	t.Helper()
	var reasons credentialReasons
	unset := holder4Folder(t)
	reasons.unset = unset.refusedWith(t, nil)
	missing := holder4Folder(t)
	reasons.missing = missing.refusedWith(t, nil, namingFolder(filepath.Join(t.TempDir(), "gone")))
	unreadable := holder4Folder(t)
	folder := writeCredentialFolder(t, unreadable.key)
	makeUnopenable(t, filepath.Join(folder, heldKeyName))
	reasons.unreadable = unreadable.refusedWith(t, unreadable.key, namingFolder(folder))
	unseal := holder4Folder(t)
	removeFile(t, unseal.keyFile)
	other, _ := newBootstrapKey(t)
	reasons.unseal = unseal.refusedWith(t, other, namingFolder(writeCredentialFolder(t, other)))
	header := brokenFolder(t, sealedUnderHolder4)
	reasons.header = header.refusedWith(t, header.key, namingFolder(writeCredentialFolder(t, header.key)))
	return reasons
}

// credentialCase is one of the credential line's refusals: the kind the line names it under, and
// the environment the row starts the program with, made beside the bootstrap folder.
type credentialCase struct {
	kind  string
	place func(t *testing.T, made *bootstrapFolder) []string
}

// The names of other checks' reasons a row's reason must differ from.
const (
	reasonHeader     = "a header the engine does not read"
	reasonKeyMissing = "a missing key file"
)

// The kinds the credential line tells apart.
const (
	kindUnset      = "no folder named"
	kindMissing    = "a missing folder or credential"
	kindUnreadable = "an unreadable folder or credential"
)

// credentialCases are the cases of the line on a missing or unreadable credential.
func credentialCases() map[string]credentialCase {
	inFolder := func(spoil func(t *testing.T, folder, credential string)) func(*testing.T, *bootstrapFolder) []string {
		return func(t *testing.T, made *bootstrapFolder) []string {
			t.Helper()
			folder := writeCredentialFolder(t, made.key)
			spoil(t, folder, filepath.Join(folder, heldKeyName))
			return []string{namingFolder(folder)}
		}
	}
	return map[string]credentialCase{
		"the variable unset": {kindUnset, func(*testing.T, *bootstrapFolder) []string { return nil }},
		"the variable empty": {kindUnset, func(*testing.T, *bootstrapFolder) []string { return []string{namingFolder("")} }},
		"the folder it names missing": {kindMissing, func(t *testing.T, _ *bootstrapFolder) []string {
			t.Helper()
			return []string{namingFolder(filepath.Join(t.TempDir(), "gone"))}
		}},
		"the folder there without the credential": {kindMissing, inFolder(func(t *testing.T, _, credential string) {
			t.Helper()
			removeFile(t, credential)
		})},
		"the folder mode 0000, no one may open it": {kindUnreadable, inFolder(func(t *testing.T, folder, _ string) {
			t.Helper()
			makeUnopenable(t, folder)
		})},
		"the credential mode 0000, no one may open it": {kindUnreadable, inFolder(func(t *testing.T, _, credential string) {
			t.Helper()
			makeUnopenable(t, credential)
		})},
		"a folder in the credential's place": {kindUnreadable, inFolder(func(t *testing.T, _, credential string) {
			t.Helper()
			makeFolderAt(t, credential)
		})},
		"a named pipe in the credential's place, no writer ever opening it": {kindUnreadable, inFolder(func(t *testing.T, _, credential string) {
			t.Helper()
			removeFile(t, credential)
			if err := syscall.Mkfifo(credential, 0o600); err != nil {
				t.Fatalf("making a named pipe: %v", err)
			}
		})},
	}
}

// reasonOfKind is the reason for a kind of the credential line.
func (reasons credentialReasons) reasonOfKind(kind string) string {
	switch kind {
	case kindUnset:
		return reasons.unset
	case kindMissing:
		return reasons.missing
	default:
		return reasons.unreadable
	}
}

// printableKey is 32 printable bytes, RFC 4648's foobar five times and fo, so a log that quoted
// or escaped what it read would still show it.
const printableKey = "foobarfoobarfoobarfoobarfoobarfo"

func TestLinuxCredentialProgram(t *testing.T) {
	t.Parallel()

	t.Run("When the bootstrap file's key holder is 4, the engine shall take the bootstrap file's key only from the file `hadv-bootstrap-key` in the folder systemd names in `CREDENTIALS_DIRECTORY`.", func(t *testing.T) {
		t.Parallel()
		t.Run("the raw key at hadv-bootstrap-key, mode 0600, and no key file: it starts", func(t *testing.T) {
			t.Parallel()
			made := holder4Folder(t)
			removeFile(t, made.keyFile)
			made.startsWith(t, made.key, namingFolder(writeCredentialFolder(t, made.key)))
		})
		t.Run("the raw key at hadv-bootstrap-key, and a key file holding another key: it starts", func(t *testing.T) {
			t.Parallel()
			made := holder4Folder(t)
			_, other := newBootstrapKey(t)
			made.writeKey(t, other)
			made.startsWith(t, made.key, namingFolder(writeCredentialFolder(t, made.key)))
		})
		t.Run("another key at hadv-bootstrap-key, the right one beside it as bootstrap.key and as hadv-bootstrap-key.cred, and in the bootstrap folder's key file: the reason for a credential that does not unseal the file, not the header's", func(t *testing.T) {
			t.Parallel()
			made := holder4Folder(t)
			other, _ := newBootstrapKey(t)
			folder := writeCredentialFolder(t, other)
			for name, contents := range map[string][]byte{keyFileName: []byte(made.keyText), heldKeyName + ".cred": made.key} {
				if err := os.WriteFile(filepath.Join(folder, name), contents, 0o600); err != nil {
					t.Fatalf("writing %s beside the credential: %v", name, err)
				}
			}
			reason := made.refusedWith(t, other, namingFolder(folder))
			reasons := reasonsUnderHolder4(t)
			if reason != reasons.unseal {
				t.Fatalf("the reason %q is not the one for a credential that does not unseal the file, %q: the key was taken from elsewhere", reason, reasons.unseal)
			}
			expectOwnReason(t, reason, reasons.header, reasonHeader)
		})
	})

	t.Run("If, under key holder 4, no folder is named in `CREDENTIALS_DIRECTORY`, or the folder or its `hadv-bootstrap-key` is missing or unreadable, then the engine shall write one `start_failed` line saying which, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		for name, each := range credentialCases() {
			t.Run(name+", a good key file beside the bootstrap file: one start_failed line saying "+each.kind+", and a non-zero exit", func(t *testing.T) {
				t.Parallel()
				made := holder4Folder(t)
				reason := made.refusedWith(t, made.key, each.place(t, made)...)
				reasons := reasonsUnderHolder4(t)
				for _, other := range []string{kindUnset, kindMissing, kindUnreadable} {
					if other != each.kind {
						expectOwnReason(t, reason, reasons.reasonOfKind(other), other)
					}
				}
				expectOwnReason(t, reason, reasons.header, reasonHeader)
				expectOwnReason(t, reason, keyMissingReason(t), reasonKeyMissing)
			})
		}
		t.Run("no folder named, the folder missing, the credential unreadable, a missing key file and a header the engine does not read: five reasons, each its own", func(t *testing.T) {
			t.Parallel()
			reasons := reasonsUnderHolder4(t)
			expectDifferent(t, map[string]string{
				kindUnset: reasons.unset, kindMissing: reasons.missing, kindUnreadable: reasons.unreadable,
				reasonKeyMissing: keyMissingReason(t), reasonHeader: reasons.header,
			})
		})
	})

	t.Run("If, under key holder 4, the key is not exactly 32 bytes, or is 32 zero bytes, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		for name, build := range map[string]func(made *bootstrapFolder) []byte{
			"31 bytes, the right key's first 31": func(made *bootstrapFolder) []byte { return made.key[:31] },
			"33 bytes, the right key and a line feed": func(made *bootstrapFolder) []byte {
				return append(bytes.Clone(made.key), '\n')
			},
			"0 bytes": func(*bootstrapFolder) []byte { return []byte{} },
			"45 bytes, the right key in the key file's form": func(made *bootstrapFolder) []byte { return []byte(made.keyText) },
			"1 MiB, the right key then zeros": func(made *bootstrapFolder) []byte {
				return append(bytes.Clone(made.key), make([]byte, 1<<20-len(made.key))...)
			},
		} {
			t.Run(name+": one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) {
				t.Parallel()
				made := holder4Folder(t)
				credential := build(made)
				reason := made.refusedWith(t, credential, namingFolder(writeCredentialFolder(t, credential)))
				expectNotOtherCredentialReason(t, reason, reasonsUnderHolder4(t))
			})
		}
		t.Run("the key of 32 zero bytes, the bootstrap file sealed under it by the oracle: one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			zero := base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
			made := holder4Folder(t)
			made.writeFile(t, sealBootstrap(t, zero, made.plaintext, "holder 4"))
			reason := made.refusedWith(t, nil, namingFolder(writeCredentialFolder(t, make([]byte, 32))))
			expectNotOtherCredentialReason(t, reason, reasonsUnderHolder4(t))
		})
	})

	t.Run("If the bootstrap file's header is not format version 1's for the key file, on Windows for the TPM or the software key store, or on Linux for a systemd credential or a Swarm secret, or the bootstrap file is too short for its header, nonce and tag, then the engine shall write one `start_failed` line saying so, without reading the key file, asking a key store, or reading a credential or secret, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("key holder 4, 293 sealed bytes, a name in its form, a good credential named: one start_failed line, and a non-zero exit, the same reason with no folder named and with the key file missing, not a missing key file's", func(t *testing.T) {
			t.Parallel()
			made := brokenFolder(t, sealedUnderHolder4)
			reason := made.refusedWith(t, made.key, namingFolder(writeCredentialFolder(t, made.key)))
			if got := brokenFolder(t, sealedUnderHolder4).refusedWith(t, nil); got != reason {
				t.Fatalf("with no folder named the reason was %q, not the header's %q: the credential was read", got, reason)
			}
			without := brokenFolder(t, sealedUnderHolder4)
			removeFile(t, without.keyFile)
			if got := without.refusedWith(t, without.key, namingFolder(writeCredentialFolder(t, without.key))); got != reason {
				t.Fatalf("with the key file missing the reason was %q, not the header's %q: the key file was read", got, reason)
			}
			expectOwnReason(t, reason, keyMissingReason(t), reasonKeyMissing)
		})
	})

	t.Run("The engine shall not write the bootstrap file's password, or its key from the key file, a Windows key store, a systemd credential or a Swarm secret, to the local log.", func(t *testing.T) {
		t.Parallel()
		// Every row above checks the log the same way; these put a key of printable bytes where a
		// log that quoted what it read, escaped or not, would show it.
		t.Run("a key of 32 printable bytes, foobar five times and fo, as the credential: it starts, the key not in the log", func(t *testing.T) {
			t.Parallel()
			made := printableHolder4Folder(t)
			made.startsWith(t, made.key, namingFolder(writeCredentialFolder(t, made.key)))
		})
		t.Run("a key of 32 printable bytes and a line feed, as the credential: refused, a reason of its own, neither the key nor the credential in the log", func(t *testing.T) {
			t.Parallel()
			made := printableHolder4Folder(t)
			credential := append(bytes.Clone(made.key), '\n')
			reason := made.refusedWith(t, credential, namingFolder(writeCredentialFolder(t, credential)))
			expectNotOtherCredentialReason(t, reason, reasonsUnderHolder4(t))
		})
	})
}

// startsWith is starts, the program started with the entries given in its environment: it starts
// and listens, with neither a password nor the key in its log, nor what the row wrote as the
// credential or the secret.
func (made *bootstrapFolder) startsWith(t *testing.T, held []byte, environment ...string) {
	t.Helper()
	program := startWithEnvironment(t, made.path, environment)
	program.listening(t)
	expectNoPassword(t, program)
	made.expectKeyNotIn(t, program.text())
	expectHeldNotIn(t, program.text(), held)
}

// printableHolder4Folder makes a bootstrap folder under key holder 4 sealed under printableKey,
// with no key file.
func printableHolder4Folder(t *testing.T) *bootstrapFolder {
	t.Helper()
	made := holder4Folder(t)
	made.key = []byte(printableKey)
	made.keyText = base64.StdEncoding.EncodeToString(made.key) + "\n"
	if !strings.HasPrefix(made.keyText, "Zm9vYmFy") {
		t.Fatalf("the printable key's key file text is %q: a fault in the test", made.keyText)
	}
	made.writeFile(t, sealBootstrap(t, made.keyText, made.plaintext, "holder 4"))
	removeFile(t, made.keyFile)
	return made
}

// expectNotOtherCredentialReason fails the row when a reason for a credential not in its form is
// the reason for another of holder 4's checks, or for a header the engine does not read.
func expectNotOtherCredentialReason(t *testing.T, reason string, reasons credentialReasons) {
	t.Helper()
	expectOwnReason(t, reason, reasons.missing, "a missing credential")
	expectOwnReason(t, reason, reasons.unreadable, "an unreadable credential")
	expectOwnReason(t, reason, reasons.unseal, "a credential that does not unseal the file")
	expectOwnReason(t, reason, reasons.header, reasonHeader)
}
