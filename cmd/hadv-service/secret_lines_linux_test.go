// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The program under key holder 5, the Swarm secret: the secret planted at /run/secrets through
// sudo as Swarm would, owned by the runner's own user, which the program runs as, or by root as
// Swarm's default gives it. Each bootstrap folder under key holder 5 also holds a good key file
// with the very key the file is sealed under, so a program that took the key from the key file
// would start where it must refuse; one that must start holds none. Each refusal is one
// start_failed line and a non-zero exit, its reason not the reason another check gives, nor the
// reason for a header the engine does not read, which the unbuilt engine gives every key holder 5
// file; neither the key nor the secret is in the log. /run/secrets is one place for the whole
// machine, so the rows run alone, one after the other.
package main_test

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// holder5Folder makes a bootstrap folder under key holder 5 for a row of its own on the shared
// board, beside a good key file holding the very key it is sealed under, and a /run/secrets of the
// row's own with no secret yet.
func holder5Folder(t *testing.T) *bootstrapFolder {
	t.Helper()
	made := brokenFolder(t, "holder 5")
	takeSecretFolder(t, true)
	return made
}

// secretReasons are the reasons the program gives under key holder 5 for each kind the lines tell
// apart, and the reasons of other checks a row's reason must differ from.
type secretReasons struct {
	missing, unreadable, reachable, form, unseal, header, keyMissing, credentialMissing string
}

// reasonsUnderHolder5 starts the program once for each kind, one after the other, each with a
// /run/secrets of its own.
func reasonsUnderHolder5(t *testing.T) secretReasons {
	t.Helper()
	var reasons secretReasons
	planted := func(text string, mode os.FileMode) string {
		made := holder5Folder(t)
		plantSecret(t, []byte(text), mode, ownOwner)
		return made.refusedWith(t, []byte(text))
	}
	missing := brokenFolder(t, "holder 5")
	takeSecretFolder(t, false)
	reasons.missing = missing.refusedWith(t, nil)
	unreadable := holder5Folder(t)
	plantSecret(t, []byte(unreadable.keyText), 0, ownOwner)
	reasons.unreadable = unreadable.refusedWith(t, nil)
	_, other := newBootstrapKey(t)
	reasons.reachable = planted(other, 0o440)
	reasons.form = planted(strings.TrimRight(other, "\n")[:43], 0o400)
	unseal := holder5Folder(t)
	removeFile(t, unseal.keyFile)
	plantSecret(t, []byte(other), 0o400, ownOwner)
	reasons.unseal = unseal.refusedWith(t, []byte(other))
	reasons.header = brokenFolder(t, sealedUnderHolder4).refusedWith(t, nil)
	reasons.keyMissing = keyMissingReason(t)
	credential := holder4Folder(t)
	reasons.credentialMissing = credential.refusedWith(t, nil, namingFolder(filepath.Join(t.TempDir(), "gone")))
	return reasons
}

// The names of the secret's kinds, and of other checks' reasons a row's reason must differ from.
const (
	reasonSwarmMissing      = "a missing secret"
	reasonSwarmUnreadable   = "an unreadable secret"
	reasonSwarmUnseal       = "a secret that does not unseal the file"
	reasonSwarmReachable    = "a secret others can reach"
	reasonSwarmForm         = "a secret out of its form"
	reasonCredentialMissing = "a missing credential"
)

// expectNotAmong fails the row when its reason is any of the others named.
func expectNotAmong(t *testing.T, reason string, others map[string]string) {
	t.Helper()
	for name, other := range others {
		expectOwnReason(t, reason, other, name)
	}
}

// TestLinuxRootSecretProgram plants the machine's one Swarm secret through sudo, so it runs alone,
// its rows one after the other.
func TestLinuxRootSecretProgram(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
	reasons := reasonsUnderHolder5(t)

	t.Run("When the bootstrap file's key holder is 5, the engine shall take the bootstrap file's key only from the Swarm secret `/run/secrets/hadv-bootstrap-key`.", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
		t.Run("the key in the key file's form, mode 0400, the runner's own, and no key file: it starts", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := holder5Folder(t)
			removeFile(t, made.keyFile)
			plantSecret(t, []byte(made.keyText), 0o400, ownOwner)
			made.startsWith(t, nil)
		})
		t.Run("another key as the secret, the right one in /run/secrets/other, in the bootstrap folder's key file, and raw as a credential named: the reason for a secret that does not unseal the file, not the header's", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := holder5Folder(t)
			_, other := newBootstrapKey(t)
			plantSecret(t, []byte(other), 0o400, ownOwner)
			plantFile(t, filepath.Join(secretFolder, "other"), []byte(made.keyText), 0o400, ownOwner)
			reason := made.refusedWith(t, []byte(other), namingFolder(writeCredentialFolder(t, made.key)))
			if reason != reasons.unseal {
				t.Fatalf("the reason %q is not the one for a secret that does not unseal the file, %q: the key was taken from elsewhere", reason, reasons.unseal)
			}
			expectOwnReason(t, reason, reasons.header, reasonHeader)
		})
	})

	t.Run("If, under key holder 5, the secret is missing, unreadable or a link leading out of `/run/secrets`, then the engine shall write one `start_failed` line saying which, and exit with a non-zero code.", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
		uid := strconv.Itoa(os.Getuid())
		for _, each := range []struct {
			name, kind string
			place      func(t *testing.T, made *bootstrapFolder)
		}{
			{"no /run/secrets", reasonSwarmMissing, func(t *testing.T, _ *bootstrapFolder) { t.Helper(); removeSecretFolder(t) }},
			{"/run/secrets without the secret", reasonSwarmMissing, func(*testing.T, *bootstrapFolder) {}},
			{"/run/secrets mode 0700, root's, a good secret in it", reasonSwarmUnreadable, func(t *testing.T, made *bootstrapFolder) {
				t.Helper()
				plantSecret(t, []byte(made.keyText), 0o400, ownOwner)
				sudo(t, "chmod", "0700", secretFolder)
			}},
			{"the secret mode 0000, the runner's own", reasonSwarmUnreadable, func(t *testing.T, made *bootstrapFolder) {
				t.Helper()
				plantSecret(t, []byte(made.keyText), 0, ownOwner)
			}},
			{"a folder in the secret's place", reasonSwarmUnreadable, func(t *testing.T, _ *bootstrapFolder) {
				t.Helper()
				sudo(t, "install", "-d", "-m", "0700", "-o", uid, secretPath)
			}},
			{"a named pipe in the secret's place, the runner's own at mode 0600, no writer", reasonSwarmUnreadable, func(t *testing.T, _ *bootstrapFolder) {
				t.Helper()
				sudo(t, "mkfifo", "-m", "0600", secretPath)
				sudo(t, "chown", uid, secretPath)
			}},
			{"a symbolic link to a good secret outside /run/secrets", reasonSwarmUnreadable, func(t *testing.T, made *bootstrapFolder) {
				t.Helper()
				outside := filepath.Join(t.TempDir(), "outside")
				if err := os.WriteFile(outside, []byte(made.keyText), 0o600); err != nil {
					t.Fatalf("writing the secret outside: %v", err)
				}
				setKeyMode(t, outside, 0o400)
				sudo(t, "ln", "-s", outside, secretPath)
			}},
		} {
			t.Run(each.name+", a good key file beside the bootstrap file: one start_failed line saying "+each.kind+", and a non-zero exit", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
				made := holder5Folder(t)
				each.place(t, made)
				reason := made.refusedWith(t, nil)
				others := map[string]string{reasonHeader: reasons.header, reasonKeyMissing: reasons.keyMissing,
					reasonCredentialMissing: reasons.credentialMissing}
				if each.kind == reasonSwarmMissing {
					others[reasonSwarmUnreadable] = reasons.unreadable
				} else {
					others[reasonSwarmMissing] = reasons.missing
				}
				expectNotAmong(t, reason, others)
			})
		}
		t.Run("a missing secret, an unreadable one, one others can reach, one out of its form, one that does not unseal the file, a header the engine does not read, a missing key file and a missing credential: eight reasons, each its own", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			expectDifferent(t, map[string]string{
				reasonSwarmMissing: reasons.missing, reasonSwarmUnreadable: reasons.unreadable, reasonSwarmReachable: reasons.reachable,
				reasonSwarmForm: reasons.form, reasonSwarmUnseal: reasons.unseal,
				reasonHeader: reasons.header, reasonKeyMissing: reasons.keyMissing,
				reasonCredentialMissing: reasons.credentialMissing,
			})
		})
		t.Run("a relative symbolic link to a good secret inside /run/secrets, and no key file: it starts", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := holder5Folder(t)
			removeFile(t, made.keyFile)
			plantFile(t, filepath.Join(secretFolder, "inside"), []byte(made.keyText), 0o400, ownOwner)
			sudo(t, "ln", "-s", "inside", secretPath)
			made.startsWith(t, nil)
		})
	})

	t.Run("If, under key holder 5, the secret's mode gives its group or others any access, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
		notReachable := map[string]string{reasonSwarmMissing: reasons.missing, reasonSwarmUnreadable: reasons.unreadable,
			reasonSwarmForm: reasons.form, reasonSwarmUnseal: reasons.unseal,
			reasonHeader: reasons.header}
		t.Run("root's, mode 0444, as Swarm grants a secret by default: one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := holder5Folder(t)
			plantSecret(t, []byte(made.keyText), 0o444, rootOwner)
			expectNotAmong(t, made.refusedWith(t, nil), notReachable)
		})
		for _, mode := range []os.FileMode{0o440, 0o420, 0o410, 0o404, 0o402, 0o401, 0o444, 0o640} {
			t.Run(modeName(mode)+", the runner's own: one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
				made := holder5Folder(t)
				plantSecret(t, []byte(made.keyText), mode, ownOwner)
				expectNotAmong(t, made.refusedWith(t, nil), notReachable)
			})
		}
		t.Run("an access-list entry letting nobody read it, the mode then 0440, which the system says nobody may read: one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := holder5Folder(t)
			plantSecret(t, []byte(made.keyText), 0o400, ownOwner)
			sudo(t, "setfacl", "-m", "u:nobody:r", secretPath)
			info, err := os.Stat(secretPath)
			if err != nil {
				t.Fatalf("reading the secret's mode: %v", err)
			}
			if info.Mode().Perm() != 0o440 {
				t.Fatalf("the secret's mode is %o with the entry, not 0440: a fault in the test", info.Mode().Perm())
			}
			expectNobodyMay(t, secretPath, true, false)
			expectNotAmong(t, made.refusedWith(t, nil), notReachable)
		})
		for _, mode := range []os.FileMode{0o400, 0o600, 0o700} {
			t.Run(modeName(mode)+", the runner's own, the owner's bits alone, and no key file: it starts", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
				made := holder5Folder(t)
				removeFile(t, made.keyFile)
				plantSecret(t, []byte(made.keyText), mode, ownOwner)
				made.startsWith(t, nil)
			})
		}
	})

	t.Run("If, under key holder 5, the secret is not in the key file's form, or holds a key of 32 zero bytes, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
		notForm := map[string]string{reasonSwarmReachable: reasons.reachable, reasonSwarmUnseal: reasons.unseal,
			reasonSwarmMissing: reasons.missing, reasonSwarmUnreadable: reasons.unreadable, reasonHeader: reasons.header}
		for name, build := range malformedKeys {
			t.Run(name+": one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
				made := holder5Folder(t)
				text := build(made.keyBase())
				plantSecret(t, []byte(text), 0o400, ownOwner)
				expectNotAmong(t, made.refusedWith(t, []byte(text)), notForm)
			})
		}
		t.Run("a 1 MiB secret, the key then line feeds: one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := holder5Folder(t)
			text := made.keyBase() + strings.Repeat("\n", 1<<20)
			plantSecret(t, []byte(text), 0o400, ownOwner)
			expectNotAmong(t, made.refusedWith(t, nil), notForm)
		})
		t.Run("the key of 32 zero bytes, the bootstrap file sealed under it by the oracle: one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			zero := base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
			made := holder5Folder(t)
			made.writeFile(t, sealBootstrap(t, zero, made.plaintext, "holder 5"))
			plantSecret(t, []byte(zero), 0o400, ownOwner)
			expectNotAmong(t, made.refusedWith(t, nil), notForm)
		})
		for name, ending := range map[string]string{"no line ending": "", "a line feed": "\n", "a carriage return and line feed": "\r\n"} {
			t.Run("the key with "+name+", and no key file: it starts", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
				made := holder5Folder(t)
				removeFile(t, made.keyFile)
				plantSecret(t, []byte(made.keyBase()+ending), 0o400, ownOwner)
				made.startsWith(t, nil)
			})
		}
	})

	t.Run("If the bootstrap file's header is not format version 1's for the key file, on Windows for the TPM or the software key store, or on Linux for a systemd credential or a Swarm secret, or the bootstrap file is too short for its header, nonce and tag, then the engine shall write one `start_failed` line saying so, without reading the key file, asking a key store, or reading a credential or secret, and exit with a non-zero code.", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
		t.Run("key holder 5, 293 sealed bytes, a name in its form, a good secret planted: one start_failed line, and a non-zero exit, the same reason with no /run/secrets and with the key file missing, not a missing secret's", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			const sealedUnderHolder5 = "holder 5\nsealed \"hadv-0123456789abcdef0123456789abcdef\" random:256"
			made := brokenFolder(t, sealedUnderHolder5)
			takeSecretFolder(t, true)
			plantSecret(t, []byte(made.keyText), 0o400, ownOwner)
			reason := made.refusedWith(t, nil)
			removeSecretFolder(t)
			if got := brokenFolder(t, sealedUnderHolder5).refusedWith(t, nil); got != reason {
				t.Fatalf("with no /run/secrets the reason was %q, not the header's %q: the secret was read", got, reason)
			}
			without := brokenFolder(t, sealedUnderHolder5)
			removeFile(t, without.keyFile)
			if got := without.refusedWith(t, nil); got != reason {
				t.Fatalf("with the key file missing the reason was %q, not the header's %q: the key file was read", got, reason)
			}
			expectNotAmong(t, reason, map[string]string{reasonSwarmMissing: reasons.missing, reasonKeyMissing: reasons.keyMissing})
		})
	})

	t.Run("The engine shall not write the bootstrap file's password, or its key from the key file, a Windows key store, a systemd credential or a Swarm secret, to the local log.", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
		// Every row above checks the log the same way; these put a key of printable bytes where a
		// log that quoted what it read, escaped or not, would show it.
		t.Run("a key of 32 printable bytes, foobar five times and fo, as the secret, mode 0444: refused, a reason of its own, neither the key nor the secret in the log", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := holder5Folder(t)
			made.key = []byte(printableKey)
			made.keyText = base64.StdEncoding.EncodeToString(made.key) + "\n"
			made.writeFile(t, sealBootstrap(t, made.keyText, made.plaintext, "holder 5"))
			removeFile(t, made.keyFile)
			plantSecret(t, []byte(made.keyText), 0o444, ownOwner)
			expectNotAmong(t, made.refusedWith(t, []byte(made.keyText)), map[string]string{
				reasonSwarmMissing: reasons.missing, reasonSwarmUnreadable: reasons.unreadable,
				reasonSwarmForm: reasons.form, reasonSwarmUnseal: reasons.unseal, reasonHeader: reasons.header,
			})
		})
		t.Run("the same key as the secret, mode 0400: it starts, the key not in the log", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := holder5Folder(t)
			made.key = []byte(printableKey)
			made.keyText = base64.StdEncoding.EncodeToString(made.key) + "\n"
			made.writeFile(t, sealBootstrap(t, made.keyText, made.plaintext, "holder 5"))
			removeFile(t, made.keyFile)
			plantSecret(t, []byte(made.keyText), 0o400, ownOwner)
			made.startsWith(t, []byte(made.keyText))
		})
	})
}
