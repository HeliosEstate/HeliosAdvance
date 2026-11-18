// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Open under key holder 5, the Swarm secret, on Linux: the secret planted at /run/secrets through
// sudo as Swarm would, owned by the runner's own user, which stands for the engine's account, or
// by root as Swarm's default gives it. Each bootstrap folder under key holder 5 that Open must
// refuse also holds a good key file with the very key the file is sealed under, so an Open that
// took the key from the key file would open it; each one Open must open holds none, or one Open
// would refuse. /run/secrets is one place for the whole machine, so the rows run alone, one after
// the other.
package bootstrap_test

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/bootstrap"
)

// holder5Layout makes a bootstrap folder under key holder 5 beside a good key file holding the very
// key it is sealed under, and a /run/secrets of the row's own, with no secret yet.
func holder5Layout(t *testing.T) *layout {
	t.Helper()
	made := makeFolderWith(t, plaintextOf(t, 64), "holder 5")
	takeSecretFolder(t, true)
	return made
}

// plantFor plants text as the secret, mode 0400 and the runner's own, and records it as a secret no
// error may hold.
func (made *layout) plantFor(t *testing.T, text string, mode os.FileMode, owner string) {
	t.Helper()
	made.secret = []byte(text)
	plantSecret(t, made.secret, mode, owner)
}

// modeRow names a mode for a row.
func modeRow(mode os.FileMode) string {
	return "mode " + strconv.FormatUint(uint64(mode), 8)
}

// secretOutcomes are the ways Open ends under key holder 5, each reached by a folder of its own,
// for the closing line's rows.
func secretOutcomes() map[string]outcome {
	return map[string]outcome{
		"opened with the secret": {want: nil, make: func(t *testing.T) *layout {
			t.Helper()
			made := holder5Layout(t)
			remove(t, made.keyFile)
			made.plantFor(t, made.keyText, 0o400, ownOwner)
			return made
		}},
		"ErrSecretMissing": {want: bootstrap.ErrSecretMissing, make: func(t *testing.T) *layout {
			t.Helper()
			return holder5Layout(t)
		}},
		"ErrSecretUnreadable, a folder as the secret": {want: bootstrap.ErrSecretUnreadable, make: func(t *testing.T) *layout {
			t.Helper()
			made := holder5Layout(t)
			mustAsRoot(t, "install", "-d", "-m", "0700", "-o", strconv.Itoa(os.Getuid()), secretPath)
			return made
		}},
		"ErrSecretReachable": {want: bootstrap.ErrSecretReachable, make: func(t *testing.T) *layout {
			t.Helper()
			made := holder5Layout(t)
			made.plantFor(t, made.keyText, 0o440, ownOwner)
			return made
		}},
		"ErrSecretForm": {want: bootstrap.ErrSecretForm, make: func(t *testing.T) *layout {
			t.Helper()
			made := holder5Layout(t)
			made.plantFor(t, baseOf(made)[:43], 0o400, ownOwner)
			return made
		}},
		"ErrUnseal, another key as the secret": {want: bootstrap.ErrUnseal, make: func(t *testing.T) *layout {
			t.Helper()
			made := holder5Layout(t)
			_, other := newKey(t)
			made.plantFor(t, other, 0o400, ownOwner)
			return made
		}},
	}
}

// TestLinuxRootSecret plants the machine's one Swarm secret through sudo, so it runs alone, its
// rows one after the other.
func TestLinuxRootSecret(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
	t.Run("Under KeyHolderSwarm, Open shall take the key only from SecretName in SecretFolder.", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
		t.Run("the key in the key file's form at /run/secrets/hadv-bootstrap-key, mode 0400, the engine's own, and no key file: opens, the plaintext exact", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := holder5Layout(t)
			remove(t, made.keyFile)
			made.plantFor(t, made.keyText, 0o400, ownOwner)
			made.expectOpened(t)
		})
		t.Run("another key as the secret, the right one in /run/secrets/other, in the bootstrap folder's key file, and raw as the credential named: ErrUnseal", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
			made := holder5Layout(t)
			_, other := newKey(t)
			made.plantFor(t, other, 0o400, ownOwner)
			plantFile(t, filepath.Join(secretFolder, "other"), []byte(made.keyText), 0o400, ownOwner)
			made.credential = made.key
			made.nameCredential(t, made.key)
			made.expectRefused(t, bootstrap.ErrUnseal)
		})
	})

	t.Run("If SecretFolder, or SecretName in it, does not exist, then Open shall return ErrSecretMissing.", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
		t.Run("no /run/secrets: ErrSecretMissing", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := makeFolderWith(t, plaintextOf(t, 64), "holder 5")
			takeSecretFolder(t, false)
			made.expectRefused(t, bootstrap.ErrSecretMissing)
		})
		t.Run("/run/secrets without the secret: ErrSecretMissing", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			holder5Layout(t).expectRefused(t, bootstrap.ErrSecretMissing)
		})
	})

	t.Run("If SecretFolder will not open, or the secret will not open, is not a regular file, or is a link leading out of SecretFolder, or reading its owner or mode fails, then Open shall return ErrSecretUnreadable.", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
		t.Run("/run/secrets mode 0700, root's, a good secret in it: ErrSecretUnreadable", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := holder5Layout(t)
			made.plantFor(t, made.keyText, 0o400, ownOwner)
			mustAsRoot(t, "chmod", "0700", secretFolder)
			made.expectRefused(t, bootstrap.ErrSecretUnreadable)
		})
		t.Run("the secret mode 0000, the engine's own: ErrSecretUnreadable", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := holder5Layout(t)
			made.plantFor(t, made.keyText, 0, ownOwner)
			made.expectRefused(t, bootstrap.ErrSecretUnreadable)
		})
		t.Run("a folder in the secret's place, the engine's own: ErrSecretUnreadable", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := holder5Layout(t)
			mustAsRoot(t, "install", "-d", "-m", "0700", "-o", strconv.Itoa(os.Getuid()), secretPath)
			made.expectRefused(t, bootstrap.ErrSecretUnreadable)
		})
		t.Run("a named pipe in the secret's place, the engine's own at mode 0600, no writer: ErrSecretUnreadable within the hang bound", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := holder5Layout(t)
			mustAsRoot(t, "mkfifo", "-m", "0600", secretPath)
			mustAsRoot(t, "chown", strconv.Itoa(os.Getuid()), secretPath)
			made.expectRefused(t, bootstrap.ErrSecretUnreadable)
		})
		t.Run("a symbolic link to a good secret outside /run/secrets: ErrSecretUnreadable", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := holder5Layout(t)
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte(made.keyText), 0o600); err != nil {
				t.Fatalf("writing the secret outside: %v", err)
			}
			setMode(t, outside, 0o400)
			mustAsRoot(t, "ln", "-s", outside, secretPath)
			made.expectRefused(t, bootstrap.ErrSecretUnreadable)
		})
		t.Run("a relative symbolic link to a good secret inside /run/secrets, no key file: opens, the plaintext exact", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := holder5Layout(t)
			remove(t, made.keyFile)
			plantFile(t, filepath.Join(secretFolder, "inside"), []byte(made.keyText), 0o400, ownOwner)
			mustAsRoot(t, "ln", "-s", "inside", secretPath)
			made.expectOpened(t)
		})
	})

	t.Run("If reading the secret fails, then Open shall return ErrSecretUnreadable.", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
		t.Run("a secret that opens and fails its first read, this process's own memory file bound in its place, mode 0600 and its own: ErrSecretUnreadable", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := holder5Layout(t)
			bindOwnMemory(t, secretPath)
			made.expectRefused(t, bootstrap.ErrSecretUnreadable)
		})
	})

	t.Run("If the secret's mode gives its group or others any access, then Open shall return ErrSecretReachable.", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
		t.Run("root's, mode 0444, as Swarm grants a secret by default: ErrSecretReachable", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := holder5Layout(t)
			made.plantFor(t, made.keyText, 0o444, rootOwner)
			made.expectRefused(t, bootstrap.ErrSecretReachable)
		})
		for _, mode := range []os.FileMode{0o440, 0o420, 0o410, 0o404, 0o402, 0o401, 0o444, 0o640} {
			t.Run(modeRow(mode)+", the engine's own: ErrSecretReachable", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
				made := holder5Layout(t)
				made.plantFor(t, made.keyText, mode, ownOwner)
				made.expectRefused(t, bootstrap.ErrSecretReachable)
			})
		}
		t.Run("an access-list entry letting nobody read it, the mode then 0440, which the system says nobody may read: ErrSecretReachable", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := holder5Layout(t)
			made.plantFor(t, made.keyText, 0o400, ownOwner)
			mustAsRoot(t, "setfacl", "-m", "u:nobody:r", secretPath)
			info, err := os.Stat(secretPath)
			if err != nil {
				t.Fatalf("reading the secret's mode: %v", err)
			}
			if info.Mode().Perm() != 0o440 {
				t.Fatalf("the secret's mode is %o with the entry, not 0440: a fault in the test", info.Mode().Perm())
			}
			expectNobodyMay(t, secretPath, true, false)
			made.expectRefused(t, bootstrap.ErrSecretReachable)
		})
		for _, mode := range []os.FileMode{0o400, 0o600, 0o700} {
			t.Run(modeRow(mode)+", the engine's own, the owner's bits alone, no key file: opens, the plaintext exact", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
				made := holder5Layout(t)
				remove(t, made.keyFile)
				made.plantFor(t, made.keyText, mode, ownOwner)
				made.expectOpened(t)
			})
		}
	})

	t.Run("If the secret is longer than KeyFileMostBytes, is not in the key file's form, or holds a key of 32 zero bytes, then Open shall return ErrSecretForm, having read at most KeyFileMostBytes and one byte more of it.", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
		for name, build := range malformedKeys {
			t.Run(name+": ErrSecretForm", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
				made := holder5Layout(t)
				made.plantFor(t, build(baseOf(made)), 0o400, ownOwner)
				made.expectRefused(t, bootstrap.ErrSecretForm)
			})
		}
		t.Run("the key of 32 zero bytes, the bootstrap file sealed under it by the oracle: ErrSecretForm", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			zero := base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
			made := holder5Layout(t)
			made.writeFile(t, seal(t, zero, made.plaintext, "holder 5"))
			made.plantFor(t, zero, 0o400, ownOwner)
			made.expectRefused(t, bootstrap.ErrSecretForm)
		})
		for name, ending := range map[string]string{"no line ending": "", "a line feed": "\n", "a carriage return and line feed": "\r\n"} {
			t.Run("the key with "+name+", no key file: opens, the plaintext exact", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
				made := holder5Layout(t)
				remove(t, made.keyFile)
				made.plantFor(t, baseOf(made)+ending, 0o400, ownOwner)
				made.expectOpened(t)
			})
		}
	})

	t.Run("If the bootstrap file is shorter than HeaderBytes, NonceBytes and TagBytes together, or its first HeaderBytes are not Magic, FormatVersion, then KeyHolderKeyFile with a sealed-key length of 0, on Windows KeyHolderTPM or KeyHolderSoftwareKeyStore with a sealed-key length of SealedKeyBytes, or on Linux KeyHolderSystemd or KeyHolderSwarm with a sealed-key length of 0, or, under key holder 2 or 3, the file is too short for the sealed key, nonce and tag, or the sealed key's first KeyNameBytes are not KeyNamePrefix and 32 lower-case hex digits, then Open shall return ErrHeader before it opens the key file, asks a key store, or reads a credential or secret.", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
		for name, edits := range map[string]string{
			"key holder 5, 293 sealed bytes, a name in its form": "holder 5\nsealed \"hadv-0123456789abcdef0123456789abcdef\" random:256",
			"key holder 5, a sealed-key length of 1 that lies":   "holder 5\nsealed-length 1",
		} {
			t.Run(name+", a good secret planted: ErrHeader", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
				made := makeFolderWith(t, plaintextOf(t, 64), edits)
				takeSecretFolder(t, true)
				made.plantFor(t, made.keyText, 0o400, ownOwner)
				made.expectRefused(t, bootstrap.ErrHeader)
			})
		}
	})

	t.Run("Open shall take the key under KeyHolderKeyFile by the lines on the key file, under KeyHolderTPM or KeyHolderSoftwareKeyStore by the lines on the key store key, under KeyHolderSystemd by the lines on systemd's credential, and under KeyHolderSwarm by the lines on the Swarm secret, never by another holder's; it shall open the key file only under key holder 1.", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
		for name, spoil := range map[string]func(t *testing.T, made *layout){
			"the key file missing":         func(t *testing.T, made *layout) { t.Helper(); remove(t, made.keyFile) },
			"the key file no one may open": func(t *testing.T, made *layout) { t.Helper(); makeUnopenable(t, made.keyFile) },
			"the key file open to others":  func(t *testing.T, made *layout) { t.Helper(); openToOthers(t, made.keyFile) },
			"the key file out of its form": func(t *testing.T, made *layout) { t.Helper(); made.writeKey(t, baseOf(made)[:43]) },
		} {
			t.Run("key holder 5, "+name+", a good secret: opens, the plaintext exact", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
				made := holder5Layout(t)
				plantSecret(t, []byte(made.keyText), 0o400, ownOwner)
				spoil(t, made)
				made.expectOpened(t)
			})
		}
		t.Run("key holder 5, the secret missing, beside a good key file holding the very key: ErrSecretMissing", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			holder5Layout(t).expectRefused(t, bootstrap.ErrSecretMissing)
		})
		t.Run("key holder 5, the right raw key as the credential named and another key as the secret: ErrUnseal", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment
			made := holder5Layout(t)
			_, other := newKey(t)
			made.plantFor(t, other, 0o400, ownOwner)
			made.credential = made.key
			made.nameCredential(t, made.key)
			made.expectRefused(t, bootstrap.ErrUnseal)
		})
		t.Run("key holder 4 when sealed, its byte then changed to 5, the right key planted as the secret: ErrUnseal, since the header is sealed too", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := makeFolderWith(t, plaintextOf(t, 64), "holder 4\nflip 10")
			if made.sealed[10] != 5 {
				t.Fatalf("the oracle's file names key holder %d, not 5: a fault in the test", made.sealed[10])
			}
			takeSecretFolder(t, true)
			made.plantFor(t, made.keyText, 0o400, ownOwner)
			made.expectRefused(t, bootstrap.ErrUnseal)
		})
	})

	t.Run("Open shall check in the order of these lines and return the first refusal that applies.", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
		t.Run("the secret mode 0444 and out of its form: ErrSecretReachable", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := holder5Layout(t)
			made.plantFor(t, baseOf(made)[:43], 0o444, ownOwner)
			made.expectRefused(t, bootstrap.ErrSecretReachable)
		})
		t.Run("a symbolic link to a secret outside /run/secrets of mode 0444: ErrSecretUnreadable", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := holder5Layout(t)
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte(made.keyText), 0o600); err != nil {
				t.Fatalf("writing the secret outside: %v", err)
			}
			setMode(t, outside, 0o444)
			mustAsRoot(t, "ln", "-s", outside, secretPath)
			made.expectRefused(t, bootstrap.ErrSecretUnreadable)
		})
		t.Run("the secret out of its form and a tag that does not verify: ErrSecretForm", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := makeFolderWith(t, plaintextOf(t, 64), "holder 5\nflip 60")
			takeSecretFolder(t, true)
			made.plantFor(t, baseOf(made)[:43], 0o400, ownOwner)
			made.expectRefused(t, bootstrap.ErrSecretForm)
		})
		t.Run("the secret missing and the bootstrap file 65,537 bytes: ErrFileTooLarge", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			made := makeFolderWith(t, plaintextOf(t, fileMostBytes+1-sealedOverhead), "holder 5")
			takeSecretFolder(t, true)
			made.expectRefused(t, bootstrap.ErrFileTooLarge)
		})
	})

	t.Run("No error the bootstrap package returns shall hold, in its text, the key or any part of what it reads: the bootstrap file, the key file, systemd's credential or the Swarm secret.", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
		// Every refusal row above checks its error's text the same way; this one puts a secret of a
		// printable key where a careless error would quote it.
		t.Run("a secret of the key foobar five times and fo, mode 0444: ErrSecretReachable, none of it in the error", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
			text := strings.Repeat("Zm9vYmFy", 5) + "Zm8=\n"
			made := holder5Layout(t)
			made.key, made.keyText = []byte(strings.Repeat("foobar", 5)+"fo"), text
			made.writeFile(t, seal(t, text, made.plaintext, "holder 5"))
			made.plantFor(t, text, 0o444, ownOwner)
			made.expectRefused(t, bootstrap.ErrSecretReachable)
		})
	})

	t.Run("When it returns, Open shall have closed every folder and file it opened, and freed every key store handle it opened.", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
		for name, way := range secretOutcomes() {
			t.Run("key holder 5, "+name+": no descriptor of this process leads into the bootstrap folder or /run/secrets", func(t *testing.T) { //nolint:paralleltest // it plants the machine's one Swarm secret
				made := way.reach(t)
				if left := append(descriptorsInto(t, made.folder), descriptorsInto(t, secretFolder)...); len(left) != 0 {
					t.Fatalf("still open after Open returned: %v", left)
				}
			})
		}
	})
}
