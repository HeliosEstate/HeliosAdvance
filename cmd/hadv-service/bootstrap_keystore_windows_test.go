// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The program and a bootstrap file whose key a Windows key store holds: finding the key in the
// one store the file names, who has access to it, the unwrap and its result, Bootstrap Part 1's
// key file lines left behind under key holder 3, a key store loaded from System32 alone, and
// neither the key nor what the store unwrapped in the local log. Every key is made, wrapped under
// and deleted by the key store oracle; every bootstrap file is the bootstrap file oracle's. Each
// refusal is one start_failed line and a non-zero exit, its reason not the reason another check
// gives. The rows that make a key need an elevated process; those on the TPM's key store need a
// TPM as well.
package main_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// storeMissingReason is the reason the program gives for a bootstrap file under the store's
// holder naming a key that is not there.
func storeMissingReason(t *testing.T, store string) string {
	t.Helper()
	key, keyText := newBootstrapKey(t)
	return storeBootstrapFolder(t, holderOf[store], newKeyName(t), randomBytes(t, 256), key, keyText, "").refused(t)
}

// randomBytes is size random bytes.
func randomBytes(t *testing.T, size int) []byte {
	t.Helper()
	random := make([]byte, size)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("making random bytes: %v", err)
	}
	return random
}

// expectNotInLog fails the row when the program's log holds any of the secrets, raw or in hex.
func expectNotInLog(t *testing.T, program *run, secrets map[string][]byte) {
	t.Helper()
	log := program.text()
	for name, secret := range secrets {
		for form, text := range map[string]string{"raw": string(secret), "in hex": hex.EncodeToString(secret),
			"in base64": base64.StdEncoding.EncodeToString(secret)} {
			if strings.Contains(log, text) {
				t.Fatalf("the local log holds %s, %s:\n%s", name, form, log)
			}
		}
	}
}

func TestWindowsBootstrapKeyStoreProgram(t *testing.T) {
	t.Parallel()

	t.Run("If the Windows key is not there, or the key store refuses to open it or to unwrap with it, then the engine shall write one `start_failed` line naming the key store and its answer, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("key holder 3 naming a key not there, and key holder 2 naming a key not there or with no TPM ready: one start_failed line each, and a non-zero exit, two reasons, each its own and neither a missing key file's", func(t *testing.T) {
			t.Parallel()
			expectDifferent(t, map[string]string{
				"the software key store, no such key": storeMissingReason(t, softwareStore),
				"the TPM's key store, no such key":    storeMissingReason(t, tpmStore),
				"a missing key file":                  keyMissingReason(t),
			})
		})
	})

	t.Run("If the bootstrap file's header is not format version 1's for the key file or, on Windows, for the TPM or the software key store, or the bootstrap file is too short for its header, nonce and tag, then the engine shall write one `start_failed` line saying so, without reading the key file or asking a key store, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		for store, holder := range holderOf {
			for name, edits := range map[string]func(name string) string{
				"292 sealed bytes": func(name string) string {
					return "holder " + strconv.Itoa(holder) + "\nsealed hex:" + hex.EncodeToString([]byte(name)) + " random:255\n"
				},
				"a name in capitals": func(name string) string {
					return "holder " + strconv.Itoa(holder) + "\nsealed \"" + strings.ToUpper(name) + "\" random:256\n"
				},
			} {
				t.Run("key holder "+strconv.Itoa(holder)+", "+name+", with a good key file and with it missing: the same reason each time, not the reason for a key not in "+store, func(t *testing.T) {
					t.Parallel()
					keyName := newKeyName(t)
					withKey := brokenFolder(t, edits(keyName))
					reason := withKey.refused(t)
					without := brokenFolder(t, edits(keyName))
					removeFile(t, without.keyFile)
					if got := without.refused(t); got != reason {
						t.Fatalf("with the key file missing the reason was %q, not the header's %q: the key file was read", got, reason)
					}
					expectOwnReason(t, reason, storeMissingReason(t, store), "a key not in "+store)
				})
			}
		}
	})
}

// TestWindowsElevatedBootstrapKeyStoreProgram holds the rows on the software key store's machine
// keys, which only an elevated process can make. CI's Windows runner is elevated.
func TestWindowsElevatedBootstrapKeyStoreProgram(t *testing.T) {
	t.Parallel()

	t.Run("When the bootstrap file's key holder is 2, the engine shall look for the key its sealed key names only among the machine keys of Microsoft's TPM key store, and when it is 3, only among those of Microsoft's software key store.", func(t *testing.T) {
		t.Parallel()
		t.Run("key holder 3, a machine key of the software key store: it starts", func(t *testing.T) {
			t.Parallel()
			_, made := keyStoreFolder(t, softwareStore, goodList(t), "")
			made.starts(t)
		})
		t.Run("key holder 3, a key of the software key store made without the machine-key flag: one start_failed line, and a non-zero exit, the reason neither a missing key file's nor a header's", func(t *testing.T) {
			t.Parallel()
			key, keyText := newBootstrapKey(t)
			userKey := makeStoreKey(t, softwareStore, true, goodList(t), "", oaep(key))
			made := storeBootstrapFolder(t, 3, userKey.name, userKey.wraps[0], key, keyText, "")
			reason := made.refused(t)
			expectOwnReason(t, reason, keyMissingReason(t), "a missing key file")
			expectOwnReason(t, reason, headerReason(t), "a header the engine does not read")
		})
	})

	t.Run("The engine shall take the bootstrap file's key by unwrapping the sealed key's last 256 bytes under that Windows key, by RSA-OAEP with SHA-256.", func(t *testing.T) {
		t.Parallel()
		t.Run("key holder 3, the key wrapped by OAEP with SHA-256: it starts", func(t *testing.T) {
			t.Parallel()
			_, made := keyStoreFolder(t, softwareStore, goodList(t), "")
			made.starts(t)
		})
		t.Run("key holder 3, a file that is not a DLL named ncrypt.dll beside a copy of the program: it starts, the key store loaded from System32", func(t *testing.T) {
			t.Parallel()
			expectNotKnownDLL(t, "ncrypt.dll")
			_, made := keyStoreFolder(t, softwareStore, goodList(t), "")
			folder := t.TempDir()
			program := filepath.Join(folder, filepath.Base(programPath))
			copyFile(t, programPath, program)
			if err := os.CopyFS(filepath.Join(folder, langFolder), os.DirFS(shippedLang)); err != nil {
				t.Fatalf("placing the shipped lang folder beside the copy of the program: %v", err)
			}
			if err := os.WriteFile(filepath.Join(folder, "ncrypt.dll"), []byte("not a DLL, planted beside the program"), 0o600); err != nil {
				t.Fatalf("planting ncrypt.dll: %v", err)
			}
			command := exec.CommandContext(t.Context(), program, databaseOption, made.path)
			command.Env = cleanEnvironment()
			started := startCommand(t, command)
			started.listening(t)
			expectNoPassword(t, started)
			made.expectKeyNotIn(t, started.text())
		})
	})

	t.Run("If the unwrap gives other than 32 bytes, or 32 zero bytes, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		zero := make([]byte, 32)
		for name, payload := range map[string][]byte{"31 bytes": randomBytes(t, 31), "33 bytes": randomBytes(t, 33), "32 zero bytes": zero} {
			t.Run("key holder 3, an unwrap of "+name+": one start_failed line, and a non-zero exit, the reason neither a missing key's nor a file that does not unseal's", func(t *testing.T) {
				t.Parallel()
				key, keyText := newBootstrapKey(t)
				if name == "32 zero bytes" {
					key, keyText = zero, base64.StdEncoding.EncodeToString(zero)+"\n"
				}
				made := makeStoreKey(t, softwareStore, false, goodList(t), "", oaep(payload))
				reason := storeBootstrapFolder(t, 3, made.name, made.wraps[0], key, keyText, "").refused(t)
				expectOwnReason(t, reason, storeMissingReason(t, softwareStore), "a key not there")
				expectOwnReason(t, reason, unsealReason(t), "a file that does not unseal")
			})
		}
	})

	t.Run("If the Windows key's owner, or any entry of its access list that allows access, names anyone but SYSTEM, Administrators or the account the engine runs as, or the key has no access list, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		for name, list := range map[string]func(t *testing.T) string{
			"an entry allowing Users to read, beside the account's own": func(t *testing.T) string {
				t.Helper()
				return "O:BAD:P(A;;GA;;;" + runnerSID(t) + ")(A;;GR;;;BU)"
			},
			"no access list at all": func(*testing.T) string { return "O:BAD:NO_ACCESS_CONTROL" },
			"Users the owner, the access list the account's alone": func(t *testing.T) string {
				t.Helper()
				return "O:BUD:P(A;;GA;;;" + runnerSID(t) + ")"
			},
		} {
			t.Run("key holder 3, "+name+": one start_failed line, and a non-zero exit, the reason not a missing key's", func(t *testing.T) {
				t.Parallel()
				_, made := keyStoreFolder(t, softwareStore, list(t), "")
				expectOwnReason(t, made.refused(t), storeMissingReason(t, softwareStore), "a key not there")
			})
		}
		t.Run("key holder 3, SYSTEM, Administrators and the account, each allowed everything: it starts", func(t *testing.T) {
			t.Parallel()
			_, made := keyStoreFolder(t, softwareStore, goodList(t), "")
			made.starts(t)
		})
	})

	t.Run("If the engine is unable to confirm that no account but those above has access to the Windows key, such as an access-list entry of a kind it does not judge, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("key holder 3, a conditional entry allowing Everyone to read when a member of Administrators, beside the account's own: one start_failed line, and a non-zero exit, the reason neither a missing key's nor a key Users may read's", func(t *testing.T) {
			t.Parallel()
			_, made := keyStoreFolder(t, softwareStore, "O:BAD:P(A;;GA;;;"+runnerSID(t)+")(XA;;GR;;;WD;(Member_of {SID(BA)}))", "")
			reason := made.refused(t)
			expectOwnReason(t, reason, storeMissingReason(t, softwareStore), "a key not there")
			_, reachable := keyStoreFolder(t, softwareStore, "O:BAD:P(A;;GA;;;"+runnerSID(t)+")(A;;GR;;;BU)", "")
			expectOwnReason(t, reason, reachable.refused(t), "a key Users may read")
		})
	})

	t.Run("If the bootstrap folder is missing or unreadable, the bootstrap file in it is missing, unreadable or a link leading out of the bootstrap folder, or, when the bootstrap file's key holder is the key file, the key file is, then the engine shall write one `start_failed` line saying which, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		for name, spoil := range map[string]func(t *testing.T, made *bootstrapFolder){
			"no key file": func(*testing.T, *bootstrapFolder) {},
			"a folder in the key file's place": func(t *testing.T, made *bootstrapFolder) {
				t.Helper()
				if err := os.Mkdir(made.keyFile, 0o700); err != nil {
					t.Fatalf("making a folder at the key file: %v", err)
				}
			},
		} {
			t.Run("key holder 3, a good key, with "+name+": it starts", func(t *testing.T) {
				t.Parallel()
				_, made := keyStoreFolder(t, softwareStore, goodList(t), "")
				spoil(t, made)
				made.starts(t)
			})
		}
	})

	t.Run("If the bootstrap file's key holder is the key file and, on Windows, the key file's owner, or any entry of its access list that allows access, names anyone but SYSTEM, Administrators or the account the engine runs as, or the key file has no access list, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("key holder 3, a good key, beside a key file with no access list at all: it starts", func(t *testing.T) {
			t.Parallel()
			_, made := keyStoreFolder(t, softwareStore, goodList(t), "")
			made.writeKey(t, made.keyText)
			openToOthers(t, made.keyFile)
			made.starts(t)
		})
	})

	t.Run("If the bootstrap file's key holder is the key file and the engine is unable to confirm that no account but those above has access to the key file, such as on Windows an access-list entry of a kind it does not judge, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("key holder 3, a good key, beside a key file with a conditional entry: it starts", func(t *testing.T) {
			t.Parallel()
			_, made := keyStoreFolder(t, softwareStore, goodList(t), "")
			made.writeKey(t, made.keyText)
			setAccessList(t, made.keyFile, conditionalAllow(t))
			made.starts(t)
		})
	})

	t.Run("If the bootstrap file's key holder is the key file and the key file is not in the key file's form, or holds a key of 32 zero bytes, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("key holder 3, a good key, beside a key file out of its form: it starts", func(t *testing.T) {
			t.Parallel()
			_, made := keyStoreFolder(t, softwareStore, goodList(t), "")
			made.writeKey(t, made.keyBase()[:43])
			made.starts(t)
		})
	})

	t.Run("If the bootstrap file does not unseal under the key its key holder gives, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("key holder 3, the file sealed under a key other than the one wrapped, beside a key file holding the key it is sealed under: one start_failed line, and a non-zero exit, the reason not a missing key's", func(t *testing.T) {
			t.Parallel()
			key, _ := newBootstrapKey(t)
			_, other := newBootstrapKey(t)
			made := makeStoreKey(t, softwareStore, false, goodList(t), "", oaep(key))
			folder := storeBootstrapFolder(t, 3, made.name, made.wraps[0], key, other, "")
			folder.writeKey(t, other)
			expectOwnReason(t, folder.refused(t), storeMissingReason(t, softwareStore), "a key not there")
		})
	})

	t.Run("The engine shall not write the bootstrap file's password, or its key from the key file or a Windows key store, to the local log.", func(t *testing.T) {
		t.Parallel()
		t.Run("key holder 3, a run that starts and stops: neither the password, nor the key, nor the wrapped key anywhere in its log", func(t *testing.T) {
			t.Parallel()
			send := stopSignals()[0].prepare(t)
			made, folder := keyStoreFolder(t, softwareStore, goodList(t), "")
			program := startWithFile(t, folder.path, nil)
			program.listening(t)
			_, sentBy := send(t, program)
			program.exit(t, sentBy.Add(endLeaseWait+testrun.Patient(margin)))
			expectNoPassword(t, program)
			folder.expectKeyNotIn(t, program.text())
			expectNotInLog(t, program, map[string][]byte{"the wrapped key": made.wraps[0], "the key's name": []byte(made.name)})
		})
		t.Run("key holder 3, an unwrap of 33 bytes: one start_failed line, the reason not a header's, and none of the 33 bytes in the log", func(t *testing.T) {
			t.Parallel()
			key, keyText := newBootstrapKey(t)
			result := randomBytes(t, 33)
			made := makeStoreKey(t, softwareStore, false, goodList(t), "", oaep(result))
			folder := storeBootstrapFolder(t, 3, made.name, made.wraps[0], key, keyText, "")
			program := startWithFile(t, folder.path, nil)
			expectOwnReason(t, program.expectRefusal(t), headerReason(t), "a header the engine does not read")
			expectNotInLog(t, program, map[string][]byte{"what the key store unwrapped": result, "its first 32 bytes": result[:32]})
		})
	})
}

// headerReason is the reason the program gives for a bootstrap file whose header it does not
// read: a wrong magic.
func headerReason(t *testing.T) string {
	t.Helper()
	return brokenFolder(t, `magic "HADVBOOX"`).refused(t)
}

// unsealReason is the reason the program gives for a good file under key holder 3 sealed under
// another key than the one wrapped.
func unsealReason(t *testing.T) string {
	t.Helper()
	key, _ := newBootstrapKey(t)
	_, other := newBootstrapKey(t)
	made := makeStoreKey(t, softwareStore, false, goodList(t), "", oaep(key))
	return storeBootstrapFolder(t, 3, made.name, made.wraps[0], key, other, "").refused(t)
}

// expectNotKnownDLL fails the row as one that cannot tell when Windows lists the DLL among its
// KnownDLLs, which it loads from System32 whatever a program asks: a DLL planted beside the
// program would then prove nothing.
func expectNotKnownDLL(t *testing.T, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testrun.Patient(testrun.HangBound))
	defer cancel()
	output, err := exec.CommandContext(ctx, "reg", "query", `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`).CombinedOutput()
	if err != nil {
		t.Fatalf("reading Windows' KnownDLLs: %v: %s", err, strings.TrimSpace(string(output)))
	}
	if strings.Contains(strings.ToLower(string(output)), strings.ToLower(name)) {
		t.Fatalf("cannot tell: Windows lists %s among its KnownDLLs, so it is loaded from System32 whatever the program asks", name)
	}
}

// TestWindowsElevatedTPMBootstrapKeyStoreProgram holds the rows on the TPM's key store, which
// need an elevated process to make a machine key and a TPM to make it in: check.sh skips them
// where either is missing, CI's runners among them.
func TestWindowsElevatedTPMBootstrapKeyStoreProgram(t *testing.T) {
	t.Parallel()

	t.Run("When the bootstrap file's key holder is 2, the engine shall look for the key its sealed key names only among the machine keys of Microsoft's TPM key store, and when it is 3, only among those of Microsoft's software key store.", func(t *testing.T) {
		t.Parallel()
		t.Run("key holder 2, a machine key of the TPM's key store: it starts", func(t *testing.T) {
			t.Parallel()
			_, made := keyStoreFolder(t, tpmStore, goodList(t), "")
			made.starts(t)
		})
	})

	t.Run("If the Windows key is not there, or the key store refuses to open it or to unwrap with it, then the engine shall write one `start_failed` line naming the key store and its answer, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("key holder 2, a key whose access list names SYSTEM alone, which the TPM's key store refuses to open: one start_failed line, and a non-zero exit, the reason not a missing key's in the same store", func(t *testing.T) {
			t.Parallel()
			key, keyText := newBootstrapKey(t)
			made := makeStoreKey(t, tpmStore, false, goodList(t), "O:BAD:P(A;;GA;;;SY)", oaep(key))
			reason := storeBootstrapFolder(t, 2, made.name, made.wraps[0], key, keyText, "").refused(t)
			expectOwnReason(t, reason, storeMissingReason(t, tpmStore), "a key not in the TPM's key store")
		})
		t.Run("key holder 2 naming a key not there, beside key holder 3 naming one not there: two reasons, each its own", func(t *testing.T) {
			t.Parallel()
			expectOwnReason(t, storeMissingReason(t, tpmStore), storeMissingReason(t, softwareStore), "a key not in the software key store")
		})
	})
}
