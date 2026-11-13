// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Open's lines on a key store key, on Windows: the header under key holders 2 and 3, finding the
// key only among one store's machine keys, who has access to it, the unwrap and its result, the
// unseal under the unwrapped key, the order of these checks, and what is closed on return. Every
// key is made, wrapped under and deleted by the key store oracle; every bootstrap file is the
// bootstrap file oracle's. The rows that make a key need an elevated process; those on the TPM's
// key store need a TPM as well.
package bootstrap_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/heliosestate/heliosadvance/internal/bootstrap"
)

// The bootstrap file's layout under key holders 2 and 3, the test's own copy, as the page states
// it: the header's first 13 bytes, then the sealed key, 37 bytes of name and 256 of wrapped key,
// then the 12-byte nonce.
const (
	storeHeaderBytes = 13 + 293
	storeNonceAt     = storeHeaderBytes
	storeSealedAt    = storeHeaderBytes + 12
)

// storeEdits is the bootstrap file oracle's edits for a header under holder whose sealed key is
// name's bytes then wrapped.
func storeEdits(holder int, name string, wrapped []byte) string {
	return fmt.Sprintf("holder %d\nsealed hex:%s hex:%s\n", holder, hex.EncodeToString([]byte(name)), hex.EncodeToString(wrapped))
}

// storeFolder makes a bootstrap folder whose bootstrap file, sealed under the key in keyText,
// names name under holder with wrapped as its wrapped key, broken further as edits says. It holds
// no key file.
func storeFolder(t *testing.T, holder int, name string, wrapped, key []byte, keyText, edits string) *layout {
	t.Helper()
	folder := filepath.Join(t.TempDir(), "bootstrap")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatalf("making the bootstrap folder: %v", err)
	}
	made := &layout{folder: folder, file: filepath.Join(folder, fileName), keyFile: filepath.Join(folder, keyFileName),
		key: key, keyText: keyText, plaintext: plaintextOf(t, 64), keyName: name, wrapped: wrapped}
	if holder == holderOf[tpmStore] {
		made.turn = &tpmTurn
	}
	made.writeFile(t, seal(t, keyText, made.plaintext, storeEdits(holder, name, wrapped)+edits))
	return made
}

// keyFolder makes a good bootstrap folder for the key store key, whose first wrap must be of key,
// sealed under keyText's key, broken as edits says.
func keyFolder(t *testing.T, made *storeKey, key []byte, keyText, edits string) *layout {
	t.Helper()
	return storeFolder(t, holderOf[made.store], made.name, made.wraps[0], key, keyText, edits)
}

// keyWith has the oracle make a machine key in store with the access list given, wrapping a
// fresh key under it, and returns a good bootstrap folder for it, broken as edits says.
func keyWith(t *testing.T, store, list string, edits string) (*storeKey, *layout) {
	t.Helper()
	key, keyText := newKey(t)
	made := makeKey(t, keySpec{store: store, list: list, wraps: []wrapRequest{oaep(key)}})
	return made, keyFolder(t, made, key, keyText, edits)
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

// expectAnswer opens the folder and fails the row unless Open returned ErrKeyStore and no other
// refusal, no bytes, nothing secret in its error, and the key store's answer beneath it: the one
// the oracle met in the same case, so two refusals with two answers carry two different errors.
func (made *layout) expectAnswer(t *testing.T, answer windows.Errno) {
	t.Helper()
	contents, err := made.open(t)
	expectError(t, contents, err, bootstrap.ErrKeyStore)
	made.expectNothingSecret(t, err)
	if !errors.Is(err, answer) {
		t.Fatalf("Open's error %q does not carry the key store's answer %#x, %q, which the oracle met in the same case", err, answer, answer.Error())
	}
}

// Which wrap of the unwrap keys each row takes.
const (
	wrapGood = iota
	wrap31
	wrap33
	wrap34
	wrap190
	wrapZero
	wrapZeroButLast
	wrapSHA1
	wrapPKCS1
	wrapChanged
)

// unwrapKeys are the keys every row that leaves the access list as made shares in one store: a
// key with a good list and every wrap those rows need, and a second key wrapping the same
// bootstrap file key.
type unwrapKeys struct {
	store    string
	key      *storeKey
	second   *storeKey
	bootKey  []byte
	keyText  string
	payloads [][]byte
	empty    []byte
}

// makeUnwrapKeys has the oracle make the shared keys in store, deleted when the test ends. The
// wrap of nothing at all is the standard library's, under the key's public half: .NET will not
// wrap 0 bytes.
func makeUnwrapKeys(t *testing.T, store string) *unwrapKeys {
	t.Helper()
	key, keyText := newKey(t)
	zeroButLast := make([]byte, 32)
	zeroButLast[31] = 1
	keys := &unwrapKeys{store: store, bootKey: key, keyText: keyText, payloads: [][]byte{
		key, randomBytes(t, 31), randomBytes(t, 33), randomBytes(t, 34), randomBytes(t, 190),
		make([]byte, 32), zeroButLast, key, key, key,
	}}
	wraps := make([]wrapRequest, 0, len(keys.payloads))
	for index, payload := range keys.payloads {
		switch index {
		case wrapSHA1:
			wraps = append(wraps, wrapRequest{Padding: "oaep-sha1", Data: payload, Flip: -1})
		case wrapPKCS1:
			wraps = append(wraps, wrapRequest{Padding: "pkcs1", Data: payload, Flip: -1})
		case wrapChanged:
			wraps = append(wraps, wrapRequest{Padding: "oaep-sha256", Data: payload, Flip: 100})
		default:
			wraps = append(wraps, oaep(payload))
		}
	}
	keys.key = makeKey(t, keySpec{store: store, list: goodList(t), wraps: wraps})
	keys.second = makeKey(t, keySpec{store: store, list: goodList(t), wraps: []wrapRequest{oaep(key)}})
	empty, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, keys.key.public, []byte{}, nil)
	if err != nil {
		t.Fatalf("wrapping nothing under the key's public half: %v", err)
	}
	keys.empty = empty
	return keys
}

// folder makes a bootstrap folder whose sealed key is the shared key's name and its wrap which,
// sealed under the bootstrap file key, or under the 32 bytes unwrapped where the row is about
// those, broken further as edits says.
func (keys *unwrapKeys) folder(t *testing.T, which int, edits string) *layout {
	t.Helper()
	sealKey, sealText := keys.bootKey, keys.keyText
	if which == wrapZero || which == wrapZeroButLast {
		sealKey = keys.payloads[which]
		sealText = base64.StdEncoding.EncodeToString(sealKey) + "\n"
	}
	made := storeFolder(t, holderOf[keys.store], keys.key.name, keys.key.wraps[which], sealKey, sealText, edits)
	switch which {
	case wrap31, wrap33, wrap34, wrap190:
		made.unwrapped = keys.payloads[which]
	}
	return made
}

// badNames are sealed key names out of their form, each built from a name in it, 37 bytes like
// it.
var badNames = map[string]func(name string) string{
	"HADV- in capitals":               func(name string) string { return "HADV-" + name[5:] },
	"hadv_ in place of hadv-":         func(name string) string { return "hadv_" + name[5:] },
	"31 hex digits and a g":           func(name string) string { return name[:36] + "g" },
	"its hex digits in capitals":      func(name string) string { return "hadv-" + strings.ToUpper(name[5:]) },
	"a NUL in place of one hex digit": func(name string) string { return name[:20] + "\x00" + name[21:] },
}

// TestWindowsKeyStore holds the key store rows that need no key made: any Windows account can ask
// a key store for a key that is not there.
func TestWindowsKeyStore(t *testing.T) {
	t.Parallel()

	t.Run("If the bootstrap file is shorter than HeaderBytes, NonceBytes and TagBytes together, or its first HeaderBytes are not Magic, FormatVersion, then KeyHolderKeyFile with a sealed-key length of 0 or, on Windows, KeyHolderTPM or KeyHolderSoftwareKeyStore with a sealed-key length of SealedKeyBytes, or, under key holder 2 or 3, the file is too short for the sealed key, nonce and tag, or the sealed key's first KeyNameBytes are not KeyNamePrefix and 32 lower-case hex digits, then Open shall return ErrHeader before it opens the key file or asks a key store.", func(t *testing.T) {
		t.Parallel()
		spoils := map[string]func(t *testing.T, made *layout){
			"beside a good key file holding the key it is sealed under": func(*testing.T, *layout) {},
			"the key file missing": func(t *testing.T, made *layout) {
				t.Helper()
				remove(t, made.keyFile)
			},
			"the key file no one may open": func(t *testing.T, made *layout) {
				t.Helper()
				makeUnopenable(t, made.keyFile)
			},
			"the key file open to others": func(t *testing.T, made *layout) {
				t.Helper()
				openToOthers(t, made.keyFile)
			},
		}
		for _, holder := range []int{2, 3} {
			for badName, build := range badNames {
				for spoilName, spoil := range spoils {
					t.Run(fmt.Sprintf("key holder %d, 293 sealed bytes, the name with %s, %s: ErrHeader", holder, badName, spoilName), func(t *testing.T) {
						t.Parallel()
						key, keyText := newKey(t)
						made := storeFolder(t, holder, build(newKeyName(t)), randomBytes(t, 256), key, keyText, "")
						made.writeKey(t, keyText)
						spoil(t, made)
						made.expectRefused(t, bootstrap.ErrHeader)
					})
				}
			}
		}
		t.Run("key holder 2, 333 bytes, one short of header, sealed key, nonce and tag: ErrHeader", func(t *testing.T) {
			t.Parallel()
			key, keyText := newKey(t)
			made := storeFolder(t, 2, newKeyName(t), randomBytes(t, 256), key, keyText, "truncate 333")
			made.writeKey(t, keyText)
			expectSize(t, made, 333)
			made.expectRefused(t, bootstrap.ErrHeader)
		})
		t.Run("key holder 3, 334 bytes, a header, sealed key, nonce and tag with nothing sealed, its key not there: past the header, ErrKeyStore", func(t *testing.T) {
			t.Parallel()
			key, keyText := newKey(t)
			name := newKeyName(t)
			made := storeFolder(t, 3, name, randomBytes(t, 256), key, keyText, "truncate 334")
			expectSize(t, made, 334)
			made.expectAnswer(t, openAnswer(t, softwareStore, name))
		})
	})

	t.Run("If the key store will not load or open, the key store key is not there, or the key store refuses to open it, then Open shall return ErrKeyStore, with the key store's answer beneath it.", func(t *testing.T) {
		t.Parallel()
		// Each row is the header rows' twin, its name in form: a header row that passes because
		// Open never got as far as asking for a key would fail here.
		for store, holder := range holderOf {
			t.Run(fmt.Sprintf("key holder %d, a name in form that names no key in %s, beside a good key file holding the key it is sealed under: ErrKeyStore, the store's answer beneath", holder, store), func(t *testing.T) {
				t.Parallel()
				key, keyText := newKey(t)
				name := newKeyName(t)
				made := storeFolder(t, holder, name, randomBytes(t, 256), key, keyText, "")
				made.writeKey(t, keyText)
				made.expectAnswer(t, openAnswer(t, store, name))
			})
		}
	})

	t.Run("No error the bootstrap package returns shall hold, in its text, the key or any part of either file's contents.", func(t *testing.T) {
		t.Parallel()
		t.Run("key holder 3, a key that is not there: ErrKeyStore, neither the key's name nor its hex digits nor the wrapped bytes in the error", func(t *testing.T) {
			t.Parallel()
			key, keyText := newKey(t)
			name := newKeyName(t)
			made := storeFolder(t, 3, name, randomBytes(t, 256), key, keyText, "")
			made.expectAnswer(t, openAnswer(t, softwareStore, name))
		})
	})
}

// storeRows are the rows each key store holds alike, on keys the oracle makes in store; keys are
// the store's shared keys.
func storeRows(t *testing.T, store string, keys *unwrapKeys) {
	t.Helper()

	t.Run("Under KeyHolderTPM, Open shall look for the key store key the sealed key names only among the machine keys of Microsoft Platform Crypto Provider, and under KeyHolderSoftwareKeyStore only among those of Microsoft Software Key Storage Provider.", func(t *testing.T) {
		t.Parallel()
		t.Run(fmt.Sprintf("key holder %d, a machine key of %s: opens, the plaintext exact", holderOf[store], store), func(t *testing.T) {
			t.Parallel()
			keys.folder(t, wrapGood, "").expectOpened(t)
		})
	})

	t.Run("If reading the key store key's owner or access list fails, or an entry of its access list that allows access is of a kind other than a plain allow entry, such as a conditional entry, then Open shall return ErrKeyStorePermissions.", func(t *testing.T) {
		t.Parallel()
		t.Run("a conditional entry allowing Everyone to read when a member of Administrators, beside the user's own: ErrKeyStorePermissions", func(t *testing.T) {
			t.Parallel()
			_, made := keyWith(t, store, "O:BAD:P(A;;GA;;;"+runnerSID(t)+")(XA;;GR;;;WD;(Member_of {SID(BA)}))", "")
			made.expectRefused(t, bootstrap.ErrKeyStorePermissions)
		})
		t.Run("a conditional entry denying Everyone everything when a member of Guests, beside the user's own: an entry that denies is not judged, opens", func(t *testing.T) {
			t.Parallel()
			_, made := keyWith(t, store, "O:BAD:P(XD;;GA;;;WD;(Member_of {SID(BG)}))(A;;GA;;;"+runnerSID(t)+")", "")
			made.expectOpened(t)
		})
	})

	t.Run("If the key store key's owner, or any entry of its access list that allows access, whether the key's own or inherited, names anyone but SYSTEM (S-1-5-18), Administrators (S-1-5-32-544) or the user of the engine's own token, or the key has no access list, then Open shall return ErrKeyStoreReachable. An entry that denies access is not counted.", func(t *testing.T) {
		t.Parallel()
		for name, list := range map[string]func(t *testing.T) string{
			"an entry allowing Users to read, beside the user's own": func(t *testing.T) string {
				t.Helper()
				return "O:BAD:P(A;;GA;;;" + runnerSID(t) + ")(A;;GR;;;BU)"
			},
			"no access list at all": func(*testing.T) string { return "O:BAD:NO_ACCESS_CONTROL" },
			"Users the owner, the access list the user's alone": func(t *testing.T) string {
				t.Helper()
				return "O:BUD:P(A;;GA;;;" + runnerSID(t) + ")"
			},
		} {
			t.Run(name+": ErrKeyStoreReachable", func(t *testing.T) {
				t.Parallel()
				_, made := keyWith(t, store, list(t), "")
				made.expectRefused(t, bootstrap.ErrKeyStoreReachable)
			})
		}
		t.Run("SYSTEM, Administrators and the user, each allowed everything, Administrators the owner: opens", func(t *testing.T) {
			t.Parallel()
			keys.folder(t, wrapGood, "").expectOpened(t)
		})
		t.Run("the user alone, and an entry denying Guests everything: opens", func(t *testing.T) {
			t.Parallel()
			_, made := keyWith(t, store, "O:BAD:P(D;;GA;;;BG)(A;;GA;;;"+runnerSID(t)+")", "")
			made.expectOpened(t)
		})
	})

	t.Run("Open shall take the bootstrap file's key by unwrapping the sealed key's last WrappedKeyBytes under the key store key by RSA-OAEP with SHA-256, reading at most KeyBytes and one byte more.", func(t *testing.T) {
		t.Parallel()
		t.Run("the key wrapped by OAEP with SHA-256: opens, the plaintext exact", func(t *testing.T) {
			t.Parallel()
			keys.folder(t, wrapGood, "").expectOpened(t)
		})
		t.Run("the key wrapped by OAEP with SHA-1: ErrKeyStore, the store's answer beneath", func(t *testing.T) {
			t.Parallel()
			keys.folder(t, wrapSHA1, "").expectAnswer(t, keys.key.answers[wrapSHA1])
		})
		t.Run("the key wrapped by PKCS #1 v1.5: ErrKeyStore, the store's answer beneath", func(t *testing.T) {
			t.Parallel()
			keys.folder(t, wrapPKCS1, "").expectAnswer(t, keys.key.answers[wrapPKCS1])
		})
		t.Run("the sealed key swapped after sealing for a second key's name and its wrap of the same key: ErrUnseal, since the sealed key is sealed too", func(t *testing.T) {
			t.Parallel()
			made := keys.folder(t, wrapGood, "")
			swapped := append([]byte{}, made.sealed...)
			copy(swapped[13:], keys.second.name)
			copy(swapped[13+37:], keys.second.wraps[0])
			made.writeFile(t, swapped)
			made.expectRefused(t, bootstrap.ErrUnseal)
		})
	})

	t.Run("If the unwrap gives other than KeyBytes bytes, a result longer than KeyBytes and one byte included, or KeyBytes zero bytes, then Open shall return ErrUnwrap.", func(t *testing.T) {
		t.Parallel()
		for name, which := range map[string]int{
			"31 bytes": wrap31, "33 bytes": wrap33, "34 bytes": wrap34, "190 bytes, the most RSA-2048 wraps": wrap190,
			"32 zero bytes, the file sealed under them": wrapZero,
		} {
			t.Run(name+": ErrUnwrap", func(t *testing.T) {
				t.Parallel()
				keys.folder(t, which, "").expectRefused(t, bootstrap.ErrUnwrap)
			})
		}
		t.Run("0 bytes, wrapped by the standard library under the key's public half: ErrUnwrap", func(t *testing.T) {
			t.Parallel()
			storeFolder(t, holderOf[store], keys.key.name, keys.empty, keys.bootKey, keys.keyText, "").expectRefused(t, bootstrap.ErrUnwrap)
		})
		t.Run("32 bytes, all zero but the last, the file sealed under them: opens, the plaintext exact", func(t *testing.T) {
			t.Parallel()
			keys.folder(t, wrapZeroButLast, "").expectOpened(t)
		})
	})

	t.Run("If the key store refuses the unwrap for any other reason, then Open shall return ErrKeyStore, with the key store's answer beneath it.", func(t *testing.T) {
		t.Parallel()
		t.Run("a byte of the wrapped key changed: ErrKeyStore, the store's answer beneath", func(t *testing.T) {
			t.Parallel()
			keys.folder(t, wrapChanged, "").expectAnswer(t, keys.key.answers[wrapChanged])
		})
	})

	t.Run("No error the bootstrap package returns shall hold, in its text, the key or any part of either file's contents.", func(t *testing.T) {
		t.Parallel()
		t.Run("an unwrap of 33 bytes: ErrUnwrap, none of the 33 bytes in the error", func(t *testing.T) {
			t.Parallel()
			keys.folder(t, wrap33, "").expectRefused(t, bootstrap.ErrUnwrap)
		})
	})
}

// TestWindowsElevatedKeyStore holds the rows on the software key store's machine keys, which only
// an elevated process can make. CI's Windows runner is elevated.
func TestWindowsElevatedKeyStore(t *testing.T) {
	t.Parallel()
	keys := makeUnwrapKeys(t, softwareStore)
	storeRows(t, softwareStore, keys)

	t.Run("If the bootstrap file is shorter than HeaderBytes, NonceBytes and TagBytes together, or its first HeaderBytes are not Magic, FormatVersion, then KeyHolderKeyFile with a sealed-key length of 0 or, on Windows, KeyHolderTPM or KeyHolderSoftwareKeyStore with a sealed-key length of SealedKeyBytes, or, under key holder 2 or 3, the file is too short for the sealed key, nonce and tag, or the sealed key's first KeyNameBytes are not KeyNamePrefix and 32 lower-case hex digits, then Open shall return ErrHeader before it opens the key file or asks a key store.", func(t *testing.T) {
		t.Parallel()
		// The key is there under its lower-case name, so a store that matched names without
		// regard to case would find it: only the header check refuses these.
		for name, build := range map[string]func(name string) string{
			"its hex digits in capitals": badNames["its hex digits in capitals"],
			"HADV- in capitals":          badNames["HADV- in capitals"],
		} {
			t.Run("key holder 3, the name of a key that is there with "+name+": ErrHeader", func(t *testing.T) {
				t.Parallel()
				storeFolder(t, 3, build(keys.key.name), keys.key.wraps[wrapGood], keys.bootKey, keys.keyText, "").expectRefused(t, bootstrap.ErrHeader)
			})
		}
	})

	t.Run("Under KeyHolderTPM, Open shall look for the key store key the sealed key names only among the machine keys of Microsoft Platform Crypto Provider, and under KeyHolderSoftwareKeyStore only among those of Microsoft Software Key Storage Provider.", func(t *testing.T) {
		t.Parallel()
		t.Run("key holder 3, a key of the software key store made without the machine-key flag: ErrKeyStore, the store's answer beneath", func(t *testing.T) {
			t.Parallel()
			key, keyText := newKey(t)
			userKey := makeKey(t, keySpec{store: softwareStore, userKey: true, list: goodList(t), wraps: []wrapRequest{oaep(key)}})
			keyFolder(t, userKey, key, keyText, "").expectAnswer(t, openAnswer(t, softwareStore, userKey.name))
		})
		// Needs no TPM: where there is none, the TPM's store answers that its device is not ready,
		// and an Open that fell back to the software store would find the key there.
		t.Run("key holder 2 naming a machine key of the software key store: ErrKeyStore, the TPM store's answer beneath", func(t *testing.T) {
			t.Parallel()
			storeFolder(t, 2, keys.key.name, keys.key.wraps[wrapGood], keys.bootKey, keys.keyText, "").expectAnswer(t, openAnswer(t, tpmStore, keys.key.name))
		})
	})

	t.Run("Under KeyHolderKeyFile, Open shall take the key from the key file by the lines that follow on the key file, and under KeyHolderTPM or KeyHolderSoftwareKeyStore by the lines on the key store key, never by the other's; it shall not open the key file under key holder 2 or 3.", func(t *testing.T) {
		t.Parallel()
		for name, spoil := range map[string]func(t *testing.T, made *layout){
			"no key file": func(*testing.T, *layout) {},
			"a key file no one may open": func(t *testing.T, made *layout) {
				t.Helper()
				made.writeKey(t, made.keyText)
				makeUnopenable(t, made.keyFile)
			},
			"a key file open to others": func(t *testing.T, made *layout) {
				t.Helper()
				made.writeKey(t, made.keyText)
				openToOthers(t, made.keyFile)
			},
			"a key file out of its form": func(t *testing.T, made *layout) {
				t.Helper()
				made.writeKey(t, strings.TrimRight(made.keyText, "\r\n")[:43])
			},
		} {
			t.Run("key holder 3, a good key, with "+name+": opens, the plaintext exact", func(t *testing.T) {
				t.Parallel()
				made := keys.folder(t, wrapGood, "")
				spoil(t, made)
				made.expectOpened(t)
			})
		}
		t.Run("key holder 3, its key not there, beside a good key file holding the very key it is sealed under: ErrKeyStore", func(t *testing.T) {
			t.Parallel()
			name := newKeyName(t)
			made := storeFolder(t, 3, name, keys.key.wraps[wrapGood], keys.bootKey, keys.keyText, "")
			made.writeKey(t, keys.keyText)
			made.expectAnswer(t, openAnswer(t, softwareStore, name))
		})
	})

	t.Run("If the key store key's owner, or any entry of its access list that allows access, whether the key's own or inherited, names anyone but SYSTEM (S-1-5-18), Administrators (S-1-5-32-544) or the user of the engine's own token, or the key has no access list, then Open shall return ErrKeyStoreReachable. An entry that denies access is not counted.", func(t *testing.T) {
		t.Parallel()
		t.Run("an entry allowing Everyone to read, marked inherited, beside the user's own: ErrKeyStoreReachable", func(t *testing.T) {
			t.Parallel()
			_, made := keyWith(t, softwareStore, "O:BAD:P(A;;GA;;;"+runnerSID(t)+")(A;ID;GR;;;WD)", "")
			made.expectRefused(t, bootstrap.ErrKeyStoreReachable)
		})
		t.Run("the software key store's own list for a key made with none given, SYSTEM and Administrators: opens", func(t *testing.T) {
			t.Parallel()
			_, made := keyWith(t, softwareStore, "", "")
			made.expectOpened(t)
		})
	})

	t.Run("If the bootstrap file's tag does not verify under the key, then Open shall return ErrUnseal and no bytes.", func(t *testing.T) {
		t.Parallel()
		t.Run("key holder 3, the file sealed under a key other than the one wrapped: ErrUnseal, no bytes", func(t *testing.T) {
			t.Parallel()
			_, other := newKey(t)
			storeFolder(t, 3, keys.key.name, keys.key.wraps[wrapGood], keys.bootKey, other, "").expectRefused(t, bootstrap.ErrUnseal)
		})
		for name, edits := range map[string]string{
			"a byte of the nonce changed": fmt.Sprintf("flip %d", storeNonceAt+4),
			"a sealed byte changed":       fmt.Sprintf("flip %d", storeSealedAt+12),
			"a byte added after the tag":  "append hex:00",
		} {
			t.Run("key holder 3, "+name+": ErrUnseal, no bytes", func(t *testing.T) {
				t.Parallel()
				keys.folder(t, wrapGood, edits).expectRefused(t, bootstrap.ErrUnseal)
			})
		}
	})

	t.Run("Open shall check in the order of these lines and return the first refusal that applies.", func(t *testing.T) {
		t.Parallel()
		usersRead := func(t *testing.T) string {
			t.Helper()
			return "O:BAD:P(A;;GA;;;" + runnerSID(t) + ")(A;;GR;;;BU)"
		}
		changedSealed := fmt.Sprintf("flip %d", storeSealedAt+12)
		t.Run("key holder 3, its key not there, and a key file out of its form: ErrKeyStore", func(t *testing.T) {
			t.Parallel()
			name := newKeyName(t)
			made := storeFolder(t, 3, name, keys.key.wraps[wrapGood], keys.bootKey, keys.keyText, "")
			made.writeKey(t, strings.TrimRight(keys.keyText, "\r\n")[:43])
			made.expectAnswer(t, openAnswer(t, softwareStore, name))
		})
		t.Run("a conditional entry and an entry allowing Users to read: ErrKeyStorePermissions, not ErrKeyStoreReachable", func(t *testing.T) {
			t.Parallel()
			_, made := keyWith(t, softwareStore, usersRead(t)+"(XA;;GR;;;WD;(Member_of {SID(BA)}))", "")
			made.expectRefused(t, bootstrap.ErrKeyStorePermissions)
		})
		t.Run("an entry allowing Users to read and an unwrap of 31 bytes: ErrKeyStoreReachable, not ErrUnwrap", func(t *testing.T) {
			t.Parallel()
			key, keyText := newKey(t)
			made := makeKey(t, keySpec{store: softwareStore, list: usersRead(t), wraps: []wrapRequest{oaep(randomBytes(t, 31))}})
			keyFolder(t, made, key, keyText, "").expectRefused(t, bootstrap.ErrKeyStoreReachable)
		})
		t.Run("an entry allowing Users to read and a sealed byte changed: ErrKeyStoreReachable, not ErrUnseal", func(t *testing.T) {
			t.Parallel()
			_, made := keyWith(t, softwareStore, usersRead(t), changedSealed)
			made.expectRefused(t, bootstrap.ErrKeyStoreReachable)
		})
		t.Run("an unwrap of 31 bytes and a sealed byte changed: ErrUnwrap, not ErrUnseal", func(t *testing.T) {
			t.Parallel()
			keys.folder(t, wrap31, changedSealed).expectRefused(t, bootstrap.ErrUnwrap)
		})
		t.Run("the name of a key that is there with HADV- in capitals: ErrHeader, not opened", func(t *testing.T) {
			t.Parallel()
			storeFolder(t, 3, badNames["HADV- in capitals"](keys.key.name), keys.key.wraps[wrapGood], keys.bootKey, keys.keyText, "").expectRefused(t, bootstrap.ErrHeader)
		})
	})

	t.Run("When it returns, Open shall have closed the bootstrap folder and the files it opened, and freed every key store handle it opened.", func(t *testing.T) {
		t.Parallel()
		// Whether Open freed its key store handles cannot be seen from outside: an open key's
		// handle does not hold the key's file. That half is proved by reading.
		for name, way := range map[string]outcome{
			"key holder 3, opened": {want: nil, make: func(t *testing.T) *layout {
				t.Helper()
				return keys.folder(t, wrapGood, "")
			}},
			"key holder 3, ErrKeyStore": {want: bootstrap.ErrKeyStore, make: func(t *testing.T) *layout {
				t.Helper()
				return storeFolder(t, 3, newKeyName(t), keys.key.wraps[wrapGood], keys.bootKey, keys.keyText, "")
			}},
			"key holder 3, ErrKeyStorePermissions": {want: bootstrap.ErrKeyStorePermissions, make: func(t *testing.T) *layout {
				t.Helper()
				_, made := keyWith(t, softwareStore, "O:BAD:P(A;;GA;;;"+runnerSID(t)+")(XA;;GR;;;WD;(Member_of {SID(BA)}))", "")
				return made
			}},
			"key holder 3, ErrKeyStoreReachable": {want: bootstrap.ErrKeyStoreReachable, make: func(t *testing.T) *layout {
				t.Helper()
				_, made := keyWith(t, softwareStore, "O:BAD:NO_ACCESS_CONTROL", "")
				return made
			}},
			"key holder 3, ErrUnwrap": {want: bootstrap.ErrUnwrap, make: func(t *testing.T) *layout {
				t.Helper()
				return keys.folder(t, wrap31, "")
			}},
			"key holder 3, ErrUnseal": {want: bootstrap.ErrUnseal, make: func(t *testing.T) *layout {
				t.Helper()
				return keys.folder(t, wrapGood, "append hex:00")
			}},
			"key holder 3, ErrHeader": {want: bootstrap.ErrHeader, make: func(t *testing.T) *layout {
				t.Helper()
				return storeFolder(t, 3, badNames["HADV- in capitals"](keys.key.name), keys.key.wraps[wrapGood], keys.bootKey, keys.keyText, "")
			}},
		} {
			t.Run(name+": the folder and the bootstrap file open with no sharing at once", func(t *testing.T) {
				t.Parallel()
				made := way.reach(t)
				for _, path := range []string{made.folder, made.file} {
					if err := openAlone(path); err != nil {
						t.Fatalf("%s is still open after Open returned: %v", filepath.Base(path), err)
					}
				}
			})
		}
	})
}

// TestWindowsElevatedTPMKeyStore holds the rows on the TPM's key store, which need an elevated
// process to make a machine key and a TPM to make it in: check.sh skips them where either is
// missing, CI's runners among them.
func TestWindowsElevatedTPMKeyStore(t *testing.T) {
	t.Parallel()
	keys := makeUnwrapKeys(t, tpmStore)
	storeRows(t, tpmStore, keys)

	t.Run("Under KeyHolderTPM, Open shall look for the key store key the sealed key names only among the machine keys of Microsoft Platform Crypto Provider, and under KeyHolderSoftwareKeyStore only among those of Microsoft Software Key Storage Provider.", func(t *testing.T) {
		t.Parallel()
		t.Run("key holder 3 naming a machine key of the TPM's key store: ErrKeyStore, the software store's answer beneath", func(t *testing.T) {
			t.Parallel()
			storeFolder(t, 3, keys.key.name, keys.key.wraps[wrapGood], keys.bootKey, keys.keyText, "").expectAnswer(t, openAnswer(t, softwareStore, keys.key.name))
		})
	})

	t.Run("If the key store will not load or open, the key store key is not there, or the key store refuses to open it, then Open shall return ErrKeyStore, with the key store's answer beneath it.", func(t *testing.T) {
		t.Parallel()
		t.Run("a key whose access list names SYSTEM alone, which the TPM's key store refuses to open for the user: ErrKeyStore, the store's answer beneath", func(t *testing.T) {
			t.Parallel()
			key, keyText := newKey(t)
			made := makeKey(t, keySpec{store: tpmStore, list: goodList(t), later: "O:BAD:P(A;;GA;;;SY)", wraps: []wrapRequest{oaep(key)}})
			keyFolder(t, made, key, keyText, "").expectAnswer(t, openAnswer(t, tpmStore, made.name))
		})
	})

	t.Run("If the key store key's owner, or any entry of its access list that allows access, whether the key's own or inherited, names anyone but SYSTEM (S-1-5-18), Administrators (S-1-5-32-544) or the user of the engine's own token, or the key has no access list, then Open shall return ErrKeyStoreReachable. An entry that denies access is not counted.", func(t *testing.T) {
		t.Parallel()
		t.Run("the TPM's key store's own list for a key made with none given, CREATOR OWNER beside SYSTEM and Administrators: ErrKeyStoreReachable", func(t *testing.T) {
			t.Parallel()
			_, made := keyWith(t, tpmStore, "", "")
			made.expectRefused(t, bootstrap.ErrKeyStoreReachable)
		})
	})
}
