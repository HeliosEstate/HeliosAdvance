// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The Linux rows of issue #148, run inside TestOpenLinuxRowsInContainer's container: as root,
// since the Swarm secret's path is root's, then as the account nobody, whom a folder or file
// at mode 000 refuses. Each wrong file is written by the oracle's program in the image, from
// a kept sample's record list with one change.
package bootstrap

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/board"
)

// The lines only the Linux rows prove, word for word.
const (
	lineKeyForm      = "If the key file or the Swarm secret breaks the form the package comment gives, then the bootstrap package shall return ErrKey."
	lineKeyMissing   = "If the key file or the Swarm secret is not there, or reading it fails, then the bootstrap package shall return ErrKey."
	lineKeySize      = "If a key holder gives a bootstrap key that is not 32 bytes, then the bootstrap package shall return ErrKey."
	lineRecordLayout = "If a record breaks the record layout the package comment gives, then the bootstrap package shall return ErrInvalid."
	lineVaultVersion = "If a record's name begins with vault.key. and the rest is not a version in decimal from 1 to 4,294,967,295 with no leading zero, then the bootstrap package shall return ErrInvalid."
	lineHeader       = "If a part of the header does not match the table the package comment gives for format version 1, or the file is too short for its header, nonce and tag, then open shall return ErrFormat before it asks the key holder."
	lineDecrypt      = "If the GCM tag does not verify under the bootstrap key, then open shall return ErrDecrypt and no handle."
	lineNoHandle     = "If open fails, then open shall return no handle."
	lineHandle       = "When open returns a handle, the handle shall give the file's fields, its key holder and its sealed key."
)

// The rows more than one Linux line shares: one name for each case.
const (
	rowFileLinksOut  = "bootstrap.hadv a symbolic link out of the folder"
	rowFolderLocked  = "the bootstrap folder at mode 000"
	rowFileLocked    = "bootstrap.hadv at mode 000"
	rowKeyFileLocked = "bootstrap.key at mode 000"
	rowWrongMagic    = "a wrong magic"
	rowNoKeyFile     = "no bootstrap.key"
	rowWrongKey      = "another key in bootstrap.key"
	rowEmptyName     = "an empty name"
	viaKeyFile       = "key file: "
	viaSwarmSecret   = "Swarm secret: "
)

const (
	swarmFolder   = "/run/secrets"
	oracleProgram = "/usr/local/bin/bootstrap-file" // inside the oracle's image
)

// keyRow is one key file or Swarm secret text, by its case.
type keyRow struct {
	name string
	text string
}

// TestOpenLinuxAsRoot is every Linux row but those that need an account refused by
// permissions. The rows that use the Swarm secret share its one fixed path, so they run one
// after another; the rest run in parallel.
//
//nolint:paralleltest // the Swarm secret's path is fixed: its rows cannot overlap
func TestOpenLinuxAsRoot(t *testing.T) {
	requireContainer(t)
	if os.Getuid() != 0 {
		t.Fatalf("these rows run as root; running as uid %d", os.Getuid())
	}
	removeSwarmSecret(t)
	good := testKeyText(t)
	base := sampleList(t, sampleKeyFile)
	baseFields := fieldsOf(t, base)

	t.Run("on a missing or unreadable folder or file", placeRows)

	t.Run(lineFileUnreadable, func(t *testing.T) {
		t.Run(rowFileLinksOut, func(t *testing.T) {
			folder := linkOutFolder(t, FileName, sampleBytes(t, sampleKeyFile+".hadv"))
			writeKeyFile(t, folder, good+"\n")
			file, err := open(t, folder)
			wantRefused(t, file, err, ErrUnreadable)
			wantCause(t, err)
		})
	})
	t.Run(linePlace, func(t *testing.T) {
		t.Run(rowFileLinksOut, func(t *testing.T) {
			folder := linkOutFolder(t, FileName, sampleBytes(t, sampleKeyFile+".hadv"))
			writeKeyFile(t, folder, good+"\n")
			_, err := open(t, folder)
			wantPlace(t, err, PlaceFile)
		})
	})

	t.Run(lineKeyForm, func(t *testing.T) {
		rows := []keyRow{
			{"43 characters", good[:43]},
			{"45 characters", good + "A"},
			{"two trailing newlines", good + "\n\n"},
			{"a carriage return before the newline", good + "\r\n"},
			{"a space before the key", " " + good + "\n"},
			{"a space after the key", good + " \n"},
			{"a character outside the standard alphabet", "-" + good[1:] + "\n"},
			{"the bits after the last byte not zero", nonzeroTail(t, good) + "\n"},
			{"an empty file", ""},
			{"a newline alone", "\n"},
			{"a NUL byte after the key", good + "\x00"},
		}
		keyRows(t, rows, func(t *testing.T, err error) {
			t.Helper()
			wantCode(t, err, ErrKey)
		})
		keyRows(t, []keyRow{
			{"44 characters and one newline open", good + "\n"},
			{"44 characters with no newline open", good},
		}, func(t *testing.T, err error) {
			t.Helper()
			if err != nil {
				t.Fatalf("got %v, want a handle", err)
			}
		})
	})

	t.Run(lineKeyMissing, func(t *testing.T) {
		t.Run(viaKeyFile+rowNoKeyFile, func(t *testing.T) {
			folder := t.TempDir()
			copySample(t, folder, sampleKeyFile)
			file, err := open(t, folder)
			wantRefused(t, file, err, ErrKey)
		})
		t.Run(viaKeyFile+"a folder named bootstrap.key", func(t *testing.T) {
			folder := t.TempDir()
			copySample(t, folder, sampleKeyFile)
			if err := os.Mkdir(filepath.Join(folder, KeyFileName), 0o700); err != nil {
				t.Fatal(err)
			}
			file, err := open(t, folder)
			wantRefused(t, file, err, ErrKey)
		})
		t.Run(viaKeyFile+"bootstrap.key a symbolic link out of the folder", func(t *testing.T) {
			folder := linkOutFolder(t, KeyFileName, []byte(good+"\n"))
			copySample(t, folder, sampleKeyFile)
			file, err := open(t, folder)
			wantRefused(t, file, err, ErrKey)
		})
		t.Run(viaSwarmSecret+"no Swarm secret", func(t *testing.T) {
			folder := t.TempDir()
			copySample(t, folder, sampleSwarmSecret)
			file, err := open(t, folder)
			wantRefused(t, file, err, ErrKey)
		})
		t.Run(viaSwarmSecret+"a folder at the Swarm secret's path", func(t *testing.T) {
			folder := t.TempDir()
			copySample(t, folder, sampleSwarmSecret)
			if err := os.MkdirAll(SwarmSecretPath, 0o700); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { removeSwarmSecret(t) })
			file, err := open(t, folder)
			wantRefused(t, file, err, ErrKey)
		})
	})

	t.Run(lineKeySize, func(t *testing.T) {
		keyRows(t, []keyRow{
			{"44 characters that decode to 31 bytes", keyText(make([]byte, 31)) + "\n"},
			{"44 characters that decode to 33 bytes", keyText(make([]byte, 33)) + "\n"},
		}, func(t *testing.T, err error) {
			t.Helper()
			wantCode(t, err, ErrKey)
		})
		keyRows(t, []keyRow{{"a key of 32 bytes opens", good + "\n"}}, func(t *testing.T, err error) {
			t.Helper()
			if err != nil {
				t.Fatalf("got %v, want a handle", err)
			}
		})
	})

	t.Run(lineRecordLayout, func(t *testing.T) {
		vaultKey := `record "vault.key.1" `
		server := `record "server" `
		for _, row := range []struct {
			name string
			list recordList
		}{
			{"a record whose data runs past the end", base.with(`record "a" "abc" data-length=100`)},
			{"a record whose name runs past the end", base.with(`record "a" "abc" name-length=500`)},
			{"the plaintext cut inside a record's framing", base.with(`raw hex:0005616263`)},
			{rowEmptyName, base.with(`record "" "x"`)},
			{"a name that is not UTF-8", base.with(`record hex:ff "x"`)},
			{"a name of 256 bytes", base.with(`record zeros:256 "x"`)},
			{"two records of one unknown name", base.with(`record "x" "1"`, `record "x" "2"`)},
			{"the server record twice", base.with(server + "hex:00000001")},
			{"a server record of 3 bytes", base.replacing(t, server, server+"hex:000001")},
			{"a server record of 5 bytes", base.replacing(t, server, server+"hex:0000000001")},
			{"a vault key of 31 bytes", base.replacing(t, vaultKey, vaultKey+"zeros:31")},
			{"a vault key of 33 bytes", base.replacing(t, vaultKey, vaultKey+"zeros:33")},
		} {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				file, err := open(t, keyFileFolder(t, row.list, good))
				wantRefused(t, file, err, ErrInvalid)
			})
		}
		for _, row := range []struct {
			name string
			list recordList
		}{
			{"a name of 255 bytes opens", base.with(`record zeros:255 "x"`)},
			{"an unknown record with no data opens", base.with(`record "x" ""`)},
		} {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				file, err := open(t, keyFileFolder(t, row.list, good))
				wantOpened(t, file, err, baseFields, KeyFile)
			})
		}
	})

	t.Run(lineVaultVersion, func(t *testing.T) {
		vaultKey := `record "vault.key.1" `
		data := base.recordOf(t, "vault.key.1")
		for _, rest := range []string{
			"01", "0", "4294967296", "99999999999999999999", "x", "", "+1", "-1", " 1", "1 ", "0x1",
			`\xd9\xa1`, // ARABIC-INDIC DIGIT ONE, a decimal digit to Unicode but not ASCII
		} {
			t.Run("vault.key."+rest, func(t *testing.T) {
				t.Parallel()
				list := base.replacing(t, vaultKey, `record "vault.key.`+rest+`" `+data)
				file, err := open(t, keyFileFolder(t, list, good))
				wantRefused(t, file, err, ErrInvalid)
			})
		}
		for _, version := range []uint32{4294967295, 9} {
			name := "vault.key." + strconv.FormatUint(uint64(version), 10)
			t.Run(name+" opens", func(t *testing.T) {
				t.Parallel()
				list := base.replacing(t, vaultKey, `record "`+name+`" `+data)
				want := baseFields
				want.VaultKeys = []VaultKey{{Version: version, Key: baseFields.VaultKeys[0].Key}}
				file, err := open(t, keyFileFolder(t, list, good))
				wantOpened(t, file, err, want, KeyFile)
			})
		}
		for _, name := range []string{"vault.key", "vault.keys.1", "vault-key.1"} {
			t.Run(name+" is an unknown record and opens", func(t *testing.T) {
				t.Parallel()
				file, err := open(t, keyFileFolder(t, base.with(`record "`+name+`" `+data), good))
				wantOpened(t, file, err, baseFields, KeyFile)
			})
		}
	})

	t.Run(lineTooLarge, func(t *testing.T) {
		size := len(oracleWrite(t, base, good))
		for _, row := range []struct {
			name  string
			bytes int
		}{
			{"a file of 65,537 bytes", MaxSize + 1},
			{"a file of 262,144 bytes", 4 * MaxSize}, // the most the oracle appends
		} {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				list := base.with("append zeros:" + strconv.Itoa(row.bytes-size))
				file, err := open(t, keyFileFolder(t, list, good))
				wantRefused(t, file, err, ErrFormat)
			})
		}
		t.Run("a file of 65,536 bytes opens", func(t *testing.T) {
			t.Parallel()
			// An unknown record's 2-byte name length, 7-byte name and 4-byte data length.
			list := base.with(`record "padding" zeros:` + strconv.Itoa(MaxSize-size-13))
			folder := keyFileFolder(t, list, good)
			if info, err := os.Stat(filepath.Join(folder, FileName)); err != nil || info.Size() != MaxSize {
				t.Fatalf("the oracle's file: %v, want %d bytes", err, MaxSize)
			}
			file, err := open(t, folder)
			wantOpened(t, file, err, baseFields, KeyFile)
		})
	})

	t.Run(lineHeader, func(t *testing.T) {
		windowsName := `"hadv-0123456789abcdef0123456789abcdef"`
		holderOne := "holder 1"
		headerRows := []struct {
			name  string
			lines []string // each replaces the line that starts as it does, or is added
		}{
			{rowWrongMagic, []string{`magic "HADVBOOX"`}},
			{"format version 0", []string{"version 0"}},
			{"format version 2", []string{"version 2"}},
			{"key holder 0", []string{"holder 0"}},
			{"key holder 6", []string{"holder 6"}},
			{"key holder 1 with a sealed key one byte short", []string{holderOne, "sealed " + windowsName + " random:255"}},
			{"key holder 1 with a sealed key one byte long", []string{holderOne, "sealed " + windowsName + " random:257"}},
			{"key holder 1 with a key name in uppercase hex", []string{holderOne, `sealed "hadv-0123456789ABCDEF0123456789ABCDEF" random:256`}},
			{"key holder 1 with a key name that does not begin hadv-", []string{holderOne, `sealed "hadx-0123456789abcdef0123456789abcdef" random:256`}},
			{"key holder 2 with no sealed key", []string{"holder 2"}},
			{"key holder 3 with a sealed key of 4,097 bytes", []string{"holder 3", "sealed random:4097"}},
			{"key holder 4 with a sealed key", []string{"sealed random:1"}},
			{"key holder 5 with a sealed key", []string{"holder 5", "sealed random:1"}},
			{"a sealed-key length past the file's end", []string{"holder 2", "sealed random:100", "sealed-length 4000"}},
			{"a file one byte too short for its header, nonce and tag", []string{"truncate 40"}},
			{"a file of 12 bytes", []string{"truncate 12"}},
			{"an empty file", []string{"truncate 0"}},
		}
		for _, row := range headerRows {
			t.Run(row.name, func(t *testing.T) {
				list := base
				for _, line := range row.lines {
					prefix, _, _ := strings.Cut(line, " ")
					if prefix == "holder" || prefix == "sealed" || prefix == "magic" || prefix == "version" {
						list = list.replacing(t, prefix+" ", line)
					} else {
						list = list.with(line)
					}
				}
				// No key file and no Swarm secret: had open asked the key holder, it would
				// have got ErrKey.
				folder := t.TempDir()
				writeOracleFile(t, filepath.Join(folder, FileName), list, good)
				file, err := open(t, folder)
				wantRefused(t, file, err, ErrFormat)
			})
		}
	})

	t.Run(lineDecrypt, func(t *testing.T) {
		size := len(oracleWrite(t, base, good))
		for _, row := range []struct {
			name string
			list recordList
		}{
			{"a nonce byte changed", base.with("flip 14")},
			{"a ciphertext byte changed", base.with("flip 60")},
			{"a tag byte changed", base.with("flip " + strconv.Itoa(size-1))},
			{"a byte added at the end", base.with("append hex:00")},
			{"a byte cut from the end", base.with("truncate " + strconv.Itoa(size-1))},
		} {
			t.Run(row.name, func(t *testing.T) {
				file, err := open(t, keyFileFolder(t, row.list, good))
				wantRefused(t, file, err, ErrDecrypt)
			})
		}
		t.Run(rowWrongKey, func(t *testing.T) {
			folder := keyFileFolder(t, base, good)
			writeKeyFile(t, folder, keyText(randomKey(t))+"\n")
			file, err := open(t, folder)
			wantRefused(t, file, err, ErrDecrypt)
		})
		t.Run("key holder 4 changed to 5, with the same key in the Swarm secret", func(t *testing.T) {
			folder := t.TempDir()
			writeOracleFile(t, filepath.Join(folder, FileName), base.with("flip 10"), good)
			writeSwarmSecret(t, good+"\n")
			file, err := open(t, folder)
			wantRefused(t, file, err, ErrDecrypt)
		})
		t.Run("the right key opens", func(t *testing.T) {
			file, err := open(t, keyFileFolder(t, base, good))
			wantOpened(t, file, err, baseFields, KeyFile)
		})
	})

	t.Run(lineNoHandle, func(t *testing.T) {
		for _, row := range []struct {
			name   string
			folder func(t *testing.T) string
			code   error
		}{
			{rowFolderMissing, func(t *testing.T) string { t.Helper(); return filepath.Join(t.TempDir(), "missing") }, ErrNotFound},
			{rowFolderForFile, folderForFile, ErrUnreadable},
			{rowWrongMagic, func(t *testing.T) string {
				t.Helper()
				return keyFileFolder(t, base.replacing(t, "magic ", `magic "HADVBOOX"`), good)
			}, ErrFormat},
			{rowNoKeyFile, func(t *testing.T) string {
				t.Helper()
				folder := t.TempDir()
				copySample(t, folder, sampleKeyFile)
				return folder
			}, ErrKey},
			{rowWrongKey, func(t *testing.T) string {
				t.Helper()
				folder := keyFileFolder(t, base, good)
				writeKeyFile(t, folder, keyText(randomKey(t))+"\n")
				return folder
			}, ErrDecrypt},
			{rowEmptyName, func(t *testing.T) string { t.Helper(); return keyFileFolder(t, base.with(`record "" "x"`), good) }, ErrInvalid},
		} {
			t.Run(row.name, func(t *testing.T) {
				file, err := open(t, row.folder(t))
				wantRefused(t, file, err, row.code)
			})
		}
	})

	t.Run(lineHandle, func(t *testing.T) {
		for _, row := range []struct{ name, sample string }{
			{"key holder 4", sampleKeyFile},
			{"two vault keys", sampleTwoVaultKeys},
			{"an unknown record between the known ones", sampleUnknown},
		} {
			t.Run(row.name, func(t *testing.T) {
				folder := t.TempDir()
				copySample(t, folder, row.sample)
				writeKeyFile(t, folder, good+"\n")
				file, err := open(t, folder)
				wantOpened(t, file, err, fieldsOf(t, sampleList(t, row.sample)), KeyFile)
			})
		}
		t.Run("key holder 5", func(t *testing.T) {
			folder := t.TempDir()
			copySample(t, folder, sampleSwarmSecret)
			writeSwarmSecret(t, good+"\n")
			file, err := open(t, folder)
			wantOpened(t, file, err, fieldsOf(t, sampleList(t, sampleSwarmSecret)), SwarmSecret)
		})
	})
}

// TestOpenLinuxAsNobody is the rows that need an account the folder's or the file's mode
// refuses, run as nobody, since root reads past any mode.
func TestOpenLinuxAsNobody(t *testing.T) {
	t.Parallel()
	requireContainer(t)
	if os.Getuid() == 0 {
		t.Fatal("these rows run as an account other than root")
	}
	good := testKeyText(t)
	lockedFolder := func(t *testing.T) string {
		t.Helper()
		folder := t.TempDir()
		copySample(t, folder, sampleKeyFile)
		writeKeyFile(t, folder, good+"\n")
		lock(t, folder)
		return folder
	}
	lockedFile := func(t *testing.T) string {
		t.Helper()
		folder := t.TempDir()
		copySample(t, folder, sampleKeyFile)
		writeKeyFile(t, folder, good+"\n")
		lock(t, filepath.Join(folder, FileName))
		return folder
	}
	t.Run(lineFolderUnreadable, func(t *testing.T) {
		t.Parallel()
		t.Run(rowFolderLocked, func(t *testing.T) {
			t.Parallel()
			file, err := open(t, lockedFolder(t))
			wantRefused(t, file, err, ErrUnreadable)
			wantCause(t, err)
			wantPermission(t, err)
		})
	})
	t.Run(lineFileUnreadable, func(t *testing.T) {
		t.Parallel()
		t.Run(rowFileLocked, func(t *testing.T) {
			t.Parallel()
			file, err := open(t, lockedFile(t))
			wantRefused(t, file, err, ErrUnreadable)
			wantCause(t, err)
			wantPermission(t, err)
		})
	})
	t.Run(linePlace, func(t *testing.T) {
		t.Parallel()
		t.Run(rowFolderLocked, func(t *testing.T) {
			t.Parallel()
			_, err := open(t, lockedFolder(t))
			wantPlace(t, err, PlaceFolder)
		})
		t.Run(rowFileLocked, func(t *testing.T) {
			t.Parallel()
			_, err := open(t, lockedFile(t))
			wantPlace(t, err, PlaceFile)
		})
	})
	t.Run(lineKeyMissing, func(t *testing.T) {
		t.Parallel()
		t.Run(viaKeyFile+rowKeyFileLocked, func(t *testing.T) {
			t.Parallel()
			folder := t.TempDir()
			copySample(t, folder, sampleKeyFile)
			writeKeyFile(t, folder, good+"\n")
			lock(t, filepath.Join(folder, KeyFileName))
			file, err := open(t, folder)
			wantRefused(t, file, err, ErrKey)
		})
	})
}

// keyRows runs each row's text as the key file under key holder 4, then as the Swarm secret
// under key holder 5, both over the kept samples, and judges open's result with want.
func keyRows(t *testing.T, rows []keyRow, want func(t *testing.T, err error)) {
	t.Helper()
	for _, row := range rows {
		t.Run(viaKeyFile+row.name, func(t *testing.T) {
			folder := t.TempDir()
			copySample(t, folder, sampleKeyFile)
			writeKeyFile(t, folder, row.text)
			file, err := open(t, folder)
			if file != nil {
				defer file.Release()
			}
			want(t, err)
		})
		t.Run(viaSwarmSecret+row.name, func(t *testing.T) {
			folder := t.TempDir()
			copySample(t, folder, sampleSwarmSecret)
			writeSwarmSecret(t, row.text)
			file, err := open(t, folder)
			if file != nil {
				defer file.Release()
			}
			want(t, err)
		})
	}
}

// nonzeroTail is the key text with its last character before the padding changed so that the
// two bits after the key's last byte are not zero: the same 32 bytes, spelled a second way.
func nonzeroTail(t *testing.T, good string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	index := strings.IndexByte(alphabet, good[42])
	if index < 0 || good[43] != '=' {
		t.Fatalf("the test key %q does not end in one padding character", good)
	}
	return good[:42] + string(alphabet[index|1]) + "="
}

// keyFileFolder is a bootstrap folder holding the file the oracle seals from list under the
// key keyText spells, and that key as bootstrap.key.
func keyFileFolder(t *testing.T, list recordList, keyText string) string {
	t.Helper()
	folder := t.TempDir()
	writeOracleFile(t, filepath.Join(folder, FileName), list, keyText)
	writeKeyFile(t, folder, keyText+"\n")
	return folder
}

// oracleWrite is the file the oracle seals from list under the key keyText spells.
func oracleWrite(t *testing.T, list recordList, keyText string) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), FileName)
	writeOracleFile(t, path, list, keyText)
	return sampleBytesAt(t, path)
}

// writeOracleFile has the oracle's program seal list under the key keyText spells into path.
func writeOracleFile(t *testing.T, path string, list recordList, keyText string) {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "oracle.key")
	if err := os.WriteFile(keyPath, []byte(keyText+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	write := exec.CommandContext(t.Context(), oracleProgram, "write", keyPath, "-", path)
	write.Stdin = strings.NewReader(list.text())
	if out, err := write.CombinedOutput(); err != nil {
		t.Fatalf("the oracle's write: %v\n%s\nthe list:\n%s", err, out, list.text())
	}
}

func writeKeyFile(t *testing.T, folder, text string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(folder, KeyFileName), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeSwarmSecret puts text at the Swarm secret's path until the row ends.
func writeSwarmSecret(t *testing.T, text string) {
	t.Helper()
	if err := os.MkdirAll(swarmFolder, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(SwarmSecretPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeSwarmSecret(t) })
}

func removeSwarmSecret(t *testing.T) {
	t.Helper()
	if err := os.RemoveAll(swarmFolder); err != nil {
		t.Fatal(err)
	}
}

// copySample copies a kept sample into folder as bootstrap.hadv.
func copySample(t *testing.T, folder, sample string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(folder, FileName), sampleBytes(t, sample+".hadv"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func sampleBytes(t *testing.T, name string) []byte {
	t.Helper()
	return sampleBytesAt(t, filepath.Join(samples, name))
}

func sampleBytesAt(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// linkOutFolder is a bootstrap folder in which name is a symbolic link to a file outside it
// holding data.
func linkOutFolder(t *testing.T, name string, data []byte) string {
	t.Helper()
	outside := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(outside, data, 0o600); err != nil {
		t.Fatal(err)
	}
	folder := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(folder, name)); err != nil {
		t.Fatal(err)
	}
	return folder
}

// lock sets path to mode 000 until the row ends, then back, so the folder can be removed.
func lock(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(path, info.Mode().Perm()); err != nil {
			t.Error(err)
		}
	})
}

// wantPermission fails unless the OS refused for lack of permission.
func wantPermission(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("got %v, want the OS's permission denied beneath it", err)
	}
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(key, make([]byte, KeySize)) {
		t.Fatal("crypto/rand gave a key of zeros")
	}
	return key
}

var inContainer = flag.Bool("bootstrap.container", false, "the rows run inside TestOpenLinuxRowsInContainer's container")

// requireContainer skips a test that runs only inside TestOpenLinuxRowsInContainer, which
// runs it there; outside, it is not a row.
func requireContainer(t *testing.T) {
	t.Helper()
	if !*inContainer {
		t.Skip("runs inside TestOpenLinuxRowsInContainer")
	}
}

// wantOpened fails unless open gave a handle with want's fields, holder and no sealed key, the
// form of key holders 4 and 5; it releases the handle.
func wantOpened(t *testing.T, file File, err error, want Fields, holder KeyHolder) {
	t.Helper()
	if err != nil {
		t.Fatalf("got %v, want a handle", err)
	}
	if file == nil {
		t.Fatal("got no handle and no error")
	}
	defer file.Release()
	got := file.Fields()
	defer got.Zero()
	sameFields(t, got, want)
	if file.KeyHolder() != holder {
		t.Errorf("got key holder %d, want %d", file.KeyHolder(), holder)
	}
	if sealed := file.SealedKey(); len(sealed) != 0 {
		t.Errorf("got a sealed key of %d bytes, want none", len(sealed))
	}
}

// sameFields fails unless got and want hold the same fields; vault keys in any order.
func sameFields(t *testing.T, got, want Fields) {
	t.Helper()
	if got.Server != want.Server {
		t.Errorf("Server: got %d, want %d", got.Server, want.Server)
	}
	if got.Connection != want.Connection {
		t.Errorf("Connection: got %q, want %q", got.Connection, want.Connection)
	}
	if got.AccountName != want.AccountName {
		t.Errorf("AccountName: got %q, want %q", got.AccountName, want.AccountName)
	}
	for _, field := range []struct {
		name      string
		got, want []byte
	}{
		{"AccountPassword", got.AccountPassword, want.AccountPassword},
		{"ReceivingKey", got.ReceivingKey, want.ReceivingKey},
		{"SigningKey", got.SigningKey, want.SigningKey},
	} {
		if !bytes.Equal(field.got, field.want) {
			t.Errorf("%s: got % x, want % x", field.name, field.got, field.want)
		}
	}
	if len(got.VaultKeys) != len(want.VaultKeys) {
		t.Fatalf("VaultKeys: got %d, want %d", len(got.VaultKeys), len(want.VaultKeys))
	}
	for _, wanted := range want.VaultKeys {
		found := false
		for _, vaultKey := range got.VaultKeys {
			found = found || vaultKey == wanted
		}
		if !found {
			t.Errorf("VaultKeys: version %d with its key is missing", wanted.Version)
		}
	}
}

// sampleList is the record list of a kept sample, as the oracle prints it.
func sampleList(t *testing.T, sample string) recordList {
	t.Helper()
	text, err := os.ReadFile(filepath.Join(samples, sample+".records"))
	if err != nil {
		t.Fatal(err)
	}
	return listOf(string(text))
}

func (list recordList) text() string { return strings.Join(list, "\n") + "\n" }

// with is the list with lines added at its end.
func (list recordList) with(lines ...string) recordList {
	return append(append(recordList{}, list...), lines...)
}

// replacing is the list with its first line that starts with prefix replaced by line.
func (list recordList) replacing(t *testing.T, prefix, line string) recordList {
	t.Helper()
	changed := append(recordList{}, list...)
	for i, old := range changed {
		if strings.HasPrefix(old, prefix) {
			changed[i] = line
			return changed
		}
	}
	t.Fatalf("no line starts with %q", prefix)
	return nil
}

// recordOf is the value of the record named name in list, by its data.
func (list recordList) recordOf(t *testing.T, name string) string {
	t.Helper()
	prefix := `record "` + name + `" `
	for _, line := range list {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	t.Fatalf("no record %q", name)
	return ""
}

// fieldsOf is the known fields list's records hold, as open gives them.
func fieldsOf(t *testing.T, list recordList) Fields {
	t.Helper()
	records, err := list.records()
	if err != nil {
		t.Fatal(err)
	}
	var fields Fields
	for _, rec := range records {
		switch name := rec.name; {
		case name == FieldServer:
			fields.Server = board.ServerID(binary.BigEndian.Uint32(rec.data))
		case name == FieldConnection:
			fields.Connection = string(rec.data)
		case name == FieldAccountName:
			fields.AccountName = string(rec.data)
		case name == FieldAccountPassword:
			fields.AccountPassword = rec.data
		case name == FieldReceivingKey:
			fields.ReceivingKey = rec.data
		case name == FieldSigningKey:
			fields.SigningKey = rec.data
		case strings.HasPrefix(name, FieldVaultKeyPrefix):
			version, err := strconv.ParseUint(strings.TrimPrefix(name, FieldVaultKeyPrefix), 10, 32)
			if err != nil {
				t.Fatalf("a sample's vault key version: %v", err)
			}
			var key Key256
			copy(key[:], rec.data)
			fields.VaultKeys = append(fields.VaultKeys, VaultKey{Version: uint32(version), Key: key})
		}
	}
	return fields
}

// keyText is a key as the key file and the Swarm secret hold it: 44 characters of base64.
func keyText(key []byte) string { return base64.StdEncoding.EncodeToString(key) }

// testKeyText is the kept test key's 44 characters, without the newline the file ends with.
func testKeyText(t *testing.T) string {
	t.Helper()
	text, err := os.ReadFile(filepath.Join(samples, "test.key"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(text))
}
