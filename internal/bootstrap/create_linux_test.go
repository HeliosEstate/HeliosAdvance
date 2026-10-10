// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The Linux rows of issue #149, run inside TestCreateLinuxRowsInContainer's container: as root,
// since the Swarm secret's path is root's, then as the account nobody, whom a folder at mode 000
// refuses. The oracle's program in the image reads every file create writes, under the test key,
// and writes every file the write path is given. A failing step of the write path is made on a
// real folder by what stands at bootstrap.hadv.new or bootstrap.hadv before create runs; the
// step that opens the new file is reached through the write path itself, since every file
// create seals opens.
package bootstrap

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// The lines only the Linux rows prove, word for word.
const (
	lineLayout           = "The bootstrap package shall write the bootstrap file only in the layout the package comment gives for format version 1."
	lineNonce            = "The bootstrap package shall write a new random nonce each time it writes a bootstrap file."
	lineSeal             = "The bootstrap package shall seal the records with AES-256-GCM under the bootstrap key, with the header and the nonce as the authenticated data."
	lineTempAndRename    = "When create or save writes a bootstrap file, the bootstrap package shall write it as bootstrap.hadv.new and rename it over bootstrap.hadv through the folder's os.Root."
	lineOpenBeforeRename = "The bootstrap package shall open bootstrap.hadv.new under the bootstrap key before it renames it."
	lineWriteFails       = "If writing, flushing, opening or renaming bootstrap.hadv.new fails, then the bootstrap package shall delete bootstrap.hadv.new and return ErrWrite."
	lineCreateNotFound   = "If the bootstrap folder is not there, then create shall return ErrNotFound."
	lineExists           = "If create is called with overwrite false and bootstrap.hadv is present, then create shall return ErrExists before it makes a bootstrap key or writes a file."
)

// The rows more than one of create's lines shares: one name for each case.
const (
	rowKeyHolderFour = "key holder 4"
	rowKeyHolderFive = "key holder 5"
	rowTwoVaultKeys  = "two vault keys"
	rowTempLinksOut  = "bootstrap.hadv.new a symbolic link out of the folder"
	rowOtherKey      = "a file sealed under another key"
)

// The character devices a row puts at bootstrap.hadv.new, as Linux numbers them: major 1, minor
// 7 is /dev/full, which refuses every write, and minor 3 is /dev/null, which takes every write
// and cannot be flushed. Linux reads a number below 256 in each as major times 256 plus minor.
const (
	deviceFull = 1<<8 | 7
	deviceNull = 1<<8 | 3
)

// TestCreateLinuxAsRoot is every Linux row of create and the write path but those that need an
// account refused by permissions. The rows that use the Swarm secret share its one fixed path,
// so they run one after another; the rest run in parallel.
//
//nolint:paralleltest // the Swarm secret's path is fixed: its rows cannot overlap
func TestCreateLinuxAsRoot(t *testing.T) {
	requireContainer(t)
	if os.Getuid() != 0 {
		t.Fatalf("these rows run as root; running as uid %d", os.Getuid())
	}
	removeSwarmSecret(t)
	good := testKeyText(t)
	key := keyOf(t, good)
	base := sampleList(t, sampleKeyFile)
	// keyFolder is an empty bootstrap folder holding the test key as bootstrap.key.
	keyFolder := func(t *testing.T) string {
		t.Helper()
		folder := t.TempDir()
		writeKeyFile(t, folder, good+"\n")
		return folder
	}
	// oldFolder is keyFolder with a kept sample as bootstrap.hadv, the file a failed write
	// leaves standing.
	oldFolder := func(t *testing.T) string {
		t.Helper()
		folder := keyFolder(t)
		copySample(t, folder, sampleKeyFile)
		return folder
	}

	t.Run(lineKeyHolderMissing, func(t *testing.T) {
		for _, holder := range []KeyHolder{WindowsKeyStore, 0, 6, 255} {
			t.Run("create with key holder "+strconv.Itoa(int(holder)), func(t *testing.T) {
				t.Parallel()
				wantCode(t, create(t, keyFolder(t), holder, rowFields(), false), ErrKey)
			})
		}
		t.Run("open a file whose header names key holder 1", func(t *testing.T) {
			t.Parallel()
			folder := keyFolder(t)
			copySample(t, folder, "keyholder-1")
			file, err := open(t, folder)
			wantRefused(t, file, err, ErrKey)
		})
		t.Run("create with key holder 4 over a file whose header names key holder 1", func(t *testing.T) {
			t.Parallel()
			folder := keyFolder(t)
			copySample(t, folder, "keyholder-1")
			wantCreated(t, folder, KeyFile, rowFields(), true, good)
		})
		t.Run("create with key holder 4", func(t *testing.T) {
			t.Parallel()
			wantCreated(t, keyFolder(t), KeyFile, rowFields(), false, good)
		})
		t.Run("create with key holder 5", func(t *testing.T) {
			writeSwarmSecret(t, good+"\n")
			wantCreated(t, t.TempDir(), SwarmSecret, rowFields(), false, good)
		})
	})

	t.Run(lineLayout, func(t *testing.T) {
		for _, row := range []struct {
			name   string
			holder KeyHolder
			fields Fields
		}{
			{rowKeyHolderFour, KeyFile, rowFields()},
			{rowKeyHolderFive, SwarmSecret, rowFields()},
			{rowTwoVaultKeys, KeyFile, twoVaultKeyFields()},
		} {
			t.Run(row.name, func(t *testing.T) {
				folder := keyFolder(t)
				if row.holder == SwarmSecret {
					folder = t.TempDir()
					writeSwarmSecret(t, good+"\n")
				}
				list := wantCreated(t, folder, row.holder, row.fields, false, good)
				for _, line := range []string{`magic "HADVBOOT"`, "version 1", "holder " + strconv.Itoa(int(row.holder)), `sealed ""`} {
					if !slices.Contains(list, line) {
						t.Errorf("the oracle read no %q in the header:\n%s", line, list.text())
					}
				}
				records, err := list.records()
				if err != nil {
					t.Fatal(err)
				}
				sameRecords(t, records, recordsOf(row.fields))
			})
		}
	})

	t.Run(lineNonce, func(t *testing.T) {
		t.Run("three creates in one folder and one in each of two others write five nonces", func(t *testing.T) {
			t.Parallel()
			folders := []string{keyFolder(t), keyFolder(t), keyFolder(t)}
			var nonces [][]byte
			for i, folder := range []string{folders[0], folders[0], folders[0], folders[1], folders[2]} {
				if err := create(t, folder, KeyFile, rowFields(), i > 0); err != nil {
					t.Fatalf("create %d: got %v, want the file", i+1, err)
				}
				nonce := nonceOf(t, sampleBytesAt(t, filepath.Join(folder, FileName)))
				for j, earlier := range nonces {
					if bytes.Equal(nonce, earlier) {
						t.Fatalf("create %d wrote create %d's nonce % x", i+1, j+1, nonce)
					}
				}
				nonces = append(nonces, nonce)
			}
		})
	})

	t.Run(lineSeal, func(t *testing.T) {
		for _, row := range []struct {
			name   string
			holder KeyHolder
			fields Fields
		}{
			{rowKeyHolderFour, KeyFile, rowFields()},
			{rowKeyHolderFive, SwarmSecret, rowFields()},
			{rowTwoVaultKeys, KeyFile, twoVaultKeyFields()},
		} {
			t.Run(row.name+": the oracle reads the file under the test key", func(t *testing.T) {
				folder := keyFolder(t)
				if row.holder == SwarmSecret {
					folder = t.TempDir()
					writeSwarmSecret(t, good+"\n")
				}
				wantCreated(t, folder, row.holder, row.fields, false, good)
			})
		}
	})

	t.Run(lineTempAndRename, func(t *testing.T) {
		t.Run("no bootstrap.hadv.new is left after create", func(t *testing.T) {
			t.Parallel()
			folder := keyFolder(t)
			wantCreated(t, folder, KeyFile, rowFields(), false, good)
			wantNoTempFile(t, folder)
		})
		t.Run("a leftover bootstrap.hadv.new longer than the new file is truncated", func(t *testing.T) {
			t.Parallel()
			folder := keyFolder(t)
			writeFolderFile(t, folder, TempFileName, bytes.Repeat([]byte{0xAA}, 70000))
			wantCreated(t, folder, KeyFile, rowFields(), false, good)
			wantNoTempFile(t, folder)
		})
		t.Run("with overwrite true, a hard link to the old bootstrap.hadv keeps the old file", func(t *testing.T) {
			t.Parallel()
			folder := oldFolder(t)
			if err := os.Link(filepath.Join(folder, FileName), filepath.Join(folder, "old.hadv")); err != nil {
				t.Fatal(err)
			}
			wantCreated(t, folder, KeyFile, rowFields(), true, good)
			wantSame(t, filepath.Join(folder, "old.hadv"), sampleBytes(t, sampleKeyFile+".hadv"))
		})
		t.Run(rowTempLinksOut+": the file outside is untouched", func(t *testing.T) {
			t.Parallel()
			folder := keyFolder(t)
			outside := tempLinksOut(t, folder)
			wantCode(t, create(t, folder, KeyFile, rowFields(), false), ErrWrite)
			wantSame(t, outside, []byte("outside the folder"))
		})
	})

	t.Run(lineOpenBeforeRename, func(t *testing.T) {
		for _, row := range []struct {
			name string
			file func(t *testing.T) []byte
		}{
			{rowOtherKey, func(t *testing.T) []byte { t.Helper(); return oracleWrite(t, base, keyText(randomKey(t))) }},
			{"a file with a wrong magic", func(t *testing.T) []byte {
				t.Helper()
				return oracleWrite(t, base.replacing(t, "magic ", `magic "HADVBOOX"`), good)
			}},
			{"a file whose records break the record layout", func(t *testing.T) []byte {
				t.Helper()
				return oracleWrite(t, base.with(`record "" "x"`), good)
			}},
		} {
			t.Run(row.name+" is not put in place", func(t *testing.T) {
				t.Parallel()
				folder := oldFolder(t)
				wantCode(t, writeThrough(t, folder, key, row.file(t)), ErrWrite)
				wantSame(t, filepath.Join(folder, FileName), sampleBytes(t, sampleKeyFile+".hadv"))
				wantNoTempFile(t, folder)
			})
		}
		t.Run("a file that opens under the bootstrap key is put in place", func(t *testing.T) {
			t.Parallel()
			folder := oldFolder(t)
			file := oracleWrite(t, base, good)
			if err := writeThrough(t, folder, key, file); err != nil {
				t.Fatalf("got %v, want the file in place", err)
			}
			wantSame(t, filepath.Join(folder, FileName), file)
			wantNoTempFile(t, folder)
		})
	})

	t.Run(lineWriteFails, func(t *testing.T) {
		old := sampleBytes(t, sampleKeyFile+".hadv")
		for _, row := range []struct {
			name  string
			stage func(t *testing.T, folder string)
		}{
			{"writing fails: bootstrap.hadv.new a device that refuses every write", func(t *testing.T, folder string) {
				t.Helper()
				makeDevice(t, filepath.Join(folder, TempFileName), deviceFull)
			}},
			{"writing fails: bootstrap.hadv.new an empty folder", func(t *testing.T, folder string) {
				t.Helper()
				if err := os.Mkdir(filepath.Join(folder, TempFileName), 0o700); err != nil {
					t.Fatal(err)
				}
			}},
			{"writing fails: " + rowTempLinksOut, func(t *testing.T, folder string) {
				t.Helper()
				tempLinksOut(t, folder)
			}},
			{"flushing fails: bootstrap.hadv.new a device that takes every write and cannot be flushed", func(t *testing.T, folder string) {
				t.Helper()
				makeDevice(t, filepath.Join(folder, TempFileName), deviceNull)
			}},
		} {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				folder := oldFolder(t)
				row.stage(t, folder)
				wantCode(t, create(t, folder, KeyFile, rowFields(), true), ErrWrite)
				wantNoTempFile(t, folder)
				wantSame(t, filepath.Join(folder, FileName), old)
			})
		}
		t.Run("opening fails: "+rowOtherKey, func(t *testing.T) {
			t.Parallel()
			folder := oldFolder(t)
			wantCode(t, writeThrough(t, folder, key, oracleWrite(t, base, keyText(randomKey(t)))), ErrWrite)
			wantNoTempFile(t, folder)
			wantSame(t, filepath.Join(folder, FileName), old)
		})
		t.Run("renaming fails: bootstrap.hadv a folder", func(t *testing.T) {
			t.Parallel()
			folder := keyFolder(t)
			if err := os.Mkdir(filepath.Join(folder, FileName), 0o700); err != nil {
				t.Fatal(err)
			}
			wantCode(t, create(t, folder, KeyFile, rowFields(), true), ErrWrite)
			wantNoTempFile(t, folder)
			if info, err := os.Stat(filepath.Join(folder, FileName)); err != nil || !info.IsDir() {
				t.Fatalf("bootstrap.hadv: %v, want the folder still there", err)
			}
		})
	})

	t.Run(lineCreateNotFound, func(t *testing.T) {
		t.Run(rowFolderMissing, func(t *testing.T) {
			t.Parallel()
			wantCode(t, create(t, filepath.Join(t.TempDir(), "missing"), KeyFile, rowFields(), false), ErrNotFound)
		})
	})

	t.Run(lineFolderUnreadable, func(t *testing.T) {
		t.Run("create: "+rowFileForFolder, func(t *testing.T) {
			t.Parallel()
			err := create(t, fileForFolder(t), KeyFile, rowFields(), false)
			wantCode(t, err, ErrUnreadable)
			wantCause(t, err)
		})
	})

	t.Run(linePlace, func(t *testing.T) {
		for _, row := range []struct {
			name   string
			folder func(t *testing.T) string
			code   error
		}{
			{rowFolderMissing, func(t *testing.T) string { t.Helper(); return filepath.Join(t.TempDir(), "missing") }, ErrNotFound},
			{rowFileForFolder, fileForFolder, ErrUnreadable},
		} {
			t.Run("create: "+row.name, func(t *testing.T) {
				t.Parallel()
				err := create(t, row.folder(t), KeyFile, rowFields(), false)
				wantCode(t, err, row.code)
				wantPlace(t, err, PlaceFolder)
			})
		}
	})

	t.Run(lineExists, func(t *testing.T) {
		for _, row := range []struct {
			name  string
			stage func(t *testing.T) string
		}{
			{"a kept sample as bootstrap.hadv", oldFolder},
			{"a bootstrap.hadv that is no bootstrap file", func(t *testing.T) string {
				t.Helper()
				folder := keyFolder(t)
				writeFolderFile(t, folder, FileName, []byte("not a bootstrap file"))
				return folder
			}},
			{"bootstrap.hadv beside no bootstrap.key", func(t *testing.T) string {
				t.Helper()
				folder := t.TempDir()
				copySample(t, folder, sampleKeyFile)
				return folder
			}},
		} {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				folder := row.stage(t)
				before := sampleBytesAt(t, filepath.Join(folder, FileName))
				wantCode(t, create(t, folder, KeyFile, rowFields(), false), ErrExists)
				wantSame(t, filepath.Join(folder, FileName), before)
				wantNoTempFile(t, folder)
			})
		}
		t.Run("a leftover bootstrap.hadv.new beside bootstrap.hadv is left as it was", func(t *testing.T) {
			t.Parallel()
			folder := oldFolder(t)
			writeFolderFile(t, folder, TempFileName, []byte("a leftover"))
			wantCode(t, create(t, folder, KeyFile, rowFields(), false), ErrExists)
			wantSame(t, filepath.Join(folder, TempFileName), []byte("a leftover"))
		})
		t.Run("key holder 5 with no Swarm secret", func(t *testing.T) {
			folder := t.TempDir()
			copySample(t, folder, sampleSwarmSecret)
			wantCode(t, create(t, folder, SwarmSecret, rowFields(), false), ErrExists)
			wantSame(t, filepath.Join(folder, FileName), sampleBytes(t, sampleSwarmSecret+".hadv"))
		})
		t.Run("a leftover bootstrap.hadv.new alone is no bootstrap.hadv: create writes the file", func(t *testing.T) {
			t.Parallel()
			folder := keyFolder(t)
			writeFolderFile(t, folder, TempFileName, []byte("a leftover"))
			wantCreated(t, folder, KeyFile, rowFields(), false, good)
		})
	})
}

// TestCreateLinuxAsNobody is create's rows that need an account the folder's mode refuses, run
// as nobody, since root reads past any mode.
func TestCreateLinuxAsNobody(t *testing.T) {
	t.Parallel()
	requireContainer(t)
	if os.Getuid() == 0 {
		t.Fatal("these rows run as an account other than root")
	}
	good := testKeyText(t)
	lockedFolder := func(t *testing.T) string {
		t.Helper()
		folder := t.TempDir()
		writeKeyFile(t, folder, good+"\n")
		lock(t, folder)
		return folder
	}
	t.Run(lineFolderUnreadable, func(t *testing.T) {
		t.Parallel()
		t.Run("create: "+rowFolderLocked, func(t *testing.T) {
			t.Parallel()
			err := create(t, lockedFolder(t), KeyFile, rowFields(), false)
			wantCode(t, err, ErrUnreadable)
			wantCause(t, err)
			wantPermission(t, err)
		})
	})
	t.Run(linePlace, func(t *testing.T) {
		t.Parallel()
		t.Run("create: "+rowFolderLocked, func(t *testing.T) {
			t.Parallel()
			err := create(t, lockedFolder(t), KeyFile, rowFields(), false)
			wantPlace(t, err, PlaceFolder)
		})
	})
}

// wantCreated fails unless create writes a file in folder that the oracle reads under the key
// keyText spells; it gives the oracle's record list of it.
func wantCreated(t *testing.T, folder string, holder KeyHolder, fields Fields, overwrite bool, keyText string) recordList {
	t.Helper()
	if err := create(t, folder, holder, fields, overwrite); err != nil {
		t.Fatalf("got %v, want the file", err)
	}
	return oracleRead(t, filepath.Join(folder, FileName), keyText)
}

// oracleRead is the record list the oracle's program reads from the file at path under the key
// keyText spells; the row fails unless the oracle reads it whole and every field keeps its rule.
func oracleRead(t *testing.T, path, keyText string) recordList {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "oracle.key")
	if err := os.WriteFile(keyPath, []byte(keyText+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	read := exec.CommandContext(t.Context(), oracleProgram, "read", keyPath, path)
	read.Stdout = &stdout
	read.Stderr = &stderr
	if err := read.Run(); err != nil {
		t.Fatalf("the oracle's read of create's file: %v\n%s", err, stderr.String())
	}
	return listOf(stdout.String())
}

// recordsOf is the records a file holding fields holds, in the forms the package comment gives.
func recordsOf(fields Fields) []record {
	records := []record{
		{FieldServer, binary.BigEndian.AppendUint32(nil, uint32(fields.Server))},
		{FieldConnection, []byte(fields.Connection)},
		{FieldAccountName, []byte(fields.AccountName)},
		{FieldAccountPassword, fields.AccountPassword},
	}
	for _, vaultKey := range fields.VaultKeys {
		records = append(records, record{FieldVaultKeyPrefix + strconv.FormatUint(uint64(vaultKey.Version), 10), vaultKey.Key[:]})
	}
	return append(records, record{FieldReceivingKey, fields.ReceivingKey}, record{FieldSigningKey, fields.SigningKey})
}

// sameRecords fails unless got and want hold the same records, in any order: no line fixes the
// order of the known records.
func sameRecords(t *testing.T, got, want []record) {
	t.Helper()
	byName := func(first, second record) int { return strings.Compare(first.name, second.name) }
	got, want = slices.SortedFunc(slices.Values(got), byName), slices.SortedFunc(slices.Values(want), byName)
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].name != want[i].name || !bytes.Equal(got[i].data, want[i].data) {
			t.Errorf("got the record %q: % x, want %q: % x", got[i].name, got[i].data, want[i].name, want[i].data)
		}
	}
}

// twoVaultKeyFields is rowFields with two vault keys, as during a vault-key change, numbered so
// that one version's name has two digits.
func twoVaultKeyFields() Fields {
	fields := rowFields()
	fields.VaultKeys = []VaultKey{{Version: 9, Key: rowKey(9)}, {Version: 10, Key: rowKey(10)}}
	return fields
}

// nonceOf is the nonce of a file with no sealed key, the form of key holders 4 and 5.
func nonceOf(t *testing.T, file []byte) []byte {
	t.Helper()
	if len(file) < HeaderStartSize+NonceSize {
		t.Fatalf("a file of %d bytes has no nonce", len(file))
	}
	return file[HeaderStartSize : HeaderStartSize+NonceSize]
}

// keyOf is the key the 44 characters of keyText spell.
func keyOf(t *testing.T, keyText string) Key256 {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(keyText)
	if err != nil || len(decoded) != KeySize {
		t.Fatalf("the test key %q: %v", keyText, err)
	}
	return Key256(decoded)
}

// writeThrough gives file to the write path in folder, through the folder's root, under key.
func writeThrough(t *testing.T, folder string, key Key256, file []byte) error {
	t.Helper()
	root, err := os.OpenRoot(folder)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	return writeFile(root, key, file)
}

// tempLinksOut makes bootstrap.hadv.new in folder a symbolic link to a file outside it, and
// gives the outside file's path.
func tempLinksOut(t *testing.T, folder string) string {
	t.Helper()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside the folder"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(folder, TempFileName)); err != nil {
		t.Fatal(err)
	}
	return outside
}

// makeDevice makes a character device numbered device at path.
func makeDevice(t *testing.T, path string, device int) {
	t.Helper()
	if err := syscall.Mknod(path, syscall.S_IFCHR|0o600, device); err != nil {
		t.Fatalf("making the device: %v", err)
	}
}

func writeFolderFile(t *testing.T, folder, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(folder, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// wantNoTempFile fails unless nothing named bootstrap.hadv.new is in folder.
func wantNoTempFile(t *testing.T, folder string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(folder, TempFileName)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("bootstrap.hadv.new: %v, want it gone", err)
	}
}

// wantSame fails unless the file at path holds want.
func wantSame(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: got %d bytes, want the %d it held", filepath.Base(path), len(got), len(want))
	}
}
