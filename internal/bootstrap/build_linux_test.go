// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"encoding/base64"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// systemdUnder is set by TestBuildLinuxRowsInContainer to the systemd under the rows it runs
// in a systemd image; it is empty where there is no systemd.
var systemdUnder = flag.String("bootstrap.systemd", "", "the systemd under the Build rows: set by TestBuildLinuxRowsInContainer")

// oracleProgram is the bootstrap file oracle's program, copied out of its image and mounted
// beside the test binary.
const oracleProgram = "/t/bootstrap-file"

// buildFolder makes a bootstrap folder on parent's file system, as hadv-setup makes it, with
// the key file holding contents when contents is not empty.
func buildFolder(t *testing.T, parent, contents string) string {
	t.Helper()
	folder, err := os.MkdirTemp(parent, "build-") //nolint:usetesting // on the file system the row names; t.TempDir is on overlayfs
	if err != nil {
		t.Fatal(err)
	}
	if contents != "" {
		writeItem(t, filepath.Join(folder, nameKeyFile), contents, serviceAccount, modeKeyFile)
	}
	return folder
}

// emptyContainerFolder empties the container's fixed folder and takes away the Swarm secret,
// then puts in the key file and the secret the row gives, each when it is not empty.
func emptyContainerFolder(t *testing.T, keyFile, secret string) {
	t.Helper()
	entries, err := os.ReadDir(containerFolder)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(containerFolder, entry.Name())); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.RemoveAll(swarmSecret); err != nil {
		t.Fatal(err)
	}
	if keyFile != "" {
		writeItem(t, filepath.Join(containerFolder, nameKeyFile), keyFile, serviceAccount, modeKeyFile)
	}
	if secret != "" {
		if err := os.MkdirAll(filepath.Dir(swarmSecret), 0o755); err != nil { //nolint:gosec // /run/secrets, as Docker makes it
			t.Fatal(err)
		}
		writeItem(t, swarmSecret, secret, serviceAccount, modeKeyFile)
	}
}

// wantBuilt fails the row unless Build returned the mode and the oracle reads the bootstrap
// file in the folder under the key, holding the fields.
func wantBuilt(t *testing.T, mode KeyMode, err error, wantMode KeyMode, folder string, key []byte, fields Fields) {
	t.Helper()
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	if mode != wantMode {
		t.Errorf("returned mode %d, want %d", mode, wantMode)
	}
	keyPath := filepath.Join(t.TempDir(), "oracle.key")
	if err := os.WriteFile(keyPath, []byte(keyText(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(t.Context(), oracleProgram, "read", keyPath, filepath.Join(folder, nameFile)).Output()
	if err != nil {
		t.Fatalf("the oracle did not read the bootstrap file under the row's key: %v", err)
	}
	sameFields(t, fieldsOf(t, parseRecords(t, string(out))), fields)
}

// wantFieldMalformed fails the row unless err is a FieldMalformed naming the field.
func wantFieldMalformed(t *testing.T, err error, field string) {
	t.Helper()
	refusal := refusalOf(err)
	if refusal == nil || refusal.Cause != FieldMalformed {
		t.Fatalf("got %v, want a FieldMalformed refusal", err)
	}
	if refusal.Field != field {
		t.Errorf("named field %q, want %q", refusal.Field, field)
	}
}

// TestBuildLinuxNotElevated runs as the account nobody, through setpriv: a folder that
// breaks no rule, a good key file, and only the rights missing.
func TestBuildLinuxNotElevated(t *testing.T) {
	t.Parallel()
	requireContainer(t)
	t.Run(lineBuildNotElevated, func(t *testing.T) {
		t.Parallel()
		folder, err := os.MkdirTemp(volume, "own-") //nolint:usetesting // on the ext4 volume; t.TempDir is on overlayfs
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(folder, nameKeyFile), []byte(keyText(rowKey(1))), modeKeyFile); err != nil {
			t.Fatal(err)
		}
		_, err = New().Build(t.Context(), folder, rowFields(), FirstSetup, serviceAccount, FromKeyFile)
		wantRefusal(t, err, NotElevated)
	})
}

// TestBuildLinuxAsRoot is every Linux row with no systemd but NotElevated. The rows run one
// after another: those under FromContainer share the container's one fixed folder and Swarm
// secret.
//
//nolint:paralleltest // the rows under FromContainer share the container's fixed folder
func TestBuildLinuxAsRoot(t *testing.T) {
	requireContainer(t)
	if os.Getuid() != 0 {
		t.Fatalf("the Linux rows run as root; running as uid %d", os.Getuid())
	}
	if *systemdUnder != "" {
		t.Fatalf("these rows run with no systemd; -bootstrap.systemd is %q", *systemdUnder)
	}

	t.Run(lineBuildInUse, func(t *testing.T) {
		t.Run("the lock held every usual way", func(t *testing.T) {
			folder := buildFolder(t, volume, keyText(rowKey(1)))
			lock := filepath.Join(folder, nameLock)
			writeItem(t, lock, "", serviceAccount, modeFile)
			release := holdLock(t, lock)
			defer release()
			_, err := build(t, folder, rowFields(), FirstSetup, FromKeyFile)
			wantRefusal(t, err, InUse)
		})
		t.Run("let through: the lock file there, not held", func(t *testing.T) {
			folder := buildFolder(t, volume, keyText(rowKey(2)))
			writeItem(t, filepath.Join(folder, nameLock), "", serviceAccount, modeFile)
			mode, err := build(t, folder, rowFields(), FirstSetup, FromKeyFile)
			wantBuilt(t, mode, err, ModeKeyFile, folder, rowKey(2), rowFields())
		})
	})

	t.Run(lineBuildFolder, func(t *testing.T) {
		good := buildFolder(t, volume, keyText(rowKey(3)))
		link := filepath.Join(volume, "link-"+filepath.Base(good))
		if err := os.Symlink(good, link); err != nil {
			t.Fatal(err)
		}
		for _, row := range []struct {
			name   string
			folder string
			rule   FolderRule
		}{
			{rowRelativePath, relativeFolder, NotAbsolute},
			{rowFolderLink, link, FolderLink},
			{rowTmpfs, buildFolder(t, tmpfsMount, keyText(rowKey(3))), FileSystem},
			{rowOverlayfs, buildFolder(t, overlayRoot, keyText(rowKey(3))), FileSystem},
		} {
			t.Run(row.name, func(t *testing.T) {
				_, err := build(t, row.folder, rowFields(), FirstSetup, FromKeyFile)
				wantFolderRefused(t, err, row.rule)
			})
		}
		t.Run("let through: a folder on ext4", func(t *testing.T) {
			mode, err := build(t, good, rowFields(), FirstSetup, FromKeyFile)
			wantBuilt(t, mode, err, ModeKeyFile, good, rowKey(3), rowFields())
		})
	})

	t.Run(lineBuildField, func(t *testing.T) {
		for _, row := range []struct {
			name   string
			change func(fields *Fields)
			field  string
		}{
			{"a server ID of 0", func(fields *Fields) { fields.Server = 0 }, FieldServer},
			{"an empty connection", func(fields *Fields) { fields.Connection = "" }, FieldConnection},
			{"an empty account name", func(fields *Fields) { fields.AccountName = "" }, FieldAccountName},
			{"an empty receiving key", func(fields *Fields) { fields.ReceivingKey = nil }, FieldReceivingKey},
			{"an empty signing key", func(fields *Fields) { fields.SigningKey = nil }, FieldSigningKey},
			{"no vault key", func(fields *Fields) { fields.VaultKeys = nil }, FieldVaultKeyPrefix},
			{"three vault keys", func(fields *Fields) {
				fields.VaultKeys = []VaultKey{{3, rowKey(3)}, {4, rowKey(4)}, {5, rowKey(5)}}
			}, FieldVaultKeyPrefix},
			{"two vault keys of version 7", func(fields *Fields) {
				fields.VaultKeys = []VaultKey{{7, rowKey(7)}, {7, rowKey(8)}}
			}, FieldVaultKeyPrefix + "7"},
			{"a vault key of version 0", func(fields *Fields) { fields.VaultKeys = []VaultKey{{0, rowKey(9)}} }, FieldVaultKeyPrefix + "0"},
			{"a vault key of 31 bytes", func(fields *Fields) { fields.VaultKeys = []VaultKey{{3, rowKey(3)[:31]}} }, FieldVaultKeyPrefix + "3"},
			{"a vault key of 33 bytes", func(fields *Fields) {
				fields.VaultKeys = []VaultKey{{3, append(rowKey(3), 3)}}
			}, FieldVaultKeyPrefix + "3"},
		} {
			t.Run(row.name, func(t *testing.T) {
				fields := rowFields()
				row.change(&fields)
				_, err := build(t, buildFolder(t, volume, keyText(rowKey(4))), fields, FirstSetup, FromKeyFile)
				wantFieldMalformed(t, err, row.field)
			})
		}
		for _, row := range []struct {
			name   string
			change func(fields *Fields)
		}{
			{"two vault keys, versions 3 and 4", func(fields *Fields) {
				fields.VaultKeys = []VaultKey{{3, rowKey(3)}, {4, rowKey(4)}}
			}},
			{"a vault key of version 4,294,967,295", func(fields *Fields) {
				fields.VaultKeys = []VaultKey{{4294967295, rowKey(5)}}
			}},
			{"an empty database password", func(fields *Fields) { fields.AccountPassword = nil }},
		} {
			t.Run("let through: "+row.name, func(t *testing.T) {
				fields := rowFields()
				row.change(&fields)
				folder := buildFolder(t, volume, keyText(rowKey(5)))
				mode, err := build(t, folder, fields, FirstSetup, FromKeyFile)
				wantBuilt(t, mode, err, ModeKeyFile, folder, rowKey(5), fields)
			})
		}
	})

	t.Run(lineBuildFileExists, func(t *testing.T) {
		withOldFile := func(t *testing.T, key []byte) string {
			t.Helper()
			folder := buildFolder(t, volume, keyText(key))
			writeItem(t, filepath.Join(folder, nameFile), "an old bootstrap file", serviceAccount, modeFile)
			return folder
		}
		for _, path := range []struct {
			name string
			path BuildPath
		}{{"FirstSetup", FirstSetup}, {"Joining", Joining}} {
			t.Run(path.name, func(t *testing.T) {
				_, err := build(t, withOldFile(t, rowKey(6)), rowFields(), path.path, FromKeyFile)
				wantRefusal(t, err, FileExists)
			})
		}
		for _, path := range []struct {
			name string
			path BuildPath
		}{{"JoiningAgain", JoiningAgain}, {"Restore", Restore}} {
			t.Run("let through, the old file replaced: "+path.name, func(t *testing.T) {
				folder := withOldFile(t, rowKey(7))
				mode, err := build(t, folder, rowFields(), path.path, FromKeyFile)
				wantBuilt(t, mode, err, ModeKeyFile, folder, rowKey(7), rowFields())
			})
		}
	})

	t.Run(lineBuildNoStore, func(t *testing.T) {
		t.Run("no systemd", func(t *testing.T) {
			_, err := build(t, buildFolder(t, volume, ""), rowFields(), FirstSetup, FromOSStore)
			wantRefusal(t, err, NoCredentialStore)
		})
	})

	t.Run(lineBuildKeyFile, func(t *testing.T) {
		folder := buildFolder(t, volume, keyText(rowKey(8)))
		mode, err := build(t, folder, rowFields(), FirstSetup, FromKeyFile)
		wantBuilt(t, mode, err, ModeKeyFile, folder, rowKey(8), rowFields())
	})

	t.Run(lineBuildContainer, func(t *testing.T) {
		t.Run("the Swarm secret", func(t *testing.T) {
			emptyContainerFolder(t, "", keyText(rowKey(9)))
			mode, err := build(t, containerFolder, rowFields(), FirstSetup, FromContainer)
			wantBuilt(t, mode, err, ModeContainer, containerFolder, rowKey(9), rowFields())
		})
		t.Run("the key file", func(t *testing.T) {
			emptyContainerFolder(t, keyText(rowKey(10)), "")
			mode, err := build(t, containerFolder, rowFields(), FirstSetup, FromContainer)
			wantBuilt(t, mode, err, ModeContainer, containerFolder, rowKey(10), rowFields())
		})
	})

	t.Run(lineBuildNoKeySource, func(t *testing.T) {
		emptyContainerFolder(t, "", "")
		_, err := build(t, containerFolder, rowFields(), FirstSetup, FromContainer)
		wantRefusal(t, err, NoKeySource)
	})

	t.Run(lineBuildBothKeySources, func(t *testing.T) {
		emptyContainerFolder(t, keyText(rowKey(11)), keyText(rowKey(12)))
		_, err := build(t, containerFolder, rowFields(), FirstSetup, FromContainer)
		wantRefusal(t, err, BothKeySources)
	})

	t.Run(lineBuildKeyNotFound, func(t *testing.T) {
		_, err := build(t, buildFolder(t, volume, ""), rowFields(), FirstSetup, FromKeyFile)
		wantRefusal(t, err, KeyNotFound)
	})

	t.Run(lineBuildLink, func(t *testing.T) {
		// The other name and the link's target are a good key on the same ext4 volume, so
		// that the link is the only thing wrong.
		elsewhere := func(t *testing.T) string {
			t.Helper()
			path := filepath.Join(buildFolder(t, volume, ""), "elsewhere.key")
			writeItem(t, path, keyText(rowKey(13)), serviceAccount, modeKeyFile)
			return path
		}
		t.Run("a symbolic link", func(t *testing.T) {
			folder := buildFolder(t, volume, "")
			if err := os.Symlink(elsewhere(t), filepath.Join(folder, nameKeyFile)); err != nil {
				t.Fatal(err)
			}
			_, err := build(t, folder, rowFields(), FirstSetup, FromKeyFile)
			wantRefusal(t, err, Link)
		})
		t.Run("a file with a second name", func(t *testing.T) {
			folder := buildFolder(t, volume, "")
			if err := os.Link(elsewhere(t), filepath.Join(folder, nameKeyFile)); err != nil {
				t.Fatal(err)
			}
			_, err := build(t, folder, rowFields(), FirstSetup, FromKeyFile)
			wantRefusal(t, err, Link)
		})
		t.Run("let through: a file with one name", func(t *testing.T) {
			folder := buildFolder(t, volume, keyText(rowKey(13)))
			mode, err := build(t, folder, rowFields(), FirstSetup, FromKeyFile)
			wantBuilt(t, mode, err, ModeKeyFile, folder, rowKey(13), rowFields())
		})
	})

	t.Run(lineBuildMalformed, func(t *testing.T) {
		good := base64.StdEncoding.EncodeToString(rowKey(14))
		zeros := base64.StdEncoding.EncodeToString(make([]byte, 32))
		// A key of all 0xFF bytes spells with "/", which the URL-safe alphabet spells "_".
		urlSafe := strings.ReplaceAll(base64.StdEncoding.EncodeToString(rowKey(0xFF)), "/", "_")
		for _, row := range []struct{ name, contents string }{
			{"43 characters", good[:43] + "\n"},
			{"45 characters", good + "A\n"},
			{"two trailing newlines", good + "\n\n"},
			{"a trailing carriage return and newline", good + "\r\n"},
			{"a leading space", " " + good + "\n"},
			{"the URL-safe alphabet", urlSafe + "\n"},
			{"the bits after the last byte not zero", zeros[:42] + "B=\n"},
			{"33 bytes in 44 characters, no padding", base64.StdEncoding.EncodeToString(append(rowKey(15), 15)) + "\n"},
			{"the 32 bytes themselves, not base64", string(rowKey(16))},
			{"a megabyte of base64", strings.Repeat(good, 1<<20/len(good)) + "\n"},
		} {
			t.Run("a key file: "+row.name, func(t *testing.T) {
				_, err := build(t, buildFolder(t, volume, row.contents), rowFields(), FirstSetup, FromKeyFile)
				wantRefusal(t, err, KeyFileMalformed)
			})
		}
		t.Run("a key file: empty", func(t *testing.T) {
			folder := buildFolder(t, volume, "")
			writeItem(t, filepath.Join(folder, nameKeyFile), "", serviceAccount, modeKeyFile)
			_, err := build(t, folder, rowFields(), FirstSetup, FromKeyFile)
			wantRefusal(t, err, KeyFileMalformed)
		})
		t.Run("a Swarm secret: two trailing newlines", func(t *testing.T) {
			emptyContainerFolder(t, "", good+"\n\n")
			_, err := build(t, containerFolder, rowFields(), FirstSetup, FromContainer)
			wantRefusal(t, err, KeyFileMalformed)
		})
		for _, row := range []struct{ name, contents string }{
			{"44 characters, no newline", good},
			{"44 characters and one newline", good + "\n"},
		} {
			t.Run("let through: "+row.name, func(t *testing.T) {
				folder := buildFolder(t, volume, row.contents)
				mode, err := build(t, folder, rowFields(), FirstSetup, FromKeyFile)
				wantBuilt(t, mode, err, ModeKeyFile, folder, rowKey(14), rowFields())
			})
		}
	})

	t.Run(lineBuildNoKeyMade, func(t *testing.T) {
		// The oracle reading the file under the sysop's key shows that no other key sealed
		// it; the folder shows that no sealed key or credential was written beside it.
		t.Run("FromKeyFile", func(t *testing.T) {
			folder := buildFolder(t, volume, keyText(rowKey(17)))
			mode, err := build(t, folder, rowFields(), FirstSetup, FromKeyFile)
			wantBuilt(t, mode, err, ModeKeyFile, folder, rowKey(17), rowFields())
			wantNoKeyMade(t, folder)
		})
		t.Run("FromContainer", func(t *testing.T) {
			emptyContainerFolder(t, "", keyText(rowKey(18)))
			mode, err := build(t, containerFolder, rowFields(), FirstSetup, FromContainer)
			wantBuilt(t, mode, err, ModeContainer, containerFolder, rowKey(18), rowFields())
			wantNoKeyMade(t, containerFolder)
		})
	})
}

// wantNoKeyMade fails the row when the folder holds a sealed key or a credential.
func wantNoKeyMade(t *testing.T, folder string) {
	t.Helper()
	for _, name := range []string{nameSealedKey, nameSystemdKey} {
		if _, err := os.Lstat(filepath.Join(folder, name)); err == nil {
			t.Errorf("Build wrote %s", name)
		}
	}
}

// TestBuildLinuxSystemd is the rows that turn on the systemd under them, run in each systemd
// image. Each row has one key source present, so that the systemd is the only thing judged.
//
//nolint:paralleltest // the rows under FromContainer share the container's fixed folder
func TestBuildLinuxSystemd(t *testing.T) {
	requireContainer(t)
	if os.Getuid() != 0 {
		t.Fatalf("the Linux rows run as root; running as uid %d", os.Getuid())
	}
	keyFileRow := func(t *testing.T) (string, KeyMode, error) {
		t.Helper()
		folder := buildFolder(t, volume, keyText(rowKey(19)))
		mode, err := build(t, folder, rowFields(), FirstSetup, FromKeyFile)
		return folder, mode, err
	}
	containerRow := func(t *testing.T) (KeyMode, error) {
		t.Helper()
		emptyContainerFolder(t, keyText(rowKey(20)), "")
		return build(t, containerFolder, rowFields(), FirstSetup, FromContainer)
	}
	storeRow := func(t *testing.T) error {
		t.Helper()
		_, err := build(t, buildFolder(t, volume, ""), rowFields(), FirstSetup, FromOSStore)
		return err
	}
	switch *systemdUnder {
	case systemdRunning249:
		t.Run(lineBuildKeyFileRefused, func(t *testing.T) {
			t.Run("let through: systemd 249 running", func(t *testing.T) {
				folder, mode, err := keyFileRow(t)
				wantBuilt(t, mode, err, ModeKeyFile, folder, rowKey(19), rowFields())
			})
		})
		t.Run(lineBuildContainerRefused, func(t *testing.T) {
			t.Run("systemd 249 running", func(t *testing.T) {
				_, err := containerRow(t)
				wantRefusal(t, err, SourceRefused)
			})
		})
		t.Run(lineBuildNoStore, func(t *testing.T) {
			t.Run("systemd 249 running", func(t *testing.T) { wantRefusal(t, storeRow(t), NoCredentialStore) })
		})
	case systemdRunning252:
		t.Run(lineBuildKeyFileRefused, func(t *testing.T) {
			t.Run("systemd 252 running", func(t *testing.T) {
				_, _, err := keyFileRow(t)
				wantRefusal(t, err, SourceRefused)
			})
		})
		t.Run(lineBuildContainerRefused, func(t *testing.T) {
			t.Run("systemd 252 running", func(t *testing.T) {
				_, err := containerRow(t)
				wantRefusal(t, err, SourceRefused)
			})
		})
	case systemdInstalled252:
		t.Run(lineBuildKeyFileRefused, func(t *testing.T) {
			t.Run("let through: systemd 252 installed, not running", func(t *testing.T) {
				folder, mode, err := keyFileRow(t)
				wantBuilt(t, mode, err, ModeKeyFile, folder, rowKey(19), rowFields())
			})
		})
		t.Run(lineBuildContainerRefused, func(t *testing.T) {
			t.Run("let through: systemd 252 installed, not running", func(t *testing.T) {
				mode, err := containerRow(t)
				wantBuilt(t, mode, err, ModeContainer, containerFolder, rowKey(20), rowFields())
			})
		})
		t.Run(lineBuildNoStore, func(t *testing.T) {
			t.Run("systemd 252 installed, not running", func(t *testing.T) { wantRefusal(t, storeRow(t), NoCredentialStore) })
		})
	default:
		t.Fatalf("-bootstrap.systemd is %q: these rows run under a systemd image", *systemdUnder)
	}
}
