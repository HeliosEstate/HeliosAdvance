// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// keyFileFolder is a folder on the ext4 volume holding a good key file and a bootstrap file
// sealed under its key.
func keyFileFolder(t *testing.T, parent string) string {
	t.Helper()
	folder := buildFolder(t, parent, keyText(rowKey(1)))
	writeGoodFile(t, filepath.Join(folder, nameFile), rowKey(1))
	ownAsBuildDoes(t, folder)
	return folder
}

// containerFolderWith empties the container's fixed folder, puts in the key file and the
// Swarm secret given (each when not empty), and a bootstrap file sealed under key.
func containerFolderWith(t *testing.T, keyFile, secret string, key []byte) {
	t.Helper()
	emptyContainerFolder(t, keyFile, secret)
	writeGoodFile(t, filepath.Join(containerFolder, nameFile), key)
}

// credentialFolder is a folder holding a bootstrap file sealed under a key, and that key as a
// systemd credential named name: a system credential, or one scoped to the account given.
func credentialFolder(t *testing.T, name, scopedTo string) string {
	t.Helper()
	folder := buildFolder(t, volume, "")
	key := rowKey(2)
	plain := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plain, key, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"encrypt", "--name=" + name, "--with-key=host", plain, filepath.Join(folder, nameSystemdKey)}
	if scopedTo != "" {
		args = append([]string{"--user", "--uid=" + scopedTo}, args...)
	}
	if out, err := exec.CommandContext(t.Context(), "systemd-creds", args...).CombinedOutput(); err != nil {
		t.Fatalf("the oracle's systemd-creds encrypt: %v\n%s", err, out)
	}
	writeGoodFile(t, filepath.Join(folder, nameFile), key)
	ownAsBuildDoes(t, folder)
	return folder
}

// ownAsBuildDoes gives the folder and its bootstrap file to the service account, as Build
// leaves them: the folder's owner is how an unlock knows whose credential to open.
func ownAsBuildDoes(t *testing.T, folder string) {
	t.Helper()
	setOwnerAndMode(t, folder, serviceAccount, modeFolder)
	setOwnerAndMode(t, filepath.Join(folder, nameFile), serviceAccount, modeFile)
}

// corruptCredential flips one bit in the middle of the credential's sealed bytes.
func corruptCredential(t *testing.T, path string) {
	t.Helper()
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := base64.StdEncoding.DecodeString(string(trimSpace(text)))
	if err != nil {
		t.Fatalf("%s is not base64: %v", path, err)
	}
	sealed[len(sealed)/2] ^= 1
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(sealed)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func trimSpace(data []byte) []byte {
	for len(data) > 0 && (data[len(data)-1] == '\n' || data[len(data)-1] == ' ') {
		data = data[:len(data)-1]
	}
	return data
}

// TestUnlockSetupLinuxNotElevated runs as the account nobody, through setpriv: a folder that
// breaks no rule, a good key file and bootstrap file, and only the rights missing.
func TestUnlockSetupLinuxNotElevated(t *testing.T) {
	t.Parallel()
	requireContainer(t)
	t.Run(lineSetupNotElevated, func(t *testing.T) {
		t.Parallel()
		folder, err := os.MkdirTemp(volume, "own-") //nolint:usetesting // on the ext4 volume; t.TempDir is on overlayfs
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(folder, nameKeyFile), []byte(keyText(rowKey(1))), modeKeyFile); err != nil {
			t.Fatal(err)
		}
		writeGoodFile(t, filepath.Join(folder, nameFile), rowKey(1))
		handle, err := unlockSetup(t, folder, ModeKeyFile)
		wantRefused(t, handle, err, NotElevated)
	})
}

// TestUnlockSetupLinuxAsRoot is every Linux row with no systemd but NotElevated. The rows run
// one after another: those under ModeContainer share the container's one fixed folder.
//
//nolint:paralleltest // the rows under ModeContainer share the container's fixed folder
func TestUnlockSetupLinuxAsRoot(t *testing.T) {
	requireContainer(t)
	if os.Getuid() != 0 {
		t.Fatalf("the Linux rows run as root; running as uid %d", os.Getuid())
	}
	if *systemdUnder != "" {
		t.Fatalf("these rows run with no systemd; -bootstrap.systemd is %q", *systemdUnder)
	}

	t.Run(lineHandleFields, func(t *testing.T) {
		handle, err := unlockSetup(t, keyFileFolder(t, volume), ModeKeyFile)
		handle = wantUnlocked(t, handle, err)
		fields := handle.Fields()
		fields.Connection = "changed"
		fields.AccountPassword[0] ^= 0xFF
		fields.ReceivingKey[0] ^= 0xFF
		fields.VaultKeys[0].Key[0] ^= 0xFF
		fields.VaultKeys = append(fields.VaultKeys, VaultKey{Version: 9, Key: rowKey(9)})
		sameFields(t, handle.Fields(), rowFields())
	})

	t.Run(lineHandleHolding, func(t *testing.T) {
		t.Run("a key file: HeldInKeyFile", func(t *testing.T) {
			handle, err := unlockSetup(t, keyFileFolder(t, volume), ModeKeyFile)
			if got := wantUnlocked(t, handle, err).Holding(); got != HeldInKeyFile {
				t.Errorf("Holding is %d, want HeldInKeyFile (%d)", got, HeldInKeyFile)
			}
		})
		t.Run("a Swarm secret: HeldAsSwarmSecret", func(t *testing.T) {
			containerFolderWith(t, "", keyText(rowKey(3)), rowKey(3))
			handle, err := unlockSetup(t, containerFolder, ModeContainer)
			if got := wantUnlocked(t, handle, err).Holding(); got != HeldAsSwarmSecret {
				t.Errorf("Holding is %d, want HeldAsSwarmSecret (%d)", got, HeldAsSwarmSecret)
			}
		})
		t.Run("a container's key file: HeldInKeyFile", func(t *testing.T) {
			containerFolderWith(t, keyText(rowKey(4)), "", rowKey(4))
			handle, err := unlockSetup(t, containerFolder, ModeContainer)
			if got := wantUnlocked(t, handle, err).Holding(); got != HeldInKeyFile {
				t.Errorf("Holding is %d, want HeldInKeyFile (%d)", got, HeldInKeyFile)
			}
		})
	})

	t.Run(lineHandleCloseLock, func(t *testing.T) {
		folder := keyFileFolder(t, volume)
		first, err := unlockSetup(t, folder, ModeKeyFile)
		wantUnlocked(t, first, err).Close()
		second, err := unlockSetup(t, folder, ModeKeyFile)
		wantUnlocked(t, second, err)
	})

	t.Run(lineHandleCloseTwice, func(t *testing.T) {
		folder := keyFileFolder(t, volume)
		first, err := unlockSetup(t, folder, ModeKeyFile)
		first = wantUnlocked(t, first, err)
		first.Close()
		second, err := unlockSetup(t, folder, ModeKeyFile)
		wantUnlocked(t, second, err)
		// The second Close must not release the lock the second handle now holds.
		first.Close()
		third, err := unlockSetup(t, folder, ModeKeyFile)
		wantRefused(t, third, err, InUse)
	})

	t.Run(lineSetupInUse, func(t *testing.T) {
		t.Run("another handle open", func(t *testing.T) {
			folder := keyFileFolder(t, volume)
			first, err := unlockSetup(t, folder, ModeKeyFile)
			wantUnlocked(t, first, err)
			second, err := unlockSetup(t, folder, ModeKeyFile)
			wantRefused(t, second, err, InUse)
		})
		t.Run("the lock held by another process every usual way", func(t *testing.T) {
			folder := keyFileFolder(t, volume)
			lock := filepath.Join(folder, nameLock)
			writeItem(t, lock, "", serviceAccount, modeFile)
			release := holdLock(t, lock)
			defer release()
			handle, err := unlockSetup(t, folder, ModeKeyFile)
			wantRefused(t, handle, err, InUse)
		})
	})

	t.Run(lineSetupLockMade, func(t *testing.T) {
		// The folder has no lock, as hadv-setup makes it. The lock's rule is for the account
		// given, whoever owns the folder: a folder given to root is looser than its rule and
		// not refused.
		for _, row := range []struct{ name, folderOwner string }{
			{"the folder the account's", serviceAccount},
			{"the folder given to root", "root"},
		} {
			t.Run(row.name, func(t *testing.T) {
				folder := keyFileFolder(t, volume)
				setOwnerAndMode(t, folder, row.folderOwner, modeFolder)
				handle, err := unlockSetup(t, folder, ModeKeyFile)
				wantUnlocked(t, handle, err).Close()
				lock := filepath.Join(folder, nameLock)
				if got, want := statPermissions(t, lock)[lock], linuxRule(ItemOtherFile, serviceAccount); !samePermissions(got, want) {
					t.Errorf("the lock made is %+v, want its rule %+v", got, want)
				}
			})
		}
	})

	t.Run(lineSetupHandle, func(t *testing.T) {
		folder := keyFileFolder(t, volume)
		handle, err := unlockSetup(t, folder, ModeKeyFile)
		handle = wantUnlocked(t, handle, err)
		other, err := unlockSetup(t, folder, ModeKeyFile)
		wantRefused(t, other, err, InUse)
		handle.Close()
		after, err := unlockSetup(t, folder, ModeKeyFile)
		wantUnlocked(t, after, err)
	})

	t.Run(lineSetupFolder, func(t *testing.T) {
		good := keyFileFolder(t, volume)
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
			{rowTmpfs, keyFileFolder(t, tmpfsMount), FileSystem},
			{rowOverlayfs, keyFileFolder(t, overlayRoot), FileSystem},
		} {
			t.Run(row.name, func(t *testing.T) {
				handle, err := unlockSetup(t, row.folder, ModeKeyFile)
				if handle != nil {
					handle.Close()
				}
				wantFolderRefused(t, err, row.rule)
			})
		}
		t.Run("let through: a folder on ext4", func(t *testing.T) {
			handle, err := unlockSetup(t, good, ModeKeyFile)
			wantUnlocked(t, handle, err)
		})
	})

	t.Run(lineSetupLink, func(t *testing.T) {
		// The link's target and the second name are good files on the same ext4 volume, so
		// that the link is the only thing wrong.
		for _, row := range []struct {
			name, item string
			hard       bool
		}{
			{"the bootstrap file a symbolic link", nameFile, false},
			{"the key file a symbolic link", nameKeyFile, false},
			{"the bootstrap file with a second name", nameFile, true},
			{"the key file with a second name", nameKeyFile, true},
		} {
			t.Run(row.name, func(t *testing.T) {
				folder := keyFileFolder(t, volume)
				item := filepath.Join(folder, row.item)
				elsewhere := filepath.Join(buildFolder(t, volume, ""), "elsewhere")
				if err := os.Rename(item, elsewhere); err != nil {
					t.Fatal(err)
				}
				link := os.Symlink
				if row.hard {
					link = os.Link
				}
				if err := link(elsewhere, item); err != nil {
					t.Fatal(err)
				}
				handle, err := unlockSetup(t, folder, ModeKeyFile)
				wantRefused(t, handle, err, Link)
			})
		}
		t.Run("let through: each a file with one name", func(t *testing.T) {
			handle, err := unlockSetup(t, keyFileFolder(t, volume), ModeKeyFile)
			wantUnlocked(t, handle, err)
		})
	})

	t.Run(lineSetupLooser, func(t *testing.T) {
		for _, row := range []struct {
			name   string
			loosen func(t *testing.T, folder string)
		}{
			{rowFolder0755, func(t *testing.T, folder string) { t.Helper(); chmodItem(t, folder, 0o755) }},
			{"the bootstrap file at 0644", func(t *testing.T, folder string) { t.Helper(); chmodItem(t, filepath.Join(folder, nameFile), 0o644) }},
			{"the key file at 0644", func(t *testing.T, folder string) { t.Helper(); chmodItem(t, filepath.Join(folder, nameKeyFile), 0o644) }},
			{"the bootstrap file owned by daemon", func(t *testing.T, folder string) {
				t.Helper()
				setOwnerAndMode(t, filepath.Join(folder, nameFile), otherAccount, modeFile)
			}},
		} {
			t.Run(row.name, func(t *testing.T) {
				folder := keyFileFolder(t, volume)
				row.loosen(t, folder)
				handle, err := unlockSetup(t, folder, ModeKeyFile)
				wantUnlocked(t, handle, err)
			})
		}
	})

	t.Run(lineSetupHalfMade, func(t *testing.T) {
		folder := keyFileFolder(t, volume)
		halfMade := filepath.Join(folder, nameFile+".new")
		writeItem(t, halfMade, "a half-made bootstrap file", serviceAccount, modeFile)
		handle, err := unlockSetup(t, folder, ModeKeyFile)
		wantUnlocked(t, handle, err)
		if _, err := os.Lstat(halfMade); err == nil {
			t.Error("bootstrap.hadv.new is still in the folder")
		}
	})

	t.Run(lineSetupMode, func(t *testing.T) {
		for _, row := range []struct {
			name string
			mode KeyMode
		}{
			{"ModeMachineKeyPair on Linux", ModeMachineKeyPair},
			{"ModeSystemdAtStart with no systemd", ModeSystemdAtStart},
			{"ModeSystemdPerUse with no systemd", ModeSystemdPerUse},
		} {
			t.Run(row.name, func(t *testing.T) {
				handle, err := unlockSetup(t, keyFileFolder(t, volume), row.mode)
				wantRefused(t, handle, err, SourceRefused)
			})
		}
		t.Run("let through: ModeKeyFile with no systemd", func(t *testing.T) {
			handle, err := unlockSetup(t, keyFileFolder(t, volume), ModeKeyFile)
			wantUnlocked(t, handle, err)
		})
		t.Run("let through: ModeContainer with no systemd", func(t *testing.T) {
			containerFolderWith(t, keyText(rowKey(5)), "", rowKey(5))
			handle, err := unlockSetup(t, containerFolder, ModeContainer)
			wantUnlocked(t, handle, err)
		})
	})

	t.Run(lineSetupNoKeySource, func(t *testing.T) {
		containerFolderWith(t, "", "", rowKey(6))
		handle, err := unlockSetup(t, containerFolder, ModeContainer)
		wantRefused(t, handle, err, NoKeySource)
	})

	t.Run(lineSetupBothKeySources, func(t *testing.T) {
		containerFolderWith(t, keyText(rowKey(7)), keyText(rowKey(7)), rowKey(7))
		handle, err := unlockSetup(t, containerFolder, ModeContainer)
		wantRefused(t, handle, err, BothKeySources)
	})

	t.Run(lineSetupKeyNotFound, func(t *testing.T) {
		folder := buildFolder(t, volume, "")
		writeGoodFile(t, filepath.Join(folder, nameFile), rowKey(1))
		handle, err := unlockSetup(t, folder, ModeKeyFile)
		wantRefused(t, handle, err, KeyNotFound)
	})

	t.Run(lineSetupMalformed, func(t *testing.T) {
		t.Run("a key file with two trailing newlines", func(t *testing.T) {
			folder := buildFolder(t, volume, keyText(rowKey(1))+"\n")
			writeGoodFile(t, filepath.Join(folder, nameFile), rowKey(1))
			handle, err := unlockSetup(t, folder, ModeKeyFile)
			wantRefused(t, handle, err, KeyFileMalformed)
		})
		t.Run("a Swarm secret of 43 characters", func(t *testing.T) {
			containerFolderWith(t, "", keyText(rowKey(8))[:43], rowKey(8))
			handle, err := unlockSetup(t, containerFolder, ModeContainer)
			wantRefused(t, handle, err, KeyFileMalformed)
		})
	})

	t.Run(lineSetupFileNotFound, func(t *testing.T) {
		handle, err := unlockSetup(t, buildFolder(t, volume, keyText(rowKey(1))), ModeKeyFile)
		wantRefused(t, handle, err, FileNotFound)
	})
}

// chmodItem sets one item's permission bits.
func chmodItem(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// TestUnlockSetupLinuxSystemd is the Linux rows that turn on the systemd under them, run in each
// booted systemd image. No container has a TPM, so every credential is sealed under the host key.
//
//nolint:paralleltest // the rows share the container's one systemd and its fixed folder
func TestUnlockSetupLinuxSystemd(t *testing.T) {
	requireContainer(t)
	if os.Getuid() != 0 {
		t.Fatalf("the Linux rows run as root; running as uid %d", os.Getuid())
	}
	switch *systemdUnder {
	case systemdRunning252:
		t.Run(lineSetupSystemd, func(t *testing.T) {
			t.Run("systemd 252, ModeSystemdAtStart: a system credential", func(t *testing.T) {
				handle, err := unlockSetup(t, credentialFolder(t, credentialName, ""), ModeSystemdAtStart)
				wantUnlocked(t, handle, err)
			})
		})
		t.Run(lineHandleHolding, func(t *testing.T) {
			t.Run("systemd 252, no TPM: HeldUnderHostKey", func(t *testing.T) {
				handle, err := unlockSetup(t, credentialFolder(t, credentialName, ""), ModeSystemdAtStart)
				if got := wantUnlocked(t, handle, err).Holding(); got != HeldUnderHostKey {
					t.Errorf("Holding is %d, want HeldUnderHostKey (%d)", got, HeldUnderHostKey)
				}
			})
		})
		t.Run(lineSetupMode, func(t *testing.T) {
			for _, row := range []struct {
				name string
				mode KeyMode
			}{
				{"ModeSystemdPerUse on systemd 252", ModeSystemdPerUse},
				{"ModeMachineKeyPair on Linux", ModeMachineKeyPair},
			} {
				t.Run(row.name, func(t *testing.T) {
					handle, err := unlockSetup(t, credentialFolder(t, credentialName, ""), row.mode)
					wantRefused(t, handle, err, SourceRefused)
				})
			}
			t.Run("ModeContainer under a running systemd", func(t *testing.T) {
				containerFolderWith(t, keyText(rowKey(5)), "", rowKey(5))
				handle, err := unlockSetup(t, containerFolder, ModeContainer)
				wantRefused(t, handle, err, SourceRefused)
			})
			t.Run("let through: ModeKeyFile on systemd 252", func(t *testing.T) {
				handle, err := unlockSetup(t, keyFileFolder(t, volume), ModeKeyFile)
				wantUnlocked(t, handle, err)
			})
		})
		t.Run(lineSetupKeyNotFound, func(t *testing.T) {
			t.Run("ModeSystemdAtStart with no credential", func(t *testing.T) {
				folder := buildFolder(t, volume, "")
				writeGoodFile(t, filepath.Join(folder, nameFile), rowKey(2))
				handle, err := unlockSetup(t, folder, ModeSystemdAtStart)
				wantRefused(t, handle, err, KeyNotFound)
			})
		})
		t.Run(lineSetupNotUnsealed, func(t *testing.T) {
			t.Run("systemd 252: the credential altered", func(t *testing.T) {
				folder := credentialFolder(t, credentialName, "")
				corruptCredential(t, filepath.Join(folder, nameSystemdKey))
				handle, err := unlockSetup(t, folder, ModeSystemdAtStart)
				wantRefused(t, handle, err, KeyNotUnsealed)
			})
			t.Run("systemd 252: a credential of another name", func(t *testing.T) {
				handle, err := unlockSetup(t, credentialFolder(t, "another-name", ""), ModeSystemdAtStart)
				wantRefused(t, handle, err, KeyNotUnsealed)
			})
		})
	case systemdRunning257:
		t.Run(lineSetupSystemd, func(t *testing.T) {
			t.Run("systemd 257, ModeSystemdPerUse: a credential scoped to the account", func(t *testing.T) {
				handle, err := unlockSetup(t, credentialFolder(t, credentialName, serviceAccount), ModeSystemdPerUse)
				wantUnlocked(t, handle, err)
			})
		})
		t.Run(lineSetupPerUseAccount, func(t *testing.T) {
			t.Run("systemd 257: the folder given to root, the credential scoped to the account given", func(t *testing.T) {
				// Looser than its rule and not refused: the folder's owner is not who the
				// credential is for.
				folder := credentialFolder(t, credentialName, serviceAccount)
				setOwnerAndMode(t, folder, "root", modeFolder)
				handle, err := unlockSetup(t, folder, ModeSystemdPerUse)
				wantUnlocked(t, handle, err)
			})
		})
		t.Run(lineHandleHolding, func(t *testing.T) {
			t.Run("systemd 257, no TPM: HeldUnderHostKey", func(t *testing.T) {
				handle, err := unlockSetup(t, credentialFolder(t, credentialName, serviceAccount), ModeSystemdPerUse)
				if got := wantUnlocked(t, handle, err).Holding(); got != HeldUnderHostKey {
					t.Errorf("Holding is %d, want HeldUnderHostKey (%d)", got, HeldUnderHostKey)
				}
			})
		})
		t.Run(lineSetupMode, func(t *testing.T) {
			t.Run("ModeContainer under a running systemd", func(t *testing.T) {
				containerFolderWith(t, keyText(rowKey(5)), "", rowKey(5))
				handle, err := unlockSetup(t, containerFolder, ModeContainer)
				wantRefused(t, handle, err, SourceRefused)
			})
			t.Run("let through: ModeSystemdAtStart on systemd 257, a server upgraded after Build", func(t *testing.T) {
				handle, err := unlockSetup(t, credentialFolder(t, credentialName, ""), ModeSystemdAtStart)
				wantUnlocked(t, handle, err)
			})
		})
		t.Run(lineSetupKeyNotFound, func(t *testing.T) {
			t.Run("ModeSystemdPerUse with no credential", func(t *testing.T) {
				folder := buildFolder(t, volume, "")
				writeGoodFile(t, filepath.Join(folder, nameFile), rowKey(2))
				handle, err := unlockSetup(t, folder, ModeSystemdPerUse)
				wantRefused(t, handle, err, KeyNotFound)
			})
		})
		t.Run(lineSetupNotUnsealed, func(t *testing.T) {
			t.Run("systemd 257: a credential scoped to another account", func(t *testing.T) {
				handle, err := unlockSetup(t, credentialFolder(t, credentialName, otherAccount), ModeSystemdPerUse)
				wantRefused(t, handle, err, KeyNotUnsealed)
			})
		})
	default:
		t.Fatalf("-bootstrap.systemd is %q: these rows run under systemd 252 or 257", *systemdUnder)
	}
}
