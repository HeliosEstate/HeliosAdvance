// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// launchAs starts the binary as the account through setpriv, from this process running as
// root.
func launchAs(t *testing.T, binary, account, address string) func() string {
	t.Helper()
	found, err := user.Lookup(account)
	if err != nil {
		t.Fatal(err)
	}
	return startChild(t, exec.CommandContext(t.Context(), "setpriv", "--reuid="+found.Uid, "--regid="+found.Gid, "--clear-groups", //nolint:gosec // this test binary, run again as the row's account
		binary, "-test.run", "^TestUnlockServiceChild$", "-bootstrap.container", "-bootstrap.child="+address))
}

// serviceContainerFolder empties the container's fixed folder and makes it the service
// account's at its rule, with the key file and the Swarm secret given (each when not empty)
// and a bootstrap file sealed under key.
func serviceContainerFolder(t *testing.T, keyFile, secret string, key []byte) {
	t.Helper()
	containerFolderWith(t, keyFile, secret, key)
	setOwnerAndMode(t, containerFolder, serviceAccount, modeFolder)
	setOwnerAndMode(t, filepath.Join(containerFolder, nameFile), serviceAccount, modeFile)
}

// serviceCredentialFolder is a folder holding a credential scoped to the account given and a
// bootstrap file sealed under its key, every item the service account's at its rule.
func serviceCredentialFolder(t *testing.T, scopedTo string) string {
	t.Helper()
	folder := credentialFolder(t, credentialName, scopedTo)
	setOwnerAndMode(t, filepath.Join(folder, nameSystemdKey), serviceAccount, modeFile)
	return folder
}

// noKeyFileFolder is a folder at its rule with a bootstrap file and no key file.
func noKeyFileFolder(t *testing.T) string {
	t.Helper()
	folder := buildFolder(t, volume, "")
	writeGoodFile(t, filepath.Join(folder, nameFile), rowKey(1))
	ownAsBuildDoes(t, folder)
	return folder
}

// TestUnlockServiceLinuxAsRoot is every Linux row with no systemd. The rows run one after
// another: those under ModeContainer share the container's one fixed folder.
//
//nolint:paralleltest // the rows under ModeContainer share the container's fixed folder
func TestUnlockServiceLinuxAsRoot(t *testing.T) {
	requireContainer(t)
	if os.Getuid() != 0 {
		t.Fatalf("the Linux rows run as root; running as uid %d", os.Getuid())
	}
	if *systemdUnder != "" {
		t.Fatalf("these rows run with no systemd; -bootstrap.systemd is %q", *systemdUnder)
	}
	asService := func(t *testing.T, folder string, mode KeyMode) *serviceProcess {
		t.Helper()
		return startService(t, os.Args[0], serviceAccount, folder, mode)
	}
	asRoot := func(t *testing.T, folder string, mode KeyMode) error {
		t.Helper()
		handle, err := New().UnlockForService(t.Context(), folder, mode)
		if handle != nil {
			handle.Close()
		}
		return err
	}

	t.Run(lineServiceOrder, func(t *testing.T) {
		t.Run("as root, the lock held: WrongAccount before InUse", func(t *testing.T) {
			folder := keyFileFolder(t, volume)
			wantServiceUnlocked(t, asService(t, folder, ModeKeyFile))
			wantRefusal(t, asRoot(t, folder, ModeKeyFile), WrongAccount)
		})
		t.Run("the lock held and the folder on tmpfs: InUse before FolderRefused", func(t *testing.T) {
			folder := keyFileFolder(t, tmpfsMount)
			lock := filepath.Join(folder, nameLock)
			writeItem(t, lock, "", serviceAccount, modeFile)
			release := holdLock(t, lock)
			defer release()
			wantServiceRefused(t, asService(t, folder, ModeKeyFile), InUse)
		})
		t.Run("the folder on tmpfs and the bootstrap file a symbolic link: FolderRefused before Link", func(t *testing.T) {
			folder := keyFileFolder(t, tmpfsMount)
			linkInPlace(t, filepath.Join(folder, nameFile), false)
			wantFolderRefused(t, asService(t, folder, ModeKeyFile).report.err(), FileSystem)
		})
		t.Run("the bootstrap file a symbolic link and the folder at 0755: Link before LooserThanRule", func(t *testing.T) {
			folder := keyFileFolder(t, volume)
			linkInPlace(t, filepath.Join(folder, nameFile), false)
			chmodItem(t, folder, 0o755)
			wantServiceRefused(t, asService(t, folder, ModeKeyFile), Link)
		})
		t.Run("the folder at 0755 and a half-made file: LooserThanRule, the half-made file kept", func(t *testing.T) {
			folder := keyFileFolder(t, volume)
			halfMade := filepath.Join(folder, nameFile+".new")
			writeItem(t, halfMade, "a half-made bootstrap file", serviceAccount, modeFile)
			chmodItem(t, folder, 0o755)
			wantLooserNaming(t, asService(t, folder, ModeKeyFile), ItemFolder, folder)
			wantStillThere(t, halfMade)
		})
		t.Run("a half-made file and no key file: the half-made file deleted, then KeyNotFound", func(t *testing.T) {
			folder := noKeyFileFolder(t)
			halfMade := filepath.Join(folder, nameFile+".new")
			writeItem(t, halfMade, "a half-made bootstrap file", serviceAccount, modeFile)
			wantServiceRefused(t, asService(t, folder, ModeKeyFile), KeyNotFound)
			wantGone(t, halfMade)
		})
	})

	t.Run(lineServiceElevated, func(t *testing.T) {
		wantRefusal(t, asRoot(t, keyFileFolder(t, volume), ModeKeyFile), WrongAccount)
	})

	t.Run(lineServiceAccountLinux, func(t *testing.T) {
		t.Run("as daemon, which does not own the folder", func(t *testing.T) {
			wantServiceRefused(t, startService(t, os.Args[0], otherAccount, keyFileFolder(t, volume), ModeKeyFile), WrongAccount)
		})
		t.Run("let through: as nobody, which owns the folder", func(t *testing.T) {
			wantServiceUnlocked(t, asService(t, keyFileFolder(t, volume), ModeKeyFile))
		})
	})

	t.Run(lineServiceInUse, func(t *testing.T) {
		t.Run("another handle open", func(t *testing.T) {
			folder := keyFileFolder(t, volume)
			wantServiceUnlocked(t, asService(t, folder, ModeKeyFile))
			wantServiceRefused(t, asService(t, folder, ModeKeyFile), InUse)
		})
		t.Run("the lock held by another process every usual way", func(t *testing.T) {
			folder := keyFileFolder(t, volume)
			lock := filepath.Join(folder, nameLock)
			writeItem(t, lock, "", serviceAccount, modeFile)
			release := holdLock(t, lock)
			defer release()
			wantServiceRefused(t, asService(t, folder, ModeKeyFile), InUse)
		})
	})

	t.Run(lineServiceLockMade, func(t *testing.T) {
		folder := keyFileFolder(t, volume)
		process := asService(t, folder, ModeKeyFile)
		wantServiceUnlocked(t, process)
		process.close(t)
		lock := filepath.Join(folder, nameLock)
		if got, want := statPermissions(t, lock)[lock], linuxRule(ItemOtherFile, serviceAccount); !samePermissions(got, want) {
			t.Errorf("the lock made is %+v, want its rule %+v", got, want)
		}
	})

	t.Run(lineServiceFolder, func(t *testing.T) {
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
				wantFolderRefused(t, asService(t, row.folder, ModeKeyFile).report.err(), row.rule)
			})
		}
		t.Run("let through: a folder on ext4", func(t *testing.T) {
			wantServiceUnlocked(t, asService(t, good, ModeKeyFile))
		})
	})

	t.Run(lineServiceLink, func(t *testing.T) {
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
				linkInPlace(t, filepath.Join(folder, row.item), row.hard)
				wantServiceRefused(t, asService(t, folder, ModeKeyFile), Link)
			})
		}
		t.Run("let through: each a file with one name", func(t *testing.T) {
			wantServiceUnlocked(t, asService(t, keyFileFolder(t, volume), ModeKeyFile))
		})
	})

	t.Run(lineServiceLooser, func(t *testing.T) {
		for _, row := range []struct {
			name   string
			loosen func(t *testing.T, folder string) (Item, string)
		}{
			{rowFolder0755, func(t *testing.T, folder string) (Item, string) {
				t.Helper()
				chmodItem(t, folder, 0o755)
				return ItemFolder, folder
			}},
			{rowFile0644, func(t *testing.T, folder string) (Item, string) {
				t.Helper()
				file := filepath.Join(folder, nameFile)
				chmodItem(t, file, 0o644)
				return ItemFile, file
			}},
			{"the bootstrap file owned by daemon", func(t *testing.T, folder string) (Item, string) {
				t.Helper()
				file := filepath.Join(folder, nameFile)
				setOwnerAndMode(t, file, otherAccount, modeFile)
				return ItemFile, file
			}},
			{"the key file at 0600", func(t *testing.T, folder string) (Item, string) {
				t.Helper()
				keyFile := filepath.Join(folder, nameKeyFile)
				chmodItem(t, keyFile, 0o600)
				return ItemKeyFile, keyFile
			}},
			{rowLock0644, func(t *testing.T, folder string) (Item, string) {
				t.Helper()
				lock := filepath.Join(folder, nameLock)
				writeItem(t, lock, "", serviceAccount, 0o644)
				return ItemOtherFile, lock
			}},
			{"a half-made file at 0644", func(t *testing.T, folder string) (Item, string) {
				t.Helper()
				halfMade := filepath.Join(folder, nameFile+".new")
				writeItem(t, halfMade, "a half-made bootstrap file", serviceAccount, 0o644)
				return ItemOtherFile, halfMade
			}},
		} {
			t.Run(row.name, func(t *testing.T) {
				folder := keyFileFolder(t, volume)
				item, path := row.loosen(t, folder)
				wantLooserNaming(t, asService(t, folder, ModeKeyFile), item, path)
			})
		}
		t.Run("the Swarm secret at Docker's default, owned by root at 0444", func(t *testing.T) {
			serviceContainerFolder(t, "", keyText(rowKey(3)), rowKey(3))
			setOwnerAndMode(t, swarmSecret, "root", looseSecret)
			wantLooserNaming(t, asService(t, containerFolder, ModeContainer), ItemSwarmSecret, swarmSecret)
		})
		t.Run("let through: every item at its rule, the key file at 0400", func(t *testing.T) {
			wantServiceUnlocked(t, asService(t, keyFileFolder(t, volume), ModeKeyFile))
		})
	})

	t.Run(lineServiceNotWritable, func(t *testing.T) {
		t.Run("the bootstrap file at 0400", func(t *testing.T) {
			folder := keyFileFolder(t, volume)
			file := filepath.Join(folder, nameFile)
			chmodItem(t, file, 0o400)
			wantNotWritableNaming(t, asService(t, folder, ModeKeyFile), file)
		})
		t.Run("the folder at 0500", func(t *testing.T) {
			// The lock is there already, so taking it needs nothing written in the folder.
			folder := keyFileFolder(t, volume)
			writeItem(t, filepath.Join(folder, nameLock), "", serviceAccount, modeFile)
			chmodItem(t, folder, 0o500)
			wantNotWritableNaming(t, asService(t, folder, ModeKeyFile), folder)
		})
	})

	t.Run(lineServiceHalfMade, func(t *testing.T) {
		folder := keyFileFolder(t, volume)
		halfMade := filepath.Join(folder, nameFile+".new")
		writeItem(t, halfMade, "a half-made bootstrap file", serviceAccount, modeFile)
		wantServiceUnlocked(t, asService(t, folder, ModeKeyFile))
		wantGone(t, halfMade)
	})

	t.Run(lineServiceMode, func(t *testing.T) {
		for _, row := range []struct {
			name string
			mode KeyMode
		}{
			{rowMachineKeyPairLinux, ModeMachineKeyPair},
			{"ModeSystemdAtStart with no systemd", ModeSystemdAtStart},
			{"ModeSystemdPerUse with no systemd", ModeSystemdPerUse},
		} {
			t.Run(row.name, func(t *testing.T) {
				wantServiceRefused(t, asService(t, keyFileFolder(t, volume), row.mode), SourceRefused)
			})
		}
		t.Run("let through: ModeKeyFile with no systemd", func(t *testing.T) {
			wantServiceUnlocked(t, asService(t, keyFileFolder(t, volume), ModeKeyFile))
		})
		t.Run("let through: ModeContainer with no systemd", func(t *testing.T) {
			serviceContainerFolder(t, keyText(rowKey(5)), "", rowKey(5))
			wantServiceUnlocked(t, asService(t, containerFolder, ModeContainer))
		})
	})

	t.Run(lineServiceNoKeySource, func(t *testing.T) {
		serviceContainerFolder(t, "", "", rowKey(6))
		wantServiceRefused(t, asService(t, containerFolder, ModeContainer), NoKeySource)
	})

	t.Run(lineServiceBothKeySources, func(t *testing.T) {
		serviceContainerFolder(t, keyText(rowKey(7)), keyText(rowKey(7)), rowKey(7))
		wantServiceRefused(t, asService(t, containerFolder, ModeContainer), BothKeySources)
	})

	t.Run(lineServiceKeyNotFound, func(t *testing.T) {
		wantServiceRefused(t, asService(t, noKeyFileFolder(t), ModeKeyFile), KeyNotFound)
	})

	t.Run(lineServiceMalformed, func(t *testing.T) {
		t.Run("a key file with two trailing newlines", func(t *testing.T) {
			folder := buildFolder(t, volume, keyText(rowKey(1))+"\n")
			writeGoodFile(t, filepath.Join(folder, nameFile), rowKey(1))
			ownAsBuildDoes(t, folder)
			wantServiceRefused(t, asService(t, folder, ModeKeyFile), KeyFileMalformed)
		})
		t.Run("a Swarm secret of 43 characters", func(t *testing.T) {
			serviceContainerFolder(t, "", keyText(rowKey(8))[:43], rowKey(8))
			wantServiceRefused(t, asService(t, containerFolder, ModeContainer), KeyFileMalformed)
		})
	})

	t.Run(lineServiceFileNotFound, func(t *testing.T) {
		folder := keyFileFolder(t, volume)
		removeItem(t, filepath.Join(folder, nameFile))
		wantServiceRefused(t, asService(t, folder, ModeKeyFile), FileNotFound)
	})

	t.Run(lineServiceHeldFile, func(t *testing.T) {
		t.Run("a key file: HeldInKeyFile", func(t *testing.T) {
			wantServiceHolding(t, asService(t, keyFileFolder(t, volume), ModeKeyFile), HeldInKeyFile, "HeldInKeyFile")
		})
		t.Run("a Swarm secret: HeldAsSwarmSecret", func(t *testing.T) {
			serviceContainerFolder(t, "", keyText(rowKey(3)), rowKey(3))
			wantServiceHolding(t, asService(t, containerFolder, ModeContainer), HeldAsSwarmSecret, "HeldAsSwarmSecret")
		})
		t.Run("a container's key file: HeldInKeyFile", func(t *testing.T) {
			serviceContainerFolder(t, keyText(rowKey(4)), "", rowKey(4))
			wantServiceHolding(t, asService(t, containerFolder, ModeContainer), HeldInKeyFile, "HeldInKeyFile")
		})
	})

	t.Run(lineServiceHandle, func(t *testing.T) {
		folder := keyFileFolder(t, volume)
		first := asService(t, folder, ModeKeyFile)
		wantServiceUnlocked(t, first)
		wantServiceRefused(t, asService(t, folder, ModeKeyFile), InUse)
		first.close(t)
		wantServiceUnlocked(t, asService(t, folder, ModeKeyFile))
	})
}

// TestUnlockServiceLinuxSystemd is the Linux rows that turn on the systemd under them, run in
// each booted systemd image. No container has a TPM, so every credential is sealed under the
// host key, and no container gives a service its credential folder, so no row unlocks under
// ModeSystemdAtStart.
//
//nolint:paralleltest // the rows share the container's one systemd and its fixed folder
func TestUnlockServiceLinuxSystemd(t *testing.T) {
	requireContainer(t)
	if os.Getuid() != 0 {
		t.Fatalf("the Linux rows run as root; running as uid %d", os.Getuid())
	}
	asService := func(t *testing.T, folder string, mode KeyMode) *serviceProcess {
		t.Helper()
		return startService(t, os.Args[0], serviceAccount, folder, mode)
	}
	switch *systemdUnder {
	case systemdRunning252:
		t.Run(lineServiceMode, func(t *testing.T) {
			for _, row := range []struct {
				name string
				mode KeyMode
			}{
				{"ModeSystemdPerUse on systemd 252", ModeSystemdPerUse},
				{rowMachineKeyPairLinux, ModeMachineKeyPair},
			} {
				t.Run(row.name, func(t *testing.T) {
					wantServiceRefused(t, asService(t, keyFileFolder(t, volume), row.mode), SourceRefused)
				})
			}
			t.Run("ModeContainer under a running systemd", func(t *testing.T) {
				serviceContainerFolder(t, keyText(rowKey(5)), "", rowKey(5))
				wantServiceRefused(t, asService(t, containerFolder, ModeContainer), SourceRefused)
			})
			t.Run("let through: ModeKeyFile on systemd 252", func(t *testing.T) {
				wantServiceUnlocked(t, asService(t, keyFileFolder(t, volume), ModeKeyFile))
			})
		})
		t.Run(lineServiceHeldFile, func(t *testing.T) {
			t.Run("a key file under systemd 252: HeldInKeyFile", func(t *testing.T) {
				wantServiceHolding(t, asService(t, keyFileFolder(t, volume), ModeKeyFile), HeldInKeyFile, "HeldInKeyFile")
			})
		})
	case systemdRunning257:
		t.Run(lineServiceHeldSystemd, func(t *testing.T) {
			t.Run("systemd 257, ModeSystemdPerUse, no TPM: HeldUnderHostKey", func(t *testing.T) {
				wantServiceHolding(t, asService(t, serviceCredentialFolder(t, serviceAccount), ModeSystemdPerUse), HeldUnderHostKey, "HeldUnderHostKey")
			})
		})
		t.Run(lineServiceMode, func(t *testing.T) {
			t.Run("ModeContainer under a running systemd", func(t *testing.T) {
				serviceContainerFolder(t, keyText(rowKey(5)), "", rowKey(5))
				wantServiceRefused(t, asService(t, containerFolder, ModeContainer), SourceRefused)
			})
			t.Run("let through: ModeSystemdPerUse on systemd 257", func(t *testing.T) {
				wantServiceUnlocked(t, asService(t, serviceCredentialFolder(t, serviceAccount), ModeSystemdPerUse))
			})
		})
		t.Run(lineServiceKeyNotFound, func(t *testing.T) {
			t.Run("ModeSystemdPerUse with no credential", func(t *testing.T) {
				folder := serviceCredentialFolder(t, serviceAccount)
				removeItem(t, filepath.Join(folder, nameSystemdKey))
				wantServiceRefused(t, asService(t, folder, ModeSystemdPerUse), KeyNotFound)
			})
		})
		t.Run(lineServiceNotUnsealed, func(t *testing.T) {
			t.Run("systemd 257: a credential scoped to another account", func(t *testing.T) {
				wantServiceRefused(t, asService(t, serviceCredentialFolder(t, otherAccount), ModeSystemdPerUse), KeyNotUnsealed)
			})
			t.Run("systemd 257: the credential altered", func(t *testing.T) {
				folder := serviceCredentialFolder(t, serviceAccount)
				credential := filepath.Join(folder, nameSystemdKey)
				corruptCredential(t, credential)
				setOwnerAndMode(t, credential, serviceAccount, modeFile)
				wantServiceRefused(t, asService(t, folder, ModeSystemdPerUse), KeyNotUnsealed)
			})
		})
		t.Run(lineServiceLooser, func(t *testing.T) {
			t.Run("the credential at 0644", func(t *testing.T) {
				folder := serviceCredentialFolder(t, serviceAccount)
				credential := filepath.Join(folder, nameSystemdKey)
				chmodItem(t, credential, 0o644)
				wantLooserNaming(t, asService(t, folder, ModeSystemdPerUse), ItemOtherFile, credential)
			})
		})
	default:
		t.Fatalf("-bootstrap.systemd is %q: these rows run under systemd 252 or 257", *systemdUnder)
	}
}

// childOutput collects what a child writes, for a row that fails before it reports.
type childOutput struct {
	mutex   sync.Mutex
	written strings.Builder
}

func (output *childOutput) Write(data []byte) (int, error) {
	output.mutex.Lock()
	defer output.mutex.Unlock()
	return output.written.Write(data)
}

func (output *childOutput) String() string {
	output.mutex.Lock()
	defer output.mutex.Unlock()
	return output.written.String()
}

// startChild starts the command with its output collected, waits for it when the row ends,
// and returns a reader of what it wrote.
func startChild(t *testing.T, command *exec.Cmd) func() string {
	t.Helper()
	output := &childOutput{}
	command.Stdout, command.Stderr = output, output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Wait() })
	return output.String
}
