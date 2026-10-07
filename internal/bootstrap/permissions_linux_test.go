// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"bufio"
	"bytes"
	"flag"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The accounts in the Linux rows: the service account, and another.
const (
	serviceAccount = "nobody"
	otherAccount   = "daemon"
)

// The container's fixed places, as the package comment gives them, and the mounts
// TestLinuxRowsInContainer makes.
const (
	containerFolder = "/var/lib/heliosadvance"
	swarmSecret     = "/run/secrets/heliosadvance-bootstrap-key"
	volume          = "/work"      // ext4
	tmpfsMount      = "/mnt/tmpfs" // tmpfs
	overlayRoot     = "/tmp"       // the container's own root, overlayfs
)

// The modes on Linux, each item's rule for the service account.
const (
	looseSecret fs.FileMode = 0o444 // a Swarm secret's mode by default, looser than its rule
	modeFolder  fs.FileMode = 0o700
	modeFile    fs.FileMode = 0o600
	modeKeyFile fs.FileMode = 0o400
)

// The Linux rows other lines share, by Check's and the unlocks' rows alike: one name for each
// case, so the same case reads the same under every line.
const (
	rowFile0644            = "the bootstrap file at 0644"
	rowLock0644            = "the lock at 0644"
	rowMachineKeyPairLinux = "ModeMachineKeyPair on Linux"
)

// inContainer is set by TestLinuxRowsInContainer when it runs this package's tests inside
// the container; the Linux rows skip without it, since they run as root there instead.
var inContainer = flag.Bool("bootstrap.container", false, "run the Linux rows: set inside the test container")

func requireContainer(t *testing.T) {
	t.Helper()
	if !*inContainer {
		t.Skip("runs inside the test container, through TestLinuxRowsInContainer")
	}
}

// linuxFolder is a bootstrap folder for the rows: its path and the items in it.
type linuxFolder struct {
	path  string
	items map[string]Item // path to item, the folder included
}

// itemPaths is every item's path in the folder, the folder first.
func (folder linuxFolder) itemPaths() []string {
	paths := []string{folder.path}
	for path := range folder.items {
		if path != folder.path {
			paths = append(paths, path)
		}
	}
	return paths
}

// makeFolder makes a bootstrap folder under parent for the mode, every item set to its rule
// for the account. Under ModeContainer the folder is the container's fixed one, emptied, and
// with secret the Swarm secret takes the place of the key file.
func makeFolder(t *testing.T, parent string, mode KeyMode, account string, secret bool) linuxFolder {
	t.Helper()
	var path string
	if mode == ModeContainer {
		path = containerFolder
		entries, err := os.ReadDir(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if err := os.RemoveAll(filepath.Join(path, entry.Name())); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.RemoveAll(swarmSecret); err != nil {
			t.Fatal(err)
		}
	} else {
		var err error
		if path, err = os.MkdirTemp(parent, "folder-"); err != nil { //nolint:usetesting // on the file system the row names; t.TempDir is on overlayfs
			t.Fatal(err)
		}
	}
	folder := linuxFolder{path: path, items: map[string]Item{path: ItemFolder}}
	setOwnerAndMode(t, path, account, modeFolder)
	files := map[string]Item{nameFile: ItemFile, nameLock: ItemOtherFile}
	switch {
	case mode == ModeSystemdPerUse || mode == ModeSystemdAtStart:
		files[nameSystemdKey] = ItemOtherFile
	case mode == ModeKeyFile || mode == ModeContainer && !secret:
		files[nameKeyFile] = ItemKeyFile
	}
	for name, item := range files {
		file := filepath.Join(path, name)
		writeItem(t, file, name, account, ruleMode(item))
		folder.items[file] = item
	}
	if mode == ModeContainer && secret {
		if err := os.MkdirAll(filepath.Dir(swarmSecret), 0o755); err != nil { //nolint:gosec // /run/secrets, as Docker makes it
			t.Fatal(err)
		}
		writeItem(t, swarmSecret, "secret", account, modeKeyFile)
		folder.items[swarmSecret] = ItemSwarmSecret
	}
	return folder
}

func ruleMode(item Item) fs.FileMode {
	switch item {
	case ItemFolder:
		return modeFolder
	case ItemKeyFile, ItemSwarmSecret:
		return modeKeyFile
	default:
		return modeFile
	}
}

func linuxRule(item Item, account string) Permissions {
	return Permissions{Owner: account, Mode: ruleMode(item)}
}

func writeItem(t *testing.T, path, contents, account string, mode fs.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	setOwnerAndMode(t, path, account, mode)
}

func setOwnerAndMode(t *testing.T, path, account string, mode fs.FileMode) {
	t.Helper()
	found, err := user.Lookup(account)
	if err != nil {
		t.Fatal(err)
	}
	userID, err := strconv.Atoi(found.Uid)
	if err != nil {
		t.Fatal(err)
	}
	groupID, err := strconv.Atoi(found.Gid)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(path, userID, groupID); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// statPermissions is the oracle: each path's owner and mode, as stat reports them.
func statPermissions(t *testing.T, paths ...string) map[string]Permissions {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "stat", append([]string{"-c", "%n|%U|%a"}, paths...)...).Output()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	found := map[string]Permissions{}
	for line := range strings.Lines(string(out)) {
		fields := strings.Split(strings.TrimSpace(line), "|")
		mode, err := strconv.ParseUint(fields[2], 8, 32)
		if err != nil {
			t.Fatal(err)
		}
		found[fields[0]] = Permissions{Owner: fields[1], Mode: fs.FileMode(mode)}
	}
	return found
}

// snapshot is every item's permissions and every file's bytes.
type snapshot struct {
	permissions map[string]Permissions
	contents    map[string][]byte
}

func takeSnapshot(t *testing.T, paths []string) snapshot {
	t.Helper()
	taken := snapshot{permissions: statPermissions(t, paths...), contents: map[string][]byte{}}
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			taken.contents[path] = data
		}
	}
	return taken
}

// sameExcept fails the row when anything in before but the path given has changed.
func sameExcept(t *testing.T, before, after snapshot, except string) {
	t.Helper()
	for path, was := range before.permissions {
		if path != except && !samePermissions(after.permissions[path], was) {
			t.Errorf("%s changed: %+v, was %+v", path, after.permissions[path], was)
		}
	}
	for path, was := range before.contents {
		if !bytes.Equal(after.contents[path], was) {
			t.Errorf("%s's bytes changed", path)
		}
	}
}

// findingFor is the finding the oracle expects for the item at path.
func findingFor(t *testing.T, folder linuxFolder, path, account string) Finding {
	t.Helper()
	item := folder.items[path]
	return Finding{Item: item, Path: path, Found: statPermissions(t, path)[path], Rule: linuxRule(item, account)}
}

// TestLinuxNotElevated runs as the account nobody, through setpriv.
func TestLinuxNotElevated(t *testing.T) {
	t.Parallel()
	requireContainer(t)
	folder := makeOwnFolder(t)
	t.Run(lineCheckNotElevated, func(t *testing.T) {
		t.Parallel()
		_, err := New().Check(folder, ModeKeyFile, serviceAccount)
		wantRefusal(t, err, NotElevated)
	})
	t.Run(lineSetToRuleNotElevated, func(t *testing.T) {
		t.Parallel()
		err := New().SetToRule(Finding{Item: ItemFile, Path: filepath.Join(folder, nameFile)}, serviceAccount)
		wantRefusal(t, err, NotElevated)
	})
}

// makeOwnFolder makes a folder that holds to every rule, as the account the process runs
// as, which needs no rights: only the missing rights are wrong.
func makeOwnFolder(t *testing.T) string {
	t.Helper()
	folder, err := os.MkdirTemp(volume, "own-") //nolint:usetesting // on the ext4 volume; t.TempDir is on overlayfs
	if err != nil {
		t.Fatal(err)
	}
	for name, mode := range map[string]fs.FileMode{nameFile: modeFile, nameLock: modeFile, nameKeyFile: modeKeyFile} {
		if err := os.WriteFile(filepath.Join(folder, name), []byte(name), mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(folder, modeFolder); err != nil {
		t.Fatal(err)
	}
	return folder
}

// TestLinuxAsRoot is every Linux row but NotElevated. The rows run one after another: those
// under ModeContainer share the container's one fixed folder and Swarm secret.
//
//nolint:paralleltest // the rows under ModeContainer share the container's fixed folder
func TestLinuxAsRoot(t *testing.T) {
	requireContainer(t)
	if os.Getuid() != 0 {
		t.Fatalf("the Linux rows run as root; running as uid %d", os.Getuid())
	}

	t.Run(lineCheckFolder, func(t *testing.T) {
		good := makeFolder(t, volume, ModeKeyFile, serviceAccount, false).path
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
			{rowTmpfs, makeFolder(t, tmpfsMount, ModeKeyFile, serviceAccount, false).path, FileSystem},
			{rowOverlayfs, makeFolder(t, overlayRoot, ModeKeyFile, serviceAccount, false).path, FileSystem},
		} {
			t.Run(row.name, func(t *testing.T) {
				_, err := New().Check(row.folder, ModeKeyFile, serviceAccount)
				wantFolderRefused(t, err, row.rule)
			})
		}
		t.Run("let through: a folder on ext4", func(t *testing.T) {
			findings, err := New().Check(good, ModeKeyFile, serviceAccount)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			sameFindings(t, findings, nil)
		})
	})

	t.Run(lineCheckFinding, func(t *testing.T) {
		for _, row := range []struct {
			name   string
			mode   KeyMode
			secret bool
			loosen func(t *testing.T, folder linuxFolder) []string // the items it loosened
		}{
			{rowFolder0755, ModeKeyFile, false, chmodRow(0o755, "")},
			{"the folder owned by root", ModeKeyFile, false, chownRow("root", "")},
			{"the bootstrap file at 0640", ModeKeyFile, false, chmodRow(0o640, nameFile)},
			{"the bootstrap file owned by root", ModeKeyFile, false, chownRow("root", nameFile)},
			{rowLock0644, ModeKeyFile, false, chmodRow(0o644, nameLock)},
			{"the credential file at 0644", ModeSystemdAtStart, false, chmodRow(0o644, nameSystemdKey)},
			{"the key file at 0600", ModeKeyFile, false, chmodRow(0o600, nameKeyFile)},
			{"the Swarm secret at 0444", ModeContainer, true, func(t *testing.T, _ linuxFolder) []string {
				t.Helper()
				if err := os.Chmod(swarmSecret, looseSecret); err != nil {
					t.Fatal(err)
				}
				return []string{swarmSecret}
			}},
			{"two at once: the folder at 0755 and the bootstrap file at 0644", ModeKeyFile, false, func(t *testing.T, folder linuxFolder) []string {
				t.Helper()
				return append(chmodRow(0o755, "")(t, folder), chmodRow(0o644, nameFile)(t, folder)...)
			}},
		} {
			t.Run(row.name, func(t *testing.T) {
				folder := makeFolder(t, volume, row.mode, serviceAccount, row.secret)
				var want []Finding
				for _, path := range row.loosen(t, folder) {
					want = append(want, findingFor(t, folder, path, serviceAccount))
				}
				findings, err := New().Check(checkPath(folder, row.mode), row.mode, serviceAccount)
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				sameFindings(t, findings, want)
			})
		}
	})

	t.Run(lineCheckNoFinding, func(t *testing.T) {
		for _, row := range []struct {
			name   string
			mode   KeyMode
			secret bool
			adjust func(t *testing.T, folder linuxFolder) []string
		}{
			{"under ModeKeyFile", ModeKeyFile, false, nil},
			{"under ModeSystemdPerUse", ModeSystemdPerUse, false, nil},
			{"under ModeSystemdAtStart", ModeSystemdAtStart, false, nil},
			{"under ModeContainer with a Swarm secret", ModeContainer, true, nil},
			{"under ModeContainer with a key file", ModeContainer, false, nil},
			{"let through, stricter than the rule: the folder at 0500 and the bootstrap file at 0400", ModeKeyFile, false, func(t *testing.T, folder linuxFolder) []string {
				t.Helper()
				return append(chmodRow(0o500, "")(t, folder), chmodRow(0o400, nameFile)(t, folder)...)
			}},
		} {
			t.Run(row.name, func(t *testing.T) {
				folder := makeFolder(t, volume, row.mode, serviceAccount, row.secret)
				if row.adjust != nil {
					row.adjust(t, folder)
				}
				findings, err := New().Check(checkPath(folder, row.mode), row.mode, serviceAccount)
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				sameFindings(t, findings, nil)
			})
		}
	})

	t.Run(lineCheckAccount, func(t *testing.T) {
		t.Run("every item set for nobody, checked as daemon", func(t *testing.T) {
			folder := makeFolder(t, volume, ModeKeyFile, serviceAccount, false)
			var want []Finding
			for _, path := range folder.itemPaths() {
				want = append(want, findingFor(t, folder, path, otherAccount))
			}
			findings, err := New().Check(folder.path, ModeKeyFile, otherAccount)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			sameFindings(t, findings, want)
		})
	})

	t.Run(lineCheckLock, func(t *testing.T) {
		t.Run("the lock held by another process with flock and fcntl", func(t *testing.T) {
			folder := makeFolder(t, volume, ModeKeyFile, serviceAccount, false)
			release := holdLock(t, filepath.Join(folder.path, nameLock))
			defer release()
			done := make(chan error, 1)
			go func() {
				_, err := New().Check(folder.path, ModeKeyFile, serviceAccount)
				done <- err
			}()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Check did not return within 10 seconds while another process held the lock")
			}
		})
	})

	t.Run(lineSetToRuleSets, func(t *testing.T) {
		for _, row := range []struct {
			name   string
			loosen func(t *testing.T, folder linuxFolder) []string
		}{
			{rowFolder0755, chmodRow(0o755, "")},
			{rowFile0644, chmodRow(0o644, nameFile)},
			{rowLock0644, chmodRow(0o644, nameLock)},
			{"the key file at 0644", chmodRow(0o644, nameKeyFile)},
			{"the bootstrap file owned by root", chownRow("root", nameFile)},
		} {
			t.Run(row.name, func(t *testing.T) {
				folder := makeFolder(t, volume, ModeKeyFile, serviceAccount, false)
				path := row.loosen(t, folder)[0]
				item := folder.items[path]
				before := takeSnapshot(t, folder.itemPaths())
				if err := New().SetToRule(Finding{Item: item, Path: path}, serviceAccount); err != nil {
					t.Fatalf("refused: %v", err)
				}
				after := takeSnapshot(t, folder.itemPaths())
				if got, want := after.permissions[path], linuxRule(item, serviceAccount); !samePermissions(got, want) {
					t.Errorf("%s is %+v after SetToRule, want its rule %+v", path, got, want)
				}
				sameExcept(t, before, after, path)
			})
		}
	})

	t.Run(lineSetToRuleLink, func(t *testing.T) {
		for _, row := range []struct {
			name string
			item Item
		}{
			{"the bootstrap file, a symbolic link to a file at 0644", ItemFile},
			{"the folder, a symbolic link to a folder at 0755", ItemFolder},
		} {
			t.Run(row.name, func(t *testing.T) {
				folder := makeFolder(t, volume, ModeKeyFile, serviceAccount, false)
				target := filepath.Join(folder.path, nameFile)
				link := filepath.Join(folder.path, "link")
				if row.item == ItemFolder {
					target, link = folder.path, filepath.Join(volume, "link-"+filepath.Base(folder.path))
				}
				if err := os.Chmod(target, map[Item]fs.FileMode{ItemFile: 0o644, ItemFolder: 0o755}[row.item]); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
				before := takeSnapshot(t, folder.itemPaths())
				wantRefusal(t, New().SetToRule(Finding{Item: row.item, Path: link}, serviceAccount), Link)
				sameExcept(t, before, takeSnapshot(t, folder.itemPaths()), "")
			})
		}
		t.Run("the bootstrap file at 0644, with a second name outside the folder", func(t *testing.T) {
			folder := makeFolder(t, volume, ModeKeyFile, serviceAccount, false)
			file := filepath.Join(folder.path, nameFile)
			if err := os.Chmod(file, 0o644); err != nil { //nolint:gosec // the row sets the file looser than its rule, so a SetToRule that went ahead would show
				t.Fatal(err)
			}
			if err := os.Link(file, filepath.Join(volume, "second-"+filepath.Base(folder.path))); err != nil {
				t.Fatal(err)
			}
			before := takeSnapshot(t, folder.itemPaths())
			wantRefusal(t, New().SetToRule(Finding{Item: ItemFile, Path: file}, serviceAccount), Link)
			sameExcept(t, before, takeSnapshot(t, folder.itemPaths()), "")
		})
	})

	t.Run(lineCheckLink, func(t *testing.T) {
		for _, row := range []struct {
			name string
			file string
			item Item
		}{
			{"the bootstrap file, with a second name outside the folder", nameFile, ItemFile},
			{"the lock file, with a second name outside the folder", nameLock, ItemOtherFile},
		} {
			t.Run(row.name, func(t *testing.T) {
				folder := makeFolder(t, volume, ModeKeyFile, serviceAccount, false)
				file := filepath.Join(folder.path, row.file)
				if err := os.Link(file, filepath.Join(volume, "second-"+filepath.Base(folder.path))); err != nil {
					t.Fatal(err)
				}
				_, err := New().Check(folder.path, ModeKeyFile, serviceAccount)
				wantLinkNaming(t, err, row.item, file)
			})
		}
		t.Run("let through: every file with one name", func(t *testing.T) {
			folder := makeFolder(t, volume, ModeKeyFile, serviceAccount, false)
			findings, err := New().Check(folder.path, ModeKeyFile, serviceAccount)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			sameFindings(t, findings, nil)
		})
	})

	t.Run(lineSetToRuleSwarm, func(t *testing.T) {
		t.Run("the Swarm secret at 0444", func(t *testing.T) {
			folder := makeFolder(t, volume, ModeContainer, serviceAccount, true)
			if err := os.Chmod(swarmSecret, looseSecret); err != nil {
				t.Fatal(err)
			}
			before := takeSnapshot(t, folder.itemPaths())
			wantRefusal(t, New().SetToRule(Finding{Item: ItemSwarmSecret, Path: swarmSecret}, serviceAccount), LooserThanRule)
			sameExcept(t, before, takeSnapshot(t, folder.itemPaths()), "")
		})
	})
}

// checkPath is the folder Check is given: under ModeContainer it is ignored for the fixed
// path, so it is empty.
func checkPath(folder linuxFolder, mode KeyMode) string {
	if mode == ModeContainer {
		return ""
	}
	return folder.path
}

// chmodRow sets the named file's mode, or the folder's when the name is empty.
func chmodRow(mode fs.FileMode, name string) func(t *testing.T, folder linuxFolder) []string {
	return func(t *testing.T, folder linuxFolder) []string {
		t.Helper()
		path := filepath.Join(folder.path, name)
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return []string{path}
	}
}

// chownRow gives the named file, or the folder when the name is empty, another owner.
func chownRow(account, name string) func(t *testing.T, folder linuxFolder) []string {
	return func(t *testing.T, folder linuxFolder) []string {
		t.Helper()
		path := filepath.Join(folder.path, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		setOwnerAndMode(t, path, account, info.Mode().Perm())
		return []string{path}
	}
}

// holdLock has another process hold the file locked every usual way, flock and fcntl, until
// release: a child running this test binary as TestLinuxHoldLock.
func holdLock(t *testing.T, path string) (release func()) {
	t.Helper()
	child := exec.CommandContext(t.Context(), os.Args[0], //nolint:gosec // this test binary, run again as the lock's holder
		"-test.run", "^TestLinuxHoldLock$", "-bootstrap.container", "-bootstrap.hold", path)
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	lines := bufio.NewScanner(stdout)
	for lines.Scan() && lines.Text() != "held" {
	}
	if lines.Err() != nil {
		t.Fatal(lines.Err())
	}
	return func() {
		_ = stdin.Close()
		_ = child.Wait()
	}
}

var holdPath = flag.String("bootstrap.hold", "", "the lock file TestLinuxHoldLock holds: set by holdLock")

// TestLinuxHoldLock is the child holdLock runs: it holds the lock until its input closes.
func TestLinuxHoldLock(t *testing.T) {
	t.Parallel()
	if *holdPath == "" {
		t.Skip("the child of the lock row, run by holdLock")
	}
	file, err := os.OpenFile(*holdPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if err := syscall.FcntlFlock(file.Fd(), syscall.F_SETLK, &syscall.Flock_t{Type: syscall.F_WRLCK}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stdout.WriteString("held\n"); err != nil {
		t.Fatal(err)
	}
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}
