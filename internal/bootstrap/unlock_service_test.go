// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The approved tests for issue #90, UnlockForService, written by the QA session from the
// issue's behavior lines. Each group of rows quotes, word for word, the line its rows prove.
// UnlockForService refuses an elevated or root process and any account but the bootstrap
// folder's service account, so each unlock runs in a child: this test binary started again as
// the account the row names, which takes the folder and the mode from the row over a loopback
// socket, unlocks, reports what it got, and holds the handle until the row says to close it.
// The row itself runs as root or elevated, makes the folder by hand (the format's own writer,
// systemd-creds, the CNG key store), and makes the elevated and root rows directly. Linux rows
// run in containers through TestUnlockServiceRowsInContainer, the service account being
// nobody; Windows rows run elevated, the service account being LOCAL SERVICE, started by a
// scheduled task. Docker is required, not optional: a missing docker is a failure, never a
// skip.
package bootstrap

import (
	"encoding/json"
	"errors"
	"flag"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The lines, word for word.
const (
	lineServiceOrder          = "UnlockForService shall check the account first, then take the lock, then check the folder, the links and the permissions, then delete a half-made file, and only then unlock."
	lineServiceElevated       = "If the process runs elevated or as root, then UnlockForService shall refuse with WrongAccount."
	lineServiceAccountLinux   = "Where the server runs Linux, if the process runs under any account other than the one that owns the bootstrap folder, then UnlockForService shall refuse with WrongAccount."
	lineServiceAccountWindows = "Where the server runs Windows, if the process runs under any account that the bootstrap folder's access list does not name beside SYSTEM and Administrators, then UnlockForService shall refuse with WrongAccount."
	lineServiceInUse          = "If another handle holds the lock, then UnlockForService shall refuse with InUse."
	lineServiceLockMade       = "If bootstrap.lock is absent, then UnlockForService shall create it already set to its rule."
	lineServiceFolder         = "If the folder breaks a folder rule, then UnlockForService shall refuse with FolderRefused, naming the rule."
	lineServiceLink           = "If the bootstrap file or the key file is a symbolic link, a junction, or a file with more than one name, then UnlockForService shall refuse with Link."
	lineServiceLooser         = "If an item in the permission table is set looser than its rule, then UnlockForService shall refuse with LooserThanRule, naming the item and its path."
	lineServiceNotWritable    = "If the bootstrap file or the bootstrap folder is not writable by the service account, then UnlockForService shall refuse with NotWritable."
	lineServiceHalfMade       = "If bootstrap.hadv.new is in the folder, then UnlockForService shall delete it."
	lineServiceMode           = "If the mode is not one of this platform's, then UnlockForService shall refuse with SourceRefused."
	lineServiceNoKeySource    = "If the mode is ModeContainer and neither a Swarm secret nor a key file is present, then UnlockForService shall refuse with NoKeySource."
	lineServiceBothKeySources = "If the mode is ModeContainer and both a Swarm secret and a key file are present, then UnlockForService shall refuse with BothKeySources."
	lineServiceKeyNotFound    = "If the mode is not ModeContainer and the sealed-key file, the credential or the key file is absent, then UnlockForService shall refuse with KeyNotFound."
	lineServiceMalformed      = "If a key file or Swarm secret holds anything other than 32 bytes as base64 in 44 characters with at most one trailing newline, then UnlockForService shall refuse with KeyFileMalformed."
	lineServiceNotUnsealed    = "If the OS credential store does not unseal the bootstrap key, then UnlockForService shall refuse with KeyNotUnsealed."
	lineServiceFileNotFound   = "If the bootstrap file is absent, then UnlockForService shall refuse with FileNotFound."
	lineServiceHeldWindows    = "Where the server runs Windows, UnlockForService shall report HeldInTPM when the machine key pair is in the Microsoft Platform Crypto Provider, and HeldInSoftwareKeyStore otherwise."
	lineServiceHeldSystemd    = "Where the mode is ModeSystemdPerUse or ModeSystemdAtStart, UnlockForService shall report HeldInTPM when the credential is sealed under the TPM, and HeldUnderHostKey otherwise."
	lineServiceHeldFile       = "UnlockForService shall report HeldAsSwarmSecret for a Swarm secret and HeldInKeyFile for a key file."
	lineServiceHandle         = "When UnlockForService unlocks the bootstrap file, it shall return a handle that holds the lock until Close."
)

// childAddress is where the parent row listens: set by startService on the child it starts.
var childAddress = flag.String("bootstrap.child", "", "the row to report to: set by startService")

// serviceRequest is what a row asks its child to unlock.
type serviceRequest struct {
	Folder string
	Mode   KeyMode
}

// serviceReport is what the child got: a handle's fields and holding, a refusal, or another
// error as text.
type serviceReport struct {
	Unlocked bool
	Fields   Fields
	Holding  Holding
	Refusal  *Refusal
	Error    string
}

// err is the unlock's error as the row's helpers take it.
func (report serviceReport) err() error {
	switch {
	case report.Refusal != nil:
		return report.Refusal
	case report.Error != "":
		return errors.New(report.Error)
	}
	return nil
}

// TestUnlockServiceChild is the child startService runs as the row's account: it unlocks what
// the row asks, reports, and holds the handle until the row says to close it or goes away.
func TestUnlockServiceChild(t *testing.T) {
	t.Parallel()
	if *childAddress == "" {
		t.Skip("the service account's side of the UnlockForService rows, run by startService")
	}
	connection, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", *childAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	decoder, encoder := json.NewDecoder(connection), json.NewEncoder(connection)
	var request serviceRequest
	if err := decoder.Decode(&request); err != nil {
		t.Fatal(err)
	}
	handle, err := New().UnlockForService(t.Context(), request.Folder, request.Mode)
	report := serviceReport{}
	var refusal *Refusal
	switch {
	case errors.As(err, &refusal):
		report.Refusal = refusal
	case err != nil:
		report.Error = err.Error()
	}
	if handle != nil {
		report.Unlocked, report.Fields, report.Holding = true, handle.Fields(), handle.Holding()
		defer handle.Close()
	}
	if err := encoder.Encode(report); err != nil {
		t.Fatal(err)
	}
	// The row sends one message to close the handle; a row that ends without it closes the
	// connection, which ends the wait the same way.
	var closeNow struct{}
	_ = decoder.Decode(&closeNow) // either way the handle closes now
	if handle != nil {
		handle.Close()
	}
	_ = encoder.Encode("closed") // the row may have gone
}

// serviceProcess is a child holding what its unlock returned.
type serviceProcess struct {
	report  serviceReport
	encoder *json.Encoder
	decoder *json.Decoder
}

// startService starts the binary as the account, has it unlock the folder in the mode, and
// returns what it reported. The child holds a handle it got until close or the row's end.
func startService(t *testing.T, binary, account, folder string, mode KeyMode) *serviceProcess {
	t.Helper()
	listening, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, ok := listening.(*net.TCPListener)
	if !ok {
		t.Fatalf("a TCP listen gave %T", listening)
	}
	defer func() { _ = listener.Close() }()
	output := launchAs(t, binary, account, listener.Addr().String())
	// A child that cannot start never connects; the deadline turns that into a failure with
	// what the child wrote, never a hang.
	if err := listener.SetDeadline(time.Now().Add(2 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	connection, err := listener.Accept()
	if err != nil {
		t.Fatalf("the child as %s never reported: %v\n%s", account, err, output())
	}
	t.Cleanup(func() { _ = connection.Close() })
	process := &serviceProcess{encoder: json.NewEncoder(connection), decoder: json.NewDecoder(connection)}
	if err := process.encoder.Encode(serviceRequest{Folder: folder, Mode: mode}); err != nil {
		t.Fatal(err)
	}
	if err := process.decoder.Decode(&process.report); err != nil {
		t.Fatalf("reading the child's report: %v\n%s", err, output())
	}
	return process
}

// close has the child close its handle, and waits until it has.
func (process *serviceProcess) close(t *testing.T) {
	t.Helper()
	if err := process.encoder.Encode(struct{}{}); err != nil {
		t.Fatal(err)
	}
	var closed string
	if err := process.decoder.Decode(&closed); err != nil || closed != "closed" {
		t.Fatalf("the child did not close its handle: %q, %v", closed, err)
	}
}

// wantServiceUnlocked fails the row unless the child unlocked the bootstrap file and its
// handle held rowFields.
func wantServiceUnlocked(t *testing.T, process *serviceProcess) {
	t.Helper()
	if !process.report.Unlocked {
		t.Fatalf("refused: %v", process.report.err())
	}
	sameFields(t, process.report.Fields, rowFields())
}

// wantServiceHolding fails the row unless the child unlocked, reporting the holding.
func wantServiceHolding(t *testing.T, process *serviceProcess, want Holding, name string) {
	t.Helper()
	wantServiceUnlocked(t, process)
	if got := process.report.Holding; got != want {
		t.Errorf("Holding is %d, want %s (%d)", got, name, want)
	}
}

// wantServiceRefused fails the row unless the child was refused with the cause and got no
// handle.
func wantServiceRefused(t *testing.T, process *serviceProcess, cause Cause) {
	t.Helper()
	if process.report.Unlocked {
		t.Errorf("unlocked; want a refusal with cause %d", cause)
	}
	wantRefusal(t, process.report.err(), cause)
}

// wantLooserNaming fails the row unless the child was refused with LooserThanRule, naming the
// item and its path.
func wantLooserNaming(t *testing.T, process *serviceProcess, item Item, path string) {
	t.Helper()
	wantServiceRefused(t, process, LooserThanRule)
	if refusal := process.report.Refusal; refusal != nil && (refusal.Item != item || refusal.Path != path) {
		t.Errorf("named item %d at %q, want item %d at %q", refusal.Item, refusal.Path, item, path)
	}
}

// wantNotWritableNaming fails the row unless the child was refused with NotWritable, naming
// the path.
func wantNotWritableNaming(t *testing.T, process *serviceProcess, path string) {
	t.Helper()
	wantServiceRefused(t, process, NotWritable)
	if refusal := process.report.Refusal; refusal != nil && refusal.Path != path {
		t.Errorf("named %q, want %q", refusal.Path, path)
	}
}

// wantStillThere fails the row unless the item is still in place.
func wantStillThere(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err != nil {
		t.Errorf("%s is gone: %v", filepath.Base(path), err)
	}
}

// wantGone fails the row unless the item is gone.
func wantGone(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err == nil {
		t.Errorf("%s is still in the folder", filepath.Base(path))
	}
}

// linkInPlace moves the item to a folder beside its own, on the same volume, and puts a
// symbolic link to it, or a second name for it, in its place: the link is the only thing wrong.
func linkInPlace(t *testing.T, item string, hard bool) {
	t.Helper()
	beside, err := os.MkdirTemp(filepath.Dir(filepath.Dir(item)), "elsewhere-") //nolint:usetesting // on the item's own volume, which t.TempDir may not be
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(beside) })
	elsewhere := filepath.Join(beside, filepath.Base(item))
	if err := os.Rename(item, elsewhere); err != nil {
		t.Fatal(err)
	}
	link := os.Symlink
	if hard {
		link = os.Link
	}
	if err := link(elsewhere, item); err != nil {
		t.Fatal(err)
	}
}

// removeItem takes an item out of the folder.
func removeItem(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

// TestUnlockServiceRowsInContainer runs the Linux rows as root in containers, each unlock in a
// child as the account the row names: with no systemd, and with systemd 252 and 257 booted.
func TestUnlockServiceRowsInContainer(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker is required for the Linux rows: %v", err)
	}
	architecture, err := exec.CommandContext(t.Context(), "docker", "version", "--format", "{{.Server.Arch}}").Output()
	if err != nil {
		t.Fatalf("docker version: %v", err)
	}
	dir := t.TempDir()
	// The service account runs the binary too, so the folder it is mounted from is readable.
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // the service account in the container runs the binary mounted from here
		t.Fatal(err)
	}
	build := exec.CommandContext(t.Context(), "go", "test", "-c", "-o", filepath.Join(dir, "bootstrap.test"), ".")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+strings.TrimSpace(string(architecture)), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the tests for Linux: %v\n%s", err, out)
	}
	t.Run("no systemd", func(t *testing.T) {
		t.Parallel()
		runRows(t, "docker", "run", "--rm", "-v", dir+":/t:ro",
			"--mount", "type=volume,dst=/work", "--mount", "type=volume,dst=/var/lib/heliosadvance",
			"--tmpfs", "/mnt/tmpfs", rowImage,
			"/t/bootstrap.test", "-test.v", "-test.count=1", "-test.run", "^TestUnlockServiceLinuxAsRoot$", "-bootstrap.container")
	})
	for _, booted := range []struct{ image, under string }{
		{systemd252Image, systemdRunning252},
		{systemd257Image, systemdRunning257},
	} {
		t.Run("systemd "+strings.TrimPrefix(booted.under, "running-")+" running", func(t *testing.T) {
			t.Parallel()
			container := bootSystemd(t, booted.image, dir)
			runRows(t, "docker", "exec", container, "/t/bootstrap.test", "-test.v", "-test.count=1",
				"-test.run", "^TestUnlockServiceLinuxSystemd$", "-bootstrap.container", "-bootstrap.systemd="+booted.under)
		})
	}
}
