// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The approved tests for issue #87, Build's guards, the sysop's key and writing the file,
// written by the QA session from the issue's behavior lines. Each group of rows quotes, word
// for word, the line its rows prove. Build needs administrator or root rights, so the rows
// run where those rights are, as #86's do: Linux rows as root in containers, through
// TestBuildLinuxRowsInContainer, and Windows rows on an elevated machine (GitHub's Windows
// runner), with the NotElevated rows on one that is not. "Has systemd" is the running
// service manager, so the systemd rows boot real systemd in a privileged container: systemd
// 249 (below 250) and 252 (250 to 255), and 252 installed but not running. What Build wrote
// is read back by the bootstrap file oracle under the key the row gave it. Docker is
// required, not optional: a missing docker is a failure, never a skip.
package bootstrap

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The images the systemd rows run in, built from oracle/systemd-249 and oracle/systemd-252.
const (
	systemd249Image = "heliosestate/systemd-249-oracle:0.1"
	systemd252Image = "heliosestate/systemd-252-oracle:0.1"
)

// What -bootstrap.systemd tells the rows in a container about the systemd under them.
const (
	systemdRunning249   = "running-249"
	systemdRunning252   = "running-252"
	systemdInstalled252 = "installed-252"
)

// The lines, word for word.
const (
	lineBuildNotElevated      = "If the process is neither elevated nor root, then Build shall refuse with NotElevated."
	lineBuildInUse            = "If another handle holds the lock, then Build shall refuse with InUse."
	lineBuildFolder           = "If the folder breaks a folder rule, then Build shall refuse with FolderRefused, naming the rule."
	lineBuildField            = "If a field breaks a rule in the table on Fields, then Build shall refuse with FieldMalformed, naming the field."
	lineBuildFileExists       = "If a bootstrap file is in the folder and the path is FirstSetup or Joining, then Build shall refuse with FileExists."
	lineBuildKeyFileRefused   = "If the source is FromKeyFile where the server runs Windows or has systemd 250 or later, then Build shall refuse with SourceRefused."
	lineBuildContainerRefused = "If the source is FromContainer where the server runs Windows or Linux with systemd, then Build shall refuse with SourceRefused."
	lineBuildNoStore          = "If the source is FromOSStore where the server runs Linux without systemd 250 or later, then Build shall refuse with NoCredentialStore."
	lineBuildKeyFile          = "When the source is FromKeyFile, Build shall read the bootstrap key from bootstrap.key in the folder and return ModeKeyFile."
	lineBuildContainer        = "When the source is FromContainer, Build shall read the bootstrap key from the Swarm secret or the key file and return ModeContainer."
	lineBuildNoKeySource      = "If the source is FromContainer and neither a Swarm secret nor a key file is present, then Build shall refuse with NoKeySource."
	lineBuildBothKeySources   = "If the source is FromContainer and both a Swarm secret and a key file are present, then Build shall refuse with BothKeySources."
	lineBuildKeyNotFound      = "If the source is FromKeyFile and the key file is absent, then Build shall refuse with KeyNotFound."
	lineBuildLink             = "If the key file is a symbolic link or a file with more than one name, then Build shall refuse with Link."
	lineBuildMalformed        = "If a key file or Swarm secret holds anything other than 32 bytes as base64 in 44 characters with at most one trailing newline, then Build shall refuse with KeyFileMalformed."
	lineBuildNoKeyMade        = "When the source is FromKeyFile or FromContainer, Build shall make no bootstrap key and no machine key pair."
)

// rowKey is a key for the rows: its 32 bytes all one value, so that each row's key differs.
func rowKey(value byte) []byte { return bytes.Repeat([]byte{value}, 32) }

// keyText is a key as the sysop's key file holds it: base64 and one trailing newline.
func keyText(key []byte) string { return base64.StdEncoding.EncodeToString(key) + "\n" }

// rowFields is fields that break no rule in the table on Fields.
func rowFields() Fields {
	return Fields{
		Server:          7,
		Connection:      "host=database.example port=5432 dbname=helios",
		AccountName:     "helios_server_7",
		AccountPassword: []byte("a database password"),
		VaultKeys:       []VaultKey{{Version: 3, Key: rowKey(0x33)}},
		ReceivingKey:    []byte("the receiving key pair's private half"),
		SigningKey:      []byte("the signing key pair's private half"),
	}
}

func build(t *testing.T, folder string, fields Fields, path BuildPath, source KeySource) (KeyMode, error) {
	t.Helper()
	return New().Build(t.Context(), folder, fields, path, serviceAccount, source)
}

// TestBuildLinuxRowsInContainer runs the Linux rows as root in containers: the package's
// tests built for Linux, beside the oracle's program copied out of its image. With no
// systemd, the rows run in #86's pinned Debian as root, then the NotElevated row as nobody.
// The systemd rows run in each systemd image booted, and in the 252 image not booted.
func TestBuildLinuxRowsInContainer(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker is required for the Linux rows: %v", err)
	}
	architecture, err := exec.CommandContext(t.Context(), "docker", "version", "--format", "{{.Server.Arch}}").Output()
	if err != nil {
		t.Fatalf("docker version: %v", err)
	}
	dir := t.TempDir()
	// The account nobody runs the binary too, so the folder it is mounted from is readable.
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // nobody in the container reads the binary mounted from here
		t.Fatal(err)
	}
	build := exec.CommandContext(t.Context(), "go", "test", "-c", "-o", filepath.Join(dir, "bootstrap.test"), ".")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+strings.TrimSpace(string(architecture)), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the tests for Linux: %v\n%s", err, out)
	}
	copyOracleProgram(t, dir)

	t.Run("no systemd", func(t *testing.T) {
		t.Parallel()
		script := `status=0
chmod 1777 /work
/t/bootstrap.test -test.v -test.count=1 -test.run '^TestBuildLinuxAsRoot$' -bootstrap.container || status=1
setpriv --reuid=65534 --regid=65534 --clear-groups /t/bootstrap.test -test.v -test.count=1 -test.run '^TestBuildLinuxNotElevated$' -bootstrap.container || status=1
exit $status`
		runRows(t, "docker", "run", "--rm", "-v", dir+":/t:ro",
			"--mount", "type=volume,dst=/work", "--mount", "type=volume,dst=/var/lib/heliosadvance",
			"--tmpfs", "/mnt/tmpfs", rowImage, "sh", "-c", script)
	})
	t.Run("systemd 252 installed, not running", func(t *testing.T) {
		t.Parallel()
		runRows(t, "docker", "run", "--rm", "-v", dir+":/t:ro",
			"--mount", "type=volume,dst=/work", "--mount", "type=volume,dst=/var/lib/heliosadvance",
			systemd252Image, "/t/bootstrap.test", "-test.v", "-test.count=1", "-test.run", "^TestBuildLinuxSystemd$",
			"-bootstrap.container", "-bootstrap.systemd="+systemdInstalled252)
	})
	for _, booted := range []struct{ image, under string }{
		{systemd249Image, systemdRunning249},
		{systemd252Image, systemdRunning252},
	} {
		t.Run("systemd "+strings.TrimPrefix(booted.under, "running-")+" running", func(t *testing.T) {
			t.Parallel()
			container := bootSystemd(t, booted.image, dir)
			runRows(t, "docker", "exec", container, "/t/bootstrap.test", "-test.v", "-test.count=1",
				"-test.run", "^TestBuildLinuxSystemd$", "-bootstrap.container", "-bootstrap.systemd="+booted.under)
		})
	}
}

// runRows runs one container's rows and fails when any of them failed.
func runRows(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), name, args...).CombinedOutput()
	t.Logf("the rows:\n%s", out)
	if err != nil {
		t.Fatalf("the rows failed: %v", err)
	}
}

// copyOracleProgram copies the bootstrap file oracle's program out of its image into dir. It
// is built static, so it runs in any of the rows' containers.
func copyOracleProgram(t *testing.T, dir string) {
	t.Helper()
	created, err := exec.CommandContext(t.Context(), "docker", "create", oracleImage).Output()
	if err != nil {
		t.Fatalf("docker create %s: %v", oracleImage, err)
	}
	container := strings.TrimSpace(string(created))
	defer func() {
		_ = exec.Command("docker", "rm", container).Run() //nolint:noctx // removal must run even when the test's context has ended
	}()
	if out, err := exec.CommandContext(t.Context(), "docker", "cp", container+":/usr/local/bin/bootstrap-file", filepath.Join(dir, "bootstrap-file")).CombinedOutput(); err != nil {
		t.Fatalf("copying the oracle's program: %v\n%s", err, out)
	}
}

// bootSystemd starts the image with systemd as its first process, which needs a privileged
// container, waits until systemd has started, and stops it when the test ends.
func bootSystemd(t *testing.T, image, dir string) string {
	t.Helper()
	started, err := exec.CommandContext(t.Context(), "docker", "run", "-d", "--privileged", "--cgroupns=host",
		"-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw", "--tmpfs", "/run", "--tmpfs", "/run/lock",
		"-v", dir+":/t:ro", "--mount", "type=volume,dst=/work", "--mount", "type=volume,dst=/var/lib/heliosadvance",
		image, "/lib/systemd/systemd").Output()
	if err != nil {
		t.Fatalf("booting systemd in %s: %v", image, err)
	}
	container := strings.TrimSpace(string(started))
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", "-v", container).Run() //nolint:noctx // removal must run after the test's context has ended
	})
	// systemctl's --wait waits for a starting manager, not for one not yet started: asked
	// first, it says the system was not booted with systemd. So the wait is first for
	// /run/systemd/system, systemd's own sign that it runs, for up to a minute. Degraded is a
	// booted systemd too: a unit the container cannot start fails, and the manager runs
	// regardless.
	wait := `i=0; until [ -d /run/systemd/system ] || [ $i -ge 600 ]; do sleep 0.1; i=$((i+1)); done; systemctl is-system-running --wait`
	state, _ := exec.CommandContext(t.Context(), "docker", "exec", container, "sh", "-c", wait).CombinedOutput() //nolint:errcheck // degraded exits non-zero; the state is judged below
	lines := strings.Split(strings.TrimSpace(string(state)), "\n")
	if got := lines[len(lines)-1]; got != "running" && got != "degraded" {
		t.Fatalf("systemd in %s did not start:\n%s", image, state)
	}
	return container
}
