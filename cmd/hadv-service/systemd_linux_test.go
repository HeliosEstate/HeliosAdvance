// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

const (
	// daemonUser is the account the page's unit runs the engine as.
	daemonUser = "hadv"
	// bindServiceOnly is CAP_NET_BIND_SERVICE alone, bit 10, as /proc writes a capability set.
	bindServiceOnly = "0000000000000400"
	// unitPrefix starts the name of every unit, program folder and bootstrap folder a row
	// installs, so a run killed with one installed leaves it for the next run to take.
	unitPrefix = "hadv-qa-"
	// unitPoll is how often a row reads the unit's state: systemd announces no change to a reader
	// that does not subscribe to its bus.
	unitPoll = 100 * time.Millisecond
	// failedState is how systemd names the ActiveState of a unit whose start or run failed.
	failedState = "failed"
)

// unitTemplate is the page's unit: Type=notify, so systemd waits for READY=1 before it counts the
// service started, run as hadv with the right to bind ports below 1024 and nothing else. The
// first verb is the command line, the second any environment.
const unitTemplate = `[Unit]
Description=Helios Advance, installed by a test row

[Service]
Type=notify
User=hadv
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ExecStart=%s
%s`

// systemdUnit is a unit of a row's own: its name, and the folders that hold the program and the
// bootstrap folder.
type systemdUnit struct {
	name      string
	library   string
	bootstrap string
}

// newUnit names a unit of the row's own and makes its folders: the program's and its lang
// folder, root's, and the bootstrap folder sealing settings, hadv's alone. The row's end stops and
// removes the unit and its folders.
func newUnit(t *testing.T, settings connectionFile) *systemdUnit {
	t.Helper()
	if buildFailure != nil {
		t.Fatalf("the program did not build: %v", buildFailure)
	}
	expectPort23FreeLinux(t)
	name := unitPrefix + strings.ToLower(rand.Text()[:10])
	unit := &systemdUnit{name: name, library: "/usr/local/lib/" + name, bootstrap: "/var/lib/" + name}
	t.Cleanup(func() { removeUnit(t, unit.name) })
	sudo(t, "install", "-d", "-m", "0755", "-o", "root", "-g", "root", unit.library)
	sudo(t, "install", "-m", "0755", "-o", "root", "-g", "root", programPath, unit.program())
	// The shipped lang folder beside the program, root's and readable by everyone, as the program.
	err := filepath.WalkDir(shippedLang, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(shippedLang, path)
		if err != nil {
			return err
		}
		target := filepath.Join(unit.library, langFolder, relative)
		if entry.IsDir() {
			sudo(t, "install", "-d", "-m", "0755", "-o", "root", "-g", "root", target)
		} else {
			sudo(t, "install", "-m", "0644", "-o", "root", "-g", "root", path, target)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("installing the shipped lang folder beside the program: %v", err)
	}
	made := settings.seal(t)
	sudo(t, "install", "-d", "-m", "0700", "-o", daemonUser, "-g", daemonUser, unit.bootstrap)
	unit.installFile(t, made.file, bootstrapFileName)
	unit.installFile(t, made.keyFile, keyFileName)
	return unit
}

// expectPort23FreeLinux fails the row, as one that cannot run, when anything on the machine
// listens on port 23. An ordinary user cannot listen there to find out, so it reads the system's
// table of sockets, every process's.
func expectPort23FreeLinux(t *testing.T) {
	t.Helper()
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		text, err := os.ReadFile(table)
		if err != nil {
			t.Fatalf("reading the socket table %s: %v", table, err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(text)), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			if address := tableAddress(t, fields[1]); strings.HasSuffix(address, ":23") {
				t.Fatalf("%s is held on this machine, so this row cannot run", address)
			}
		}
	}
}

func (unit *systemdUnit) program() string {
	return unit.library + "/hadv-service"
}

// installFile copies a file into the bootstrap folder, hadv's and readable by hadv alone, and
// returns its path there.
func (unit *systemdUnit) installFile(t *testing.T, from, name string) string {
	t.Helper()
	path := filepath.Join(unit.bootstrap, name)
	sudo(t, "install", "-m", "0600", "-o", daemonUser, "-g", daemonUser, from, path)
	return path
}

// install writes the unit, with the given options after the bootstrap folder on its command line.
// Under the race detector its environment keeps the program's exit from sleeping a second.
func (unit *systemdUnit) install(t *testing.T, options ...string) {
	t.Helper()
	commandLine := strings.Join(append([]string{unit.program(), databaseOption, unit.bootstrap}, options...), " ")
	environment := ""
	if testrun.Race {
		environment = "Environment=GORACE=atexit_sleep_ms=0\n"
	}
	unitFile := filepath.Join(t.TempDir(), unit.name+".service")
	if err := os.WriteFile(unitFile, fmt.Appendf(nil, unitTemplate, commandLine, environment), 0o600); err != nil {
		t.Fatalf("writing the unit: %v", err)
	}
	sudo(t, "install", "-m", "0644", "-o", "root", "-g", "root", unitFile, "/etc/systemd/system/"+unit.name+".service")
	sudo(t, "systemctl", "daemon-reload")
}

// start asks systemd to start the unit and returns at once: systemctl start would wait for READY=1.
func (unit *systemdUnit) start(t *testing.T) {
	t.Helper()
	sudo(t, "systemctl", "start", "--no-block", unit.name+".service")
}

// property reads one of the unit's properties as systemd holds it.
func (unit *systemdUnit) property(t *testing.T, name string) string {
	t.Helper()
	return strings.TrimSpace(sudo(t, "systemctl", "show", "--property="+name, "--value", unit.name+".service"))
}

// awaitActiveState reads the unit's ActiveState until it is the one wanted, by the deadline, and
// returns when it was read. A unit that ends failed or inactive meanwhile fails the row at once.
func (unit *systemdUnit) awaitActiveState(t *testing.T, want string, deadline time.Time) time.Time {
	t.Helper()
	for {
		state := unit.property(t, "ActiveState")
		if state == want {
			return time.Now()
		}
		if state == failedState || state == "inactive" {
			t.Fatalf("the unit is %s where it was to be %s; its journal:\n%s", state, want, unit.journal(t))
		}
		if time.Now().After(deadline) {
			t.Fatalf("the unit was still %s at %v; want %s; its journal:\n%s", state, deadline.Format(time.RFC3339Nano), want, unit.journal(t))
		}
		pause(t, unitPoll)
	}
}

// awaitFailed waits, up to the hang bound, for the unit to end failed.
func (unit *systemdUnit) awaitFailed(t *testing.T) {
	t.Helper()
	giveUp := time.Now().Add(testrun.Patient(testrun.HangBound))
	for {
		state := unit.property(t, "ActiveState")
		if state == failedState {
			return
		}
		if state == "active" {
			t.Fatalf("the unit became active where SSH could not listen; its journal:\n%s", unit.journal(t))
		}
		if time.Now().After(giveUp) {
			t.Fatalf("the unit was still %s %v on; want failed; its journal:\n%s", state, testrun.Patient(testrun.HangBound), unit.journal(t))
		}
		pause(t, unitPoll)
	}
}

// holdActiveState reads the unit's ActiveState until the moment given, at least once, and checks
// every read is the one wanted.
func (unit *systemdUnit) holdActiveState(t *testing.T, want string, until time.Time) {
	t.Helper()
	for {
		if state := unit.property(t, "ActiveState"); state != want {
			t.Fatalf("the unit is %s; want %s until %v; its journal:\n%s", state, want, until.Format(time.RFC3339Nano), unit.journal(t))
		}
		if time.Now().After(until) {
			return
		}
		pause(t, unitPoll)
	}
}

// journal is what the unit's own processes wrote to standard output and standard error, which
// systemd keeps in the journal: the local log, as the sysop reads it.
func (unit *systemdUnit) journal(t *testing.T) string {
	t.Helper()
	text := sudo(t, "journalctl", "--no-pager", "--output=cat", "_SYSTEMD_UNIT="+unit.name+".service", "_TRANSPORT=stdout")
	if strings.HasPrefix(text, "-- No entries --") {
		return ""
	}
	return text
}

// awaitJournalLines waits, up to the hang bound, for the journal to hold count lines, since the
// journal takes a line some time after the program writes it, and returns its text.
func (unit *systemdUnit) awaitJournalLines(t *testing.T, count int) string {
	t.Helper()
	bound := testrun.Patient(testrun.HangBound)
	giveUp := time.Now().Add(bound)
	for {
		text := unit.journal(t)
		if strings.Count(text, "\n") >= count {
			return text
		}
		if time.Now().After(giveUp) {
			t.Fatalf("the journal held %q %v on, want %d lines", text, bound, count)
		}
		pause(t, unitPoll)
	}
}

// removeUnit stops the unit, removes it and its folders, and reads back that systemd no longer
// knows it. A failure here is reported, not fatal: it is the row's cleanup.
func removeUnit(t *testing.T, name string) {
	t.Helper()
	// Asked, not waited on: systemctl stop waits up to systemd's own 90 seconds for an engine that
	// ignores its stop signal, past the hang bound, so the stop is read here and, where it does not
	// come, the unit's processes are killed.
	_, _ = runSudo(t, "systemctl", "stop", "--no-block", name+".service")
	bound := testrun.Patient(testrun.HangBound)
	for giveUp, killed := time.Now().Add(bound), false; ; {
		_, state := runSudo(t, "systemctl", "show", "--property=ActiveState", "--value", name+".service")
		if state = strings.TrimSpace(state); state == "inactive" || state == failedState {
			break
		}
		if time.Now().After(giveUp) {
			if killed {
				t.Errorf("the unit %s was still %s %v after its processes were killed", name, state, bound)
				break
			}
			_, _ = runSudo(t, "systemctl", "kill", "--signal=KILL", name+".service")
			killed, giveUp = true, time.Now().Add(bound)
		}
		pause(t, unitPoll)
	}
	for _, arguments := range [][]string{
		{"rm", "-f", "/etc/systemd/system/" + name + ".service"},
		{"rm", "-rf", "/usr/local/lib/" + name, "/var/lib/" + name},
		{"systemctl", "daemon-reload"},
	} {
		if code, output := runSudo(t, arguments...); code != 0 {
			t.Errorf("sudo %s ended %d: %s", strings.Join(arguments, " "), code, output)
		}
	}
	// A unit that failed stays known until its failure is reset; one that did not has nothing to
	// reset, which systemctl reports as a failure of its own.
	_, _ = runSudo(t, "systemctl", "reset-failed", name+".service")
	if code, output := runSudo(t, "systemctl", "show", "--property=LoadState", "--value", name+".service"); code != 0 || strings.TrimSpace(output) != "not-found" {
		t.Errorf("systemd still knows the unit %s after its removal: %d %s", name, code, output)
	}
}

// sudo runs a command as root without a password, up to the hang bound, and fails the row when
// it fails.
func sudo(t *testing.T, arguments ...string) string {
	t.Helper()
	code, output := runSudo(t, arguments...)
	if code != 0 {
		t.Fatalf("sudo %s ended %d: %s", strings.Join(arguments, " "), code, output)
	}
	return output
}

// sudoTimedOut is the exit code runSudo gives a command it ended at its bound: no command ends
// with it.
const sudoTimedOut = -1

// runSudo runs a command as root without a password, up to the hang bound, and returns its exit
// code and output, or sudoTimedOut and what it wrote by then. A hung command is not fatal here, so
// a cleanup goes on to its next step. Its context is not the row's, which has ended by the time a
// cleanup runs.
func runSudo(t *testing.T, arguments ...string) (int, string) {
	t.Helper()
	bound := testrun.Patient(testrun.HangBound)
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()
	command := exec.CommandContext(ctx, "sudo", append([]string{"-n"}, arguments...)...)
	command.WaitDelay = bound
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		return sudoTimedOut, fmt.Sprintf("sudo %s had not ended within %v: %s", strings.Join(arguments, " "), bound, output)
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), string(output)
	}
	if err != nil {
		t.Fatalf("running sudo %s: %v", strings.Join(arguments, " "), err)
	}
	return 0, string(output)
}

// startLockedUnit installs a unit on a board of the row's own whose row the test has locked,
// starts it, and returns the unit, the lock and when the server logged the engine's first try. A
// test that reads the try too near the try's own end cannot tell what came before it, and fails
// as one that cannot tell.
func startLockedUnit(t *testing.T) (*systemdUnit, *rowLock, time.Time) {
	t.Helper()
	server := sharedServer(t)
	created := server.newBoard(t)
	lock := created.lockRow(t)
	unit := newUnit(t, created.file())
	unit.install(t)
	since := time.Now()
	unit.start(t)
	tried := server.waitForTry(t, created.login, since, time.Now().Add(testrun.Patient(testrun.HangBound)))
	if time.Now().After(tried.Add(tryLimit - leaseMargin)) {
		t.Fatalf("cannot tell: the test read the engine's first try %v after it, too near the try's own end", time.Since(tried))
	}
	return unit, lock, tried
}

// TestLinuxRootSystemd runs alone, its rows one after the other: each installs a unit that listens
// on port 23, which only one program on the machine can hold. It needs root through sudo without
// a password, as CI's Linux runners allow, to make the account and install the units.
func TestLinuxRootSystemd(t *testing.T) { //nolint:paralleltest // it must run alone
	if code, output := runSudo(t, "true"); code != 0 {
		t.Fatalf("these rows need root through sudo without a password: %s", output)
	}
	// A run killed with a unit or its folders installed leaves them; this run takes them.
	left := map[string]bool{}
	for _, pattern := range []string{"/etc/systemd/system/" + unitPrefix + "*.service", "/usr/local/lib/" + unitPrefix + "*", "/var/lib/" + unitPrefix + "*"} {
		found, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("listing what a dead run left: %v", err)
		}
		for _, path := range found {
			left[strings.TrimSuffix(filepath.Base(path), ".service")] = true
		}
	}
	for name := range left {
		removeUnit(t, name)
	}
	if code, _ := runSudo(t, "id", "-u", daemonUser); code != 0 {
		sudo(t, "useradd", "--system", "--user-group", "--no-create-home", "--shell", "/usr/sbin/nologin", daemonUser)
		t.Cleanup(func() {
			if code, output := runSudo(t, "userdel", daemonUser); code != 0 {
				t.Errorf("removing the account %s this run made: %d %s", daemonUser, code, output)
			}
		})
	}
	daemonID := strings.TrimSpace(sudo(t, "id", "-u", daemonUser))

	t.Run("When systemd starts it and names a socket for readiness (`NOTIFY_SOCKET`), the engine shall send `READY=1` there once every listener it was asked for is listening, or once it first writes a `waiting` line, and not before.", func(t *testing.T) { //nolint:paralleltest // it must run alone
		t.Run("the row locked from before the start: activating for 2 s from the engine's first try; the row released: active, then 127.0.0.1:23 and [::1]:23 served and the journal's line started", func(t *testing.T) { //nolint:paralleltest // it must run alone
			unit, lock, tried := startLockedUnit(t)
			unit.holdActiveState(t, "activating", tried.Add(pendingHold))
			lock.release(t)
			unit.awaitActiveState(t, "active", time.Now().Add(testrun.Patient(testrun.HangBound)))
			expectServed(t, defaultIPv4Telnet)
			expectServed(t, defaultIPv6Telnet)
			expectStartedAtPort23(t, unit.awaitJournalLines(t, 1))
		})
		t.Run("the row locked throughout: activating until 2 s before the try's end, active by 2 s after it, and the journal's line waiting", func(t *testing.T) { //nolint:paralleltest // it must run alone
			unit, _, tried := startLockedUnit(t)
			unit.holdActiveState(t, "activating", tried.Add(tryLimit-leaseMargin))
			active := unit.awaitActiveState(t, "active", tried.Add(tryLimit).Add(testrun.Patient(testrun.HangBound)))
			expectWithin(t, "active", active, tried.Add(tryLimit-leaseMargin), tried.Add(tryLimit+leaseMargin))
			expectLogText(t, unit.awaitJournalLines(t, 1), "waiting")
		})
		t.Run("SSH on with its port held by the test at both addresses, so Telnet listens and SSH fails: the unit failed and never counted active, its journal's line start_failed; started again with that port free, it becomes active", func(t *testing.T) { //nolint:paralleltest // it must run alone
			port, ipv4, ipv6 := heldPort(t)
			unit := newUnit(t, sharedRowSettings(t))
			hostKey := unit.installFile(t, makeKey(t, "ed25519", ""), "host_key")
			unit.install(t, sshPortOption, port, hostKeyOption, hostKey)
			unit.start(t)
			unit.awaitFailed(t)
			if entered := unit.property(t, "ActiveEnterTimestampMonotonic"); entered != "0" {
				t.Fatalf("systemd counted the unit active at %s µs, with SSH not listening", entered)
			}
			expectLogText(t, unit.awaitJournalLines(t, 1), startFailedKey)
			// The probe that must be answered, so the row is red against an engine that never
			// sends READY=1: the same unit, the port now free, is counted active.
			_ = ipv4.Close()
			_ = ipv6.Close()
			unit.start(t)
			unit.awaitActiveState(t, "active", time.Now().Add(testrun.Patient(testrun.HangBound)))
		})
	})

	t.Run("When systemd starts it as an ordinary user holding no capability but the right to bind ports below 1024, the engine shall listen for Telnet callers on port 23.", func(t *testing.T) { //nolint:paralleltest // it must run alone
		t.Run("run as hadv holding CAP_NET_BIND_SERVICE alone, as /proc reads back, with no port: active, 127.0.0.1:23 and [::1]:23 served, and the started line names both", func(t *testing.T) { //nolint:paralleltest // it must run alone
			unit := newUnit(t, sharedRowSettings(t))
			unit.install(t)
			unit.start(t)
			unit.awaitActiveState(t, "active", time.Now().Add(testrun.Patient(testrun.HangBound)))
			status, err := os.ReadFile("/proc/" + unit.property(t, "MainPID") + "/status")
			if err != nil {
				t.Fatalf("reading the main process's status: %v", err)
			}
			checked := 0
			for line := range strings.SplitSeq(string(status), "\n") {
				field, value, _ := strings.Cut(line, ":")
				values := strings.Fields(value)
				switch field {
				case "Uid":
					checked++
					for _, id := range values {
						if id != daemonID {
							t.Fatalf("the main process runs with user IDs %q, want %s's, %s, alone", values, daemonUser, daemonID)
						}
					}
				case "CapEff":
					checked++
					if len(values) != 1 || values[0] != bindServiceOnly {
						t.Fatalf("the main process's effective capabilities are %q, want %s, CAP_NET_BIND_SERVICE alone", values, bindServiceOnly)
					}
				}
			}
			if checked != 2 {
				t.Fatalf("the main process's status names no Uid or no CapEff line:\n%s", status)
			}
			expectServed(t, defaultIPv4Telnet)
			expectServed(t, defaultIPv6Telnet)
			expectStartedAtPort23(t, unit.awaitJournalLines(t, 1))
		})
	})
}
