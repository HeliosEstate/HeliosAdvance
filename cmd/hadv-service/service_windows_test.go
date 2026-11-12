// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// The service as the page installs it: its name, and the account Windows makes for it.
const (
	serviceName    = "hadv-service"
	serviceAccount = `NT SERVICE\hadv-service`
)

const (
	// serviceStartBound bounds a row's wait for the service to leave start pending or to answer
	// sc.exe start: a probe on CI's Windows runner read the first RUNNING 21.9 seconds after
	// sc.exe start, and Windows' service manager waits 30 seconds for a service that never
	// connects before it gives up.
	serviceStartBound = 90 * time.Second
	// statePoll is how often a row reads the service's state: Windows' service manager announces
	// no change of state to sc.exe.
	statePoll = 100 * time.Millisecond
	// The service manager's own codes, as Windows documents them.
	noSuchService      = 1060 // ERROR_SERVICE_DOES_NOT_EXIST
	serviceSpecificErr = 1066 // ERROR_SERVICE_SPECIFIC_ERROR
	processAborted     = 1067 // ERROR_PROCESS_ABORTED
	// noSuchImage is taskkill's exit code when no process has the image name.
	noSuchImage = 128
	// stoppedState is how sc.exe names a stopped service's state.
	stoppedState = "STOPPED"
)

var (
	stateLine       = regexp.MustCompile(`STATE\s*:\s*\d+\s+(\w+)`)
	windowsCodeLine = regexp.MustCompile(`WIN32_EXIT_CODE\s*:\s*(\d+)`)
	serviceCodeLine = regexp.MustCompile(`SERVICE_EXIT_CODE\s*:\s*(\d+)`)
	processIDLine   = regexp.MustCompile(`PID\s*:\s*(\d+)`)
	startNameLine   = regexp.MustCompile(`(?m)SERVICE_START_NAME\s*:\s*(.*?)\s*$`)
	binaryPathLine  = regexp.MustCompile(`(?m)BINARY_PATH_NAME\s*:\s*(.*?)\s*$`)
)

// serviceSetup is how a row installs the service: the connection settings its bootstrap folder
// seals, and what the row leaves out or breaks.
type serviceSetup struct {
	settings         connectionFile
	withoutBootstrap bool
	withoutLogFile   bool
	logFileIsFolder  bool
}

// windowsService is the service a row installed: the program's file name, which no other process
// has, and the log file it was given.
type windowsService struct {
	image   string
	logFile string
}

// installService installs the built program as the service hadv-service, run as NT
// SERVICE\hadv-service, the way the page's setup does: the program, its bootstrap folder and its
// log folder in a folder of the row's own with no space or comma in its path, so the command line
// is plain; the account given read and run on the program, read on the bootstrap folder, and modify
// on the log folder; the key file owned by Administrators, its inherited entries removed, and
// readable by Administrators and the account alone. The row's end stops and removes the service.
func installService(t *testing.T, setup serviceSetup) *windowsService {
	t.Helper()
	if buildFailure != nil {
		t.Fatalf("the program did not build: %v", buildFailure)
	}
	// Not the row's own temporary folder, whose path carries its name's commas.
	folder, err := os.MkdirTemp("", "svc") //nolint:usetesting // the command line needs a path with no comma
	if err != nil {
		t.Fatalf("making the service's folder: %v", err)
	}
	service := &windowsService{image: "hadv-qa-" + strings.ToLower(rand.Text()[:8]) + ".exe"}
	program := filepath.Join(folder, service.image)
	copyFile(t, programPath, program)
	bootstrap := filepath.Join(folder, "bootstrap")
	keyFile := filepath.Join(bootstrap, keyFileName)
	if !setup.withoutBootstrap {
		made := setup.settings.seal(t)
		if err := os.Mkdir(bootstrap, 0o700); err != nil {
			t.Fatalf("making the bootstrap folder: %v", err)
		}
		copyFile(t, made.file, filepath.Join(bootstrap, bootstrapFileName))
		copyFile(t, made.keyFile, keyFile)
	}
	logFolder := filepath.Join(folder, "log")
	if err := os.Mkdir(logFolder, 0o700); err != nil {
		t.Fatalf("making the log folder: %v", err)
	}
	service.logFile = filepath.Join(logFolder, "hadv.log")
	if setup.logFileIsFolder {
		if err := os.Mkdir(service.logFile, 0o700); err != nil {
			t.Fatalf("making a folder where the log file goes: %v", err)
		}
	}
	commandLine := `"` + program + `" ` + databaseOption + ` "` + bootstrap + `"`
	if !setup.withoutLogFile {
		commandLine += " " + logFileOption + ` "` + service.logFile + `"`
	}
	if code, output := serviceControl(t, "create", serviceName, "binPath=", commandLine, "obj=", serviceAccount, "start=", "demand"); code != 0 {
		t.Fatalf("sc.exe create ended %d: %s", code, output)
	}
	t.Cleanup(func() { service.remove(t) })
	// The account exists only once the service does, so it is granted its rights after.
	icacls(t, program, "/grant", serviceAccount+":(RX)")
	if !setup.withoutBootstrap {
		icacls(t, keyFile, "/setowner", "*"+administratorsSID)
		// Written whole: on CI's runner icacls /inheritance:r with /grant:r kept the inherited
		// entries as the file's own, the runner's account among them, which the engine refuses.
		account, _, _, err := syscall.LookupSID("", serviceAccount)
		if err != nil {
			t.Fatalf("looking up %s: %v", serviceAccount, err)
		}
		accountSID, err := account.String()
		if err != nil {
			t.Fatalf("reading %s's SID: %v", serviceAccount, err)
		}
		setAccessList(t, keyFile, "D:P(A;;FA;;;"+administratorsSID+")(A;;FR;;;"+accountSID+")")
		icacls(t, bootstrap, "/grant", serviceAccount+":(OI)(CI)(RX)")
	}
	icacls(t, logFolder, "/grant", serviceAccount+":(OI)(CI)(M)")
	return service
}

// copyFile copies a file the test can read to a new file.
func copyFile(t *testing.T, source, destination string) {
	t.Helper()
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("reading %s: %v", source, err)
	}
	if err := os.WriteFile(destination, contents, 0o600); err != nil {
		t.Fatalf("writing %s: %v", destination, err)
	}
}

// start runs sc.exe start and returns its exit code, logging its time and output.
func (service *windowsService) start(t *testing.T) int {
	t.Helper()
	began := time.Now()
	code, output := serviceControl(t, "start", serviceName)
	t.Logf("sc.exe start took %v and ended %d", time.Since(began), code)
	if code != 0 {
		t.Logf("sc.exe start: %s", output)
	}
	return code
}

// startRunning starts the service, which must answer sc.exe start without an error.
func (service *windowsService) startRunning(t *testing.T) {
	t.Helper()
	if code := service.start(t); code != 0 {
		t.Fatalf("sc.exe start ended %d; the log file holds %q", code, service.logText(t))
	}
}

// serviceState is what sc.exe queryex shows of the service.
type serviceState struct {
	state       string
	windowsCode int
	serviceCode int
	processID   int
}

// query reads the service's state with sc.exe queryex.
func (service *windowsService) query(t *testing.T) serviceState {
	t.Helper()
	code, output := serviceControl(t, "queryex", serviceName)
	if code != 0 {
		t.Fatalf("sc.exe queryex ended %d: %s", code, output)
	}
	state := stateLine.FindStringSubmatch(output)
	numbers := make([]int, 3)
	for index, line := range []*regexp.Regexp{windowsCodeLine, serviceCodeLine, processIDLine} {
		found := line.FindStringSubmatch(output)
		if found == nil {
			t.Fatalf("sc.exe queryex's output is not as Windows writes it: %s", output)
		}
		number, err := strconv.Atoi(found[1])
		if err != nil {
			t.Fatalf("sc.exe queryex's numbers: %v: %s", err, output)
		}
		numbers[index] = number
	}
	if state == nil {
		t.Fatalf("sc.exe queryex's output is not as Windows writes it: %s", output)
	}
	return serviceState{state: state[1], windowsCode: numbers[0], serviceCode: numbers[1], processID: numbers[2]}
}

// awaitState reads the service's state until it is the one wanted, up to the bound. A service
// that stops while the row waits for another state fails the row at once.
func (service *windowsService) awaitState(t *testing.T, want string, bound time.Duration) serviceState {
	t.Helper()
	giveUp := time.Now().Add(testrun.Patient(bound))
	for {
		read := service.query(t)
		if read.state == want {
			return read
		}
		if read.state == stoppedState {
			t.Fatalf("the service stopped, codes %d and %d, where it was to reach %s; the log file holds %q",
				read.windowsCode, read.serviceCode, want, service.logText(t))
		}
		if time.Now().After(giveUp) {
			t.Fatalf("the service was still %s %v on; want %s; the log file holds %q", read.state, testrun.Patient(bound), want, service.logText(t))
		}
		pause(t, statePoll)
	}
}

// holdState reads the service's state until the moment given, at least once, and checks every
// read is the one wanted.
func (service *windowsService) holdState(t *testing.T, want string, until time.Time) {
	t.Helper()
	for {
		if read := service.query(t); read.state != want {
			t.Fatalf("the service is %s; want %s until %v; the log file holds %q", read.state, want, until.Format(time.RFC3339Nano), service.logText(t))
		}
		if time.Now().After(until) {
			return
		}
		pause(t, statePoll)
	}
}

// expectStoppedFailed waits for the service to stop and checks the engine itself reported a
// non-zero exit code. The engine reports through the Service Manager unit, whose contract gives a
// non-zero code as ERROR_SERVICE_SPECIFIC_ERROR and the code beside it. A process that ends
// without reporting is shown by Windows as ERROR_PROCESS_ABORTED (1067), which is no report.
func (service *windowsService) expectStoppedFailed(t *testing.T) {
	t.Helper()
	giveUp := time.Now().Add(testrun.Patient(serviceStartBound))
	read := service.query(t)
	for read.state != stoppedState {
		if time.Now().After(giveUp) {
			t.Fatalf("the service was still %s %v on; want STOPPED; the log file holds %q", read.state, testrun.Patient(serviceStartBound), service.logText(t))
		}
		pause(t, statePoll)
		read = service.query(t)
	}
	if read.windowsCode != serviceSpecificErr || read.serviceCode == 0 {
		t.Fatalf("the service stopped with WIN32_EXIT_CODE %d and SERVICE_EXIT_CODE %d; want %d and a non-zero code the engine reported",
			read.windowsCode, read.serviceCode, serviceSpecificErr)
	}
}

// logText is what the log file holds so far, nothing where there is none, and the reason where
// it cannot be read, which no check takes for a log line: it is also read into failure messages,
// where a row whose log file is a folder must still report its own failure.
func (service *windowsService) logText(t *testing.T) string {
	t.Helper()
	contents, err := os.ReadFile(service.logFile)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Sprintf("(the log file cannot be read: %v)", err)
	}
	return string(contents)
}

// awaitLogLines waits, up to the hang bound, for the log file to hold count whole lines, and
// returns its text.
func (service *windowsService) awaitLogLines(t *testing.T, count int) string {
	t.Helper()
	bound := testrun.Patient(testrun.HangBound)
	giveUp := time.Now().Add(bound)
	for {
		text := service.logText(t)
		if strings.Count(text, "\n") >= count {
			return text
		}
		if time.Now().After(giveUp) {
			t.Fatalf("the log file held %q %v on, want %d lines", text, bound, count)
		}
		pause(t, statePoll)
	}
}

// awaitRunningOnWaiting starts the service on a row locked throughout and reads its state and
// then its log file, in that order, until it reports running. The engine writes the waiting line
// before it reports running, so a read of RUNNING must find that line in the file read after it.
// Once the line is there, running must follow within the hang bound.
func (service *windowsService) awaitRunningOnWaiting(t *testing.T) {
	t.Helper()
	service.startRunning(t)
	giveUp := time.Now().Add(testrun.Patient(serviceStartBound + tryLimit))
	for {
		read := service.query(t)
		text := service.logText(t)
		waiting := strings.HasPrefix(text, "waiting=") && strings.Contains(text, "\n")
		switch read.state {
		case "RUNNING":
			if !waiting {
				t.Fatalf("the service reported running while its log file held %q, before any waiting line", text)
			}
			return
		case "START_PENDING":
		default:
			t.Fatalf("the service is %s, codes %d and %d, where it was to be start pending; the log file holds %q",
				read.state, read.windowsCode, read.serviceCode, text)
		}
		if waiting && giveUp.After(time.Now().Add(testrun.Patient(testrun.HangBound))) {
			giveUp = time.Now().Add(testrun.Patient(testrun.HangBound))
		}
		if time.Now().After(giveUp) {
			t.Fatalf("the service was still start pending by %v; the log file holds %q", giveUp.Format(time.RFC3339Nano), text)
		}
		pause(t, statePoll)
	}
}

// expectPort23Free fails the row, as one that cannot run, when anything else on the machine
// holds port 23.
func expectPort23Free(t *testing.T) {
	t.Helper()
	for _, address := range []string{defaultIPv4Telnet, defaultIPv6Telnet} {
		held, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", address)
		if err != nil {
			t.Fatalf("%s is not free on this machine, so this row cannot run: %v", address, err)
		}
		_ = held.Close()
	}
}

// remove stops the service if it still runs, ends any process left running the row's copy of the
// program, deletes the service and reads back that it is gone. A failure here is reported, not
// fatal: it is the row's cleanup.
func (service *windowsService) remove(t *testing.T) {
	t.Helper()
	removeService(t)
	code, output := runBounded(t, "taskkill", "/F", "/IM", service.image)
	if code != 0 && code != noSuchImage {
		t.Errorf("taskkill /IM %s ended %d: %s", service.image, code, output)
	}
}

// testService says whether hadv-service is registered, and whether it is a test's: its program
// one of the copies the rows name hadv-qa-.
func testService(t *testing.T) (registered, ours bool) {
	t.Helper()
	code, output := serviceControl(t, "qc", serviceName)
	switch code {
	case noSuchService:
		return false, false
	case 0:
		found := binaryPathLine.FindStringSubmatch(output)
		return true, found != nil && strings.Contains(strings.ToLower(found[1]), `\hadv-qa-`)
	}
	t.Fatalf("sc.exe qc %s ended %d: %s", serviceName, code, output)
	return false, false
}

// removeService stops hadv-service if it runs, ending its process where a stop does not, deletes
// it and reads back that it is gone.
func removeService(t *testing.T) {
	t.Helper()
	bound := testrun.Patient(testrun.HangBound)
	giveUp := time.Now().Add(bound)
	stopSent, killed := false, false
	for {
		code, output := serviceControl(t, "queryex", serviceName)
		if code == noSuchService {
			return
		}
		if code != 0 {
			t.Errorf("sc.exe queryex %s ended %d: %s", serviceName, code, output)
			break
		}
		if strings.Contains(output, stoppedState) {
			break
		}
		if !stopSent && strings.Contains(output, "RUNNING") {
			_, _ = serviceControl(t, "stop", serviceName)
			stopSent = true
		}
		if time.Now().After(giveUp) {
			if killed {
				t.Errorf("service %s had not stopped %v after its process was ended: %s", serviceName, bound, output)
				break
			}
			if found := processIDLine.FindStringSubmatch(output); found != nil && found[1] != "0" {
				_, _ = runBounded(t, "taskkill", "/F", "/PID", found[1])
			}
			killed = true
			giveUp = time.Now().Add(bound)
		}
		pause(t, statePoll)
	}
	if code, output := serviceControl(t, "delete", serviceName); code != 0 {
		t.Errorf("sc.exe delete %s ended %d: %s", serviceName, code, output)
		return
	}
	giveUp = time.Now().Add(bound)
	for {
		code, output := serviceControl(t, "query", serviceName)
		if code == noSuchService {
			return
		}
		if time.Now().After(giveUp) {
			t.Errorf("service %s was still registered %v after sc.exe delete: %s", serviceName, bound, output)
			return
		}
		pause(t, statePoll)
	}
}

// serviceControl runs sc.exe and returns its exit code and output. sc.exe start waits for the
// service to answer, so it has the start bound; every other call the hang bound.
func serviceControl(t *testing.T, arguments ...string) (int, string) {
	t.Helper()
	if len(arguments) > 0 && arguments[0] == "start" {
		return runWithin(t, testrun.Patient(serviceStartBound), "sc.exe", arguments...)
	}
	return runBounded(t, "sc.exe", arguments...)
}

// runBounded runs a system tool up to the hang bound and returns its exit code and output.
func runBounded(t *testing.T, name string, arguments ...string) (int, string) {
	t.Helper()
	return runWithin(t, testrun.Patient(testrun.HangBound), name, arguments...)
}

// timedOut is the exit code runWithin gives a tool it ended at its bound: no tool ends with it.
const timedOut = -1

// runWithin runs a system tool up to the bound given and returns its exit code and output, or
// timedOut and what it wrote by then. A hung tool is not fatal here, so a cleanup goes on to its
// next step. Its context is not the row's, which has ended by the time a cleanup runs.
func runWithin(t *testing.T, bound time.Duration, name string, arguments ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()
	command := exec.CommandContext(ctx, name, arguments...)
	command.WaitDelay = bound
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		return timedOut, fmt.Sprintf("%s %s had not ended within %v: %s", name, strings.Join(arguments, " "), bound, output)
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), string(output)
	}
	if err != nil {
		t.Fatalf("running %s %s: %v", name, strings.Join(arguments, " "), err)
	}
	return 0, string(output)
}

// expectProcessEnds waits, up to the hang bound, for a process the row holds a handle to to end.
// The handle is taken while the process runs, so a process ID Windows hands to a new process
// once this one has ended cannot be mistaken for it.
func expectProcessEnds(t *testing.T, process *os.Process) {
	t.Helper()
	ended := make(chan error, 1)
	go func() {
		_, err := process.Wait()
		ended <- err
	}()
	bound := testrun.Patient(testrun.HangBound)
	timer := time.NewTimer(bound)
	defer timer.Stop()
	select {
	case err := <-ended:
		if err != nil {
			t.Fatalf("waiting for the service's process to end: %v", err)
		}
	case <-timer.C:
		select {
		case err := <-ended:
			if err != nil {
				t.Fatalf("waiting for the service's process to end: %v", err)
			}
		default:
			t.Fatalf("the service's process had not ended %v after the service stopped", bound)
		}
	}
}

// TestWindowsElevatedService runs alone, its rows one after the other: each installs the one
// service name the page gives, hadv-service, and most listen on port 23, which only one program
// on the machine can hold. sc.exe needs an elevated process: CI's Windows runner is one.
func TestWindowsElevatedService(t *testing.T) { //nolint:paralleltest // it must run alone
	// A run killed with the service installed leaves it; this run takes it. A hadv-service the
	// tests did not install is the machine's own, and is left alone.
	if registered, ours := testService(t); registered && !ours {
		t.Fatalf("a hadv-service the tests did not install is registered on this machine, so these rows cannot run")
	} else if registered {
		removeService(t)
	}
	t.Cleanup(func() {
		if registered, ours := testService(t); registered {
			t.Errorf("hadv-service was still registered after the rows")
			if ours {
				removeService(t)
			}
		}
	})

	t.Run("When Windows' service manager starts it as the service `hadv-service`, the engine shall report running once every listener it was asked for is listening, or once it first writes a `waiting` line, and not before.", func(t *testing.T) { //nolint:paralleltest // it must run alone
		t.Run("the row locked from before the start: start pending for 2 s from the engine's first try; the row released: running, then 127.0.0.1:23 and [::1]:23 served and the log file's line started", func(t *testing.T) { //nolint:paralleltest // it must run alone
			expectPort23Free(t)
			server := sharedServer(t)
			created := server.newBoard(t, telnetAt(23))
			lock := created.lockRow(t)
			service := installService(t, serviceSetup{settings: created.file()})
			since := time.Now()
			service.startRunning(t)
			tried := server.waitForTry(t, created.login, since, time.Now().Add(testrun.Patient(testrun.HangBound)))
			if time.Now().After(tried.Add(tryLimit - leaseMargin)) {
				t.Fatalf("cannot tell: the test read the engine's first try %v after it, too near the try's own end", time.Since(tried))
			}
			service.holdState(t, "START_PENDING", tried.Add(pendingHold))
			lock.release(t)
			service.awaitState(t, "RUNNING", testrun.HangBound)
			expectServed(t, defaultIPv4Telnet)
			expectServed(t, defaultIPv6Telnet)
			expectStartedAtPort23(t, service.awaitLogLines(t, 1))
		})
		t.Run("the row locked throughout: start pending until the log file holds a waiting line, then running, and no started line", func(t *testing.T) { //nolint:paralleltest // it must run alone
			created := sharedServer(t).newBoard(t, telnetAt(23))
			created.lockRow(t)
			service := installService(t, serviceSetup{settings: created.file()})
			service.awaitRunningOnWaiting(t)
			expectLogText(t, service.logText(t), "waiting")
		})
		t.Run("every service off: running, its one started line naming no listener, and the service's process listening nowhere", func(t *testing.T) { //nolint:paralleltest // it must run alone
			service := installService(t, serviceSetup{settings: sharedRowSettings(t, allOff())})
			service.startRunning(t)
			// No line orders running against the started line with every service off, so the row
			// waits for the line once the service runs. Running before the take is the waiting
			// row's to catch: no build knows every service is off before it takes the lease.
			giveUp := time.Now().Add(testrun.Patient(serviceStartBound))
			for {
				read := service.query(t)
				if read.state == "RUNNING" {
					text := service.logText(t)
					lineBy := time.Now().Add(testrun.Patient(testrun.HangBound))
					for !strings.Contains(text, "\n") && time.Now().Before(lineBy) {
						pause(t, statePoll)
						text = service.logText(t)
					}
					values := expectLogText(t, text, "started")
					expectListensNowhere(t, values[0])
					if sockets := listeningSockets(t, read.processID); len(sockets) != 0 {
						t.Fatalf("the service's process listens at %q, with every service off", sockets)
					}
					return
				}
				text := service.logText(t)
				if read.state != "START_PENDING" {
					t.Fatalf("the service is %s, codes %d and %d, where it was to report running; the log file holds %q",
						read.state, read.windowsCode, read.serviceCode, text)
				}
				if time.Now().After(giveUp) {
					t.Fatalf("the service was still start pending by %v; the log file holds %q", giveUp.Format(time.RFC3339Nano), text)
				}
				pause(t, statePoll)
			}
		})
	})

	t.Run("When the service manager sends stop or shutdown, the engine shall close every open connection at once, report stopped and exit.", func(t *testing.T) { //nolint:paralleltest // it must run alone
		// Only Windows itself sends shutdown, as it shuts down, so no row can send it.
		t.Run("sc.exe stop, a caller waiting at the name prompt, shutdown accepted while running: the caller's connection closed at once, then stopped as the engine reported it, and the service's process ended", func(t *testing.T) { //nolint:paralleltest // it must run alone
			expectPort23Free(t)
			service := installService(t, serviceSetup{settings: sharedRowSettings(t, telnetAt(23))})
			service.startRunning(t)
			running := service.awaitState(t, "RUNNING", serviceStartBound)
			// Shutdown cannot be sent from a test, only accepted: a service that does not accept it
			// is never sent it.
			if code, output := serviceControl(t, "queryex", serviceName); code != 0 || !strings.Contains(output, "ACCEPTS_SHUTDOWN") {
				t.Fatalf("the running service does not accept shutdown: %d %s", code, output)
			}
			call := waitingCaller(t, defaultIPv4Telnet)
			process, err := os.FindProcess(running.processID)
			if err != nil {
				t.Fatalf("opening the service's process %d: %v", running.processID, err)
			}
			from := time.Now()
			if code, output := serviceControl(t, "stop", serviceName); code != 0 {
				t.Fatalf("sc.exe stop ended %d: %s", code, output)
			}
			call.expectEnd(t, from, time.Now().Add(testrun.Patient(margin)))
			// The line pins no exit code for a stop; a process that ends without reporting stopped
			// is no report at all.
			if stopped := service.awaitState(t, stoppedState, testrun.HangBound); stopped.windowsCode == processAborted {
				t.Fatalf("the service's process ended without reporting stopped: WIN32_EXIT_CODE %d", stopped.windowsCode)
			}
			expectProcessEnds(t, process)
		})
	})

	t.Run("If the engine writes a `start_failed` line while running as a service, then the engine shall report stopped with a non-zero exit code.", func(t *testing.T) { //nolint:paralleltest // it must run alone
		t.Run("before it reports running, the bootstrap folder missing: one start_failed line in the log file, and stopped with a non-zero code", func(t *testing.T) { //nolint:paralleltest // it must run alone
			service := installService(t, serviceSetup{withoutBootstrap: true})
			service.start(t)
			service.expectStoppedFailed(t)
			expectLogText(t, service.logText(t), startFailedKey)
		})
		t.Run("after it reports running, on a waiting line, the row then released while the test holds 127.0.0.1:23 and [::1]:23: start_failed, and stopped with a non-zero code", func(t *testing.T) { //nolint:paralleltest // it must run alone
			expectPort23Free(t)
			for _, address := range []string{defaultIPv4Telnet, defaultIPv6Telnet} {
				held, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", address)
				if err != nil {
					t.Fatalf("holding %s: %v", address, err)
				}
				t.Cleanup(func() { _ = held.Close() })
			}
			created := sharedServer(t).newBoard(t, telnetAt(23))
			lock := created.lockRow(t)
			service := installService(t, serviceSetup{settings: created.file()})
			service.awaitRunningOnWaiting(t)
			lock.release(t)
			service.expectStoppedFailed(t)
			expectLogText(t, service.logText(t), "waiting", startFailedKey)
		})
		t.Run("the log file's path naming a folder, so its start_failed line goes to standard output: stopped with a non-zero code", func(t *testing.T) { //nolint:paralleltest // it must run alone
			service := installService(t, serviceSetup{settings: sharedRowSettings(t, telnetAt(23)), logFileIsFolder: true})
			service.start(t)
			service.expectStoppedFailed(t)
		})
	})

	t.Run("If Windows' service manager starts it with no log file on the command line, then the engine shall report stopped with a non-zero exit code, listening nowhere.", func(t *testing.T) { //nolint:paralleltest // it must run alone
		t.Run("a good bootstrap folder, no log file, Telnet on at 23: stopped with a non-zero code, its process holding no listening socket at any read before", func(t *testing.T) { //nolint:paralleltest // it must run alone
			service := installService(t, serviceSetup{settings: sharedRowSettings(t, telnetAt(23)), withoutLogFile: true})
			service.start(t)
			giveUp := time.Now().Add(testrun.Patient(serviceStartBound))
			for {
				first := service.query(t)
				if first.state == stoppedState {
					break
				}
				if first.processID != 0 {
					sockets := listeningSockets(t, first.processID)
					// Read again, so the sockets are known to be the service's own process's and
					// not a new process's that Windows gave an ended one's ID.
					if second := service.query(t); second.processID == first.processID && second.state != stoppedState && len(sockets) > 0 {
						t.Fatalf("the service's process listens at %q, started with no log file", sockets)
					}
				}
				if time.Now().After(giveUp) {
					t.Fatalf("the service was still %s %v on; want STOPPED", first.state, testrun.Patient(serviceStartBound))
				}
				pause(t, statePoll)
			}
			service.expectStoppedFailed(t)
		})
	})

	t.Run("When Windows' service manager starts it as `NT SERVICE\\hadv-service` and its server's settings turn Telnet on at port 23, the engine shall listen for Telnet callers on port 23.", func(t *testing.T) { //nolint:paralleltest // it must run alone
		t.Run("installed under NT SERVICE\\hadv-service, as sc.exe qc reads back, Telnet on at 23: running, 127.0.0.1:23 and [::1]:23 served, and the started line names both", func(t *testing.T) { //nolint:paralleltest // it must run alone
			expectPort23Free(t)
			service := installService(t, serviceSetup{settings: sharedRowSettings(t, telnetAt(23))})
			code, output := serviceControl(t, "qc", serviceName)
			if found := startNameLine.FindStringSubmatch(output); code != 0 || found == nil || found[1] != serviceAccount {
				t.Fatalf("sc.exe qc ended %d and names the account %q; want %s: %s", code, found, serviceAccount, output)
			}
			service.startRunning(t)
			service.awaitState(t, "RUNNING", serviceStartBound)
			expectServed(t, defaultIPv4Telnet)
			expectServed(t, defaultIPv6Telnet)
			expectStartedAtPort23(t, service.awaitLogLines(t, 1))
		})
	})
}
