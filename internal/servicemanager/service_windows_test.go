// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package servicemanager_test

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

const (
	// startBound bounds a row's wait for the helper to reach the test after sc.exe start: a probe
	// on CI's Windows runner read the first RUNNING 21.9 seconds after sc.exe start, and Windows'
	// service manager waits 30 seconds for a service that never connects before it gives up.
	startBound = 90 * time.Second
	// pendingWait is how long a row reads the service as start pending before it calls ready:
	// a stated wait, so on a slow machine it can miss a late fault but never fail a sound engine.
	pendingWait = 2 * time.Second
	// steadyWait is how long a row reads the service as still running after a second ready.
	steadyWait = time.Second
	// pollInterval is how often a row reads the service's state while it waits for one: Windows'
	// service manager announces no change of state to sc.exe.
	pollInterval = 100 * time.Millisecond
	// mostReport bounds one line the helper writes.
	mostReport = 256
	// The service manager's own codes, as Windows documents them.
	notAccepted     = 1052 // ERROR_INVALID_SERVICE_CONTROL
	serviceSpecific = 1066 // ERROR_SERVICE_SPECIFIC_ERROR
	noSuchService   = 1060 // ERROR_SERVICE_DOES_NOT_EXIST
	// runningFlags is what sc.exe query shows a running service accepts when it accepts stop and
	// shutdown and nothing else.
	runningFlags = "STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN"
)

var (
	// copying makes the copy of the test binary the services run, once for the run; helperPath is
	// the copy, and helperFailure why it was not made.
	copying       sync.Once
	helperPath    string
	helperFailure error
)

// copyHelper copies the test binary into the run's folder, where a run killed with a service
// still running leaves it for the next run to end.
func copyHelper() {
	binary, err := os.Executable()
	if err != nil {
		helperFailure = err
		return
	}
	contents, err := os.ReadFile(binary)
	if err != nil {
		helperFailure = err
		return
	}
	helperPath = filepath.Join(os.TempDir(), "servicehelper.exe")
	helperFailure = os.WriteFile(helperPath, contents, 0o600)
}

// TestWindowsElevatedService holds the rows that register a helper as a Windows service with
// sc.exe, which needs an elevated process: CI's Windows runner is one. The helper is this test
// binary run again by the service manager, so it is approved and locked with the rows. Each row
// registers a service of its own name, so rows run side by side; the helper runs as
// LocalSystem, sc.exe's default.
func TestWindowsElevatedService(t *testing.T) {
	t.Parallel()
	if port, isChild := serviceChildPort(t); isChild {
		serveAsHelper(port)
		return
	}
	t.Run("When Windows' service manager started this process, StartedByWindowsServiceManager shall return true.", func(t *testing.T) {
		t.Parallel()
		t.Run("the helper, started by sc.exe start", func(t *testing.T) {
			t.Parallel()
			service, started := startService(t)
			if started != "started true nil" {
				t.Fatalf("the helper reported %q; want %q", started, "started true nil")
			}
			service.expect(t, "run 1")
		})
	})
	t.Run("RunWindowsService shall report the service as start pending until ready's first call, and then as running, accepting stop and shutdown.", func(t *testing.T) {
		t.Parallel()
		t.Run("start pending from run's call until ready, then running, accepting stop and shutdown", func(t *testing.T) {
			t.Parallel()
			service := startRunning(t)
			service.holdState(t, "START_PENDING", "", pendingWait)
			service.callReady(t)
			service.awaitState(t, "RUNNING", runningFlags)
		})
		t.Run("a second call to ready changes nothing", func(t *testing.T) {
			t.Parallel()
			service := startRunning(t)
			service.callReady(t)
			service.awaitState(t, "RUNNING", runningFlags)
			service.callReady(t)
			service.holdState(t, "RUNNING", runningFlags, steadyWait)
		})
	})
	t.Run("RunWindowsService shall accept no request from the service manager but stop, shutdown and its status queries.", func(t *testing.T) {
		t.Parallel()
		for _, request := range [][]string{{"pause"}, {"continue"}, {"control", "paramchange"}} {
			t.Run("sc.exe "+strings.Join(request, " ")+" refused while running", func(t *testing.T) {
				t.Parallel()
				service := startRunning(t)
				service.callReady(t)
				service.awaitState(t, "RUNNING", runningFlags)
				arguments := append([]string{request[0], service.name}, request[1:]...)
				if code, output := serviceControl(t, arguments...); code != notAccepted {
					t.Fatalf("sc.exe %s ended %d; want %d, refused: %s", strings.Join(arguments, " "), code, notAccepted, output)
				}
				service.holdState(t, "RUNNING", runningFlags, 0)
			})
		}
	})
	t.Run("When the service manager sends stop or shutdown, RunWindowsService shall end stop.", func(t *testing.T) {
		t.Parallel()
		t.Run("sc.exe stop, while running", func(t *testing.T) {
			t.Parallel()
			service := startRunning(t)
			service.callReady(t)
			service.awaitState(t, "RUNNING", runningFlags)
			if code, output := serviceControl(t, "stop", service.name); code != 0 {
				t.Fatalf("sc.exe stop ended %d: %s", code, output)
			}
			service.expect(t, "stop-ended")
			service.send(t, "return 0")
			service.expect(t, "returned 0 nil 1")
		})
	})
	t.Run("A call to ready after run has returned shall do nothing.", func(t *testing.T) {
		t.Parallel()
		// The late call coming back is the proof: the library drops a status sent after run
		// returns, so the service's state cannot show it.
		t.Run("ready called while running, and again once RunWindowsService has returned", func(t *testing.T) {
			t.Parallel()
			service := startRunning(t)
			service.callReady(t)
			service.awaitState(t, "RUNNING", runningFlags)
			service.send(t, "return 0")
			service.expect(t, "returned 0 nil 1")
			service.expect(t, "alive")
		})
		t.Run("ready first called once RunWindowsService has returned", func(t *testing.T) {
			t.Parallel()
			service := startRunning(t)
			service.send(t, "return 0")
			service.expect(t, "returned 0 nil 1")
			service.expect(t, "alive")
		})
	})
	t.Run("When run returns 0, RunWindowsService shall report the service stopped with no error, and return 0.", func(t *testing.T) {
		t.Parallel()
		t.Run("run returns 0 while running", func(t *testing.T) {
			t.Parallel()
			returnFromRunning(t, 0, 0)
		})
	})
	t.Run("When run returns any other code, RunWindowsService shall report the service stopped with ERROR_SERVICE_SPECIFIC_ERROR (1066) as its Windows exit code and run's code as its service-specific exit code, and return run's code.", func(t *testing.T) {
		t.Parallel()
		for _, code := range []int{1, 3} {
			t.Run(fmt.Sprintf("run returns %d while running", code), func(t *testing.T) {
				t.Parallel()
				returnFromRunning(t, code, serviceSpecific)
			})
		}
	})
	t.Run("RunWindowsService shall call run once at most.", func(t *testing.T) {
		t.Parallel()
		t.Run("one call, in a service the service manager started", func(t *testing.T) {
			t.Parallel()
			service := startRunning(t)
			service.callReady(t)
			service.send(t, "return 0")
			// The helper counts run's calls in its last field.
			service.expect(t, "returned 0 nil 1")
		})
	})
}

// returnFromRunning makes run return code once the service runs, and checks what RunWindowsService
// returned and the exit codes the service manager reports.
func returnFromRunning(t *testing.T, code, windowsCode int) {
	t.Helper()
	service := startRunning(t)
	service.callReady(t)
	service.awaitState(t, "RUNNING", runningFlags)
	service.send(t, "return "+strconv.Itoa(code))
	service.expect(t, fmt.Sprintf("returned %d nil 1", code))
	stopped := service.awaitState(t, "STOPPED", "")
	if stopped.windowsCode != windowsCode || stopped.serviceCode != code {
		t.Fatalf("the service stopped with WIN32_EXIT_CODE %d and SERVICE_EXIT_CODE %d; want %d and %d",
			stopped.windowsCode, stopped.serviceCode, windowsCode, code)
	}
}

// helperService is one registered, started helper, and its connection to the test.
type helperService struct {
	name       string
	connection net.Conn
	reports    *bufio.Reader
}

// startService registers the helper under a name of its own, starts it, and takes its
// connection. It returns the helper's first report, what StartedByWindowsServiceManager said.
// The row's end ends the connection, so run returns, and removes the service.
func startService(t *testing.T) (*helperService, string) {
	t.Helper()
	copying.Do(copyHelper)
	if helperFailure != nil {
		t.Fatalf("copying the test binary for the services: %v", helperFailure)
	}
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listening for the helper: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	port := listener.Addr().(*net.TCPAddr).Port //nolint:errcheck,forcetypeassert // a TCP listener's address is a TCP address
	name := "hadv-qa-" + rand.Text()
	// Quoted as Windows reads a command line, since the run's folder may hold a space.
	command := fmt.Sprintf(`"%s" -test.run=^TestWindowsElevatedService$ -test.count=1 %s %d`, helperPath, serviceChild, port)
	if code, output := serviceControl(t, "create", name, "binPath=", command, "start=", "demand"); code != 0 {
		t.Fatalf("sc.exe create ended %d: %s", code, output)
	}
	t.Cleanup(func() { removeService(t, name) })
	began := time.Now()
	code, output := serviceControl(t, "start", name)
	t.Logf("sc.exe start took %v", time.Since(began))
	if code != 0 {
		t.Fatalf("sc.exe start ended %d: %s", code, output)
	}
	if err := listener.SetDeadline(time.Now().Add(testrun.Patient(startBound))); err != nil {
		t.Fatalf("setting the listener's deadline: %v", err)
	}
	connection, err := listener.Accept()
	if err != nil {
		t.Fatalf("the helper did not connect: %v", err)
	}
	// Registered after the service's removal, so it runs first: run returns once its connection
	// ends, and the service stops.
	t.Cleanup(func() { _ = connection.Close() })
	service := &helperService{name: name, connection: connection, reports: bufio.NewReaderSize(connection, mostReport)}
	return service, service.read(t)
}

// startRunning starts the helper and waits for run's first call.
func startRunning(t *testing.T) *helperService {
	t.Helper()
	service, _ := startService(t)
	service.expect(t, "run 1")
	return service
}

// read takes the helper's next report, up to the hang bound.
func (service *helperService) read(t *testing.T) string {
	t.Helper()
	bound := testrun.Patient(testrun.HangBound)
	if err := service.connection.SetReadDeadline(time.Now().Add(bound)); err != nil {
		t.Fatalf("setting the helper's read deadline: %v", err)
	}
	line, err := service.reports.ReadString('\n')
	if err != nil {
		t.Fatalf("the helper's next report, after %q, within %v: %v", line, bound, err)
	}
	return strings.TrimSuffix(line, "\n")
}

// expect checks the helper's next report is exactly the one wanted.
func (service *helperService) expect(t *testing.T, want string) {
	t.Helper()
	if got := service.read(t); got != want {
		t.Fatalf("the helper reported %q; want %q", got, want)
	}
}

// send tells the helper what to do next.
func (service *helperService) send(t *testing.T, command string) {
	t.Helper()
	if err := service.connection.SetWriteDeadline(time.Now().Add(testrun.Patient(testrun.HangBound))); err != nil {
		t.Fatalf("setting the helper's write deadline: %v", err)
	}
	if _, err := service.connection.Write([]byte(command + "\n")); err != nil {
		t.Fatalf("telling the helper %q: %v", command, err)
	}
}

// callReady has the helper call ready, and waits for the call to return.
func (service *helperService) callReady(t *testing.T) {
	t.Helper()
	service.send(t, "ready")
	service.expect(t, "readied")
}

// serviceState is what sc.exe query shows of a service.
type serviceState struct {
	state       string
	flags       string
	windowsCode int
	serviceCode int
}

var (
	// What a service accepts is on the line after its state, and absent once it is stopped.
	stateLine       = regexp.MustCompile(`STATE\s*:\s*\d+\s+(\w+)(?:\s*\r?\n\s*\(([^)]*)\))?`)
	windowsCodeLine = regexp.MustCompile(`WIN32_EXIT_CODE\s*:\s*(\d+)`)
	serviceCodeLine = regexp.MustCompile(`SERVICE_EXIT_CODE\s*:\s*(\d+)`)
)

// query reads the service's state with sc.exe query.
func (service *helperService) query(t *testing.T) serviceState {
	t.Helper()
	code, output := serviceControl(t, "query", service.name)
	if code != 0 {
		t.Fatalf("sc.exe query ended %d: %s", code, output)
	}
	state := stateLine.FindStringSubmatch(output)
	windowsCode := windowsCodeLine.FindStringSubmatch(output)
	serviceCode := serviceCodeLine.FindStringSubmatch(output)
	if state == nil || windowsCode == nil || serviceCode == nil {
		t.Fatalf("sc.exe query's output is not as Windows writes it: %s", output)
	}
	read := serviceState{state: state[1], flags: state[2]}
	var windowsErr, serviceErr error
	read.windowsCode, windowsErr = strconv.Atoi(windowsCode[1])
	read.serviceCode, serviceErr = strconv.Atoi(serviceCode[1])
	if err := errors.Join(windowsErr, serviceErr); err != nil {
		t.Fatalf("sc.exe query's exit codes: %v: %s", err, output)
	}
	return read
}

// awaitState reads the service's state until it is the one wanted, up to the hang bound, and
// checks what it accepts there when flags is given.
func (service *helperService) awaitState(t *testing.T, state, flags string) serviceState {
	t.Helper()
	bound := testrun.Patient(testrun.HangBound)
	giveUp := time.Now().Add(bound)
	for {
		read := service.query(t)
		if read.state == state {
			if flags != "" && read.flags != flags {
				t.Fatalf("the service is %s accepting (%s); want (%s)", state, read.flags, flags)
			}
			return read
		}
		if time.Now().After(giveUp) {
			t.Fatalf("the service was still %s %v on; want %s", read.state, bound, state)
		}
		<-time.NewTimer(pollInterval).C
	}
}

// holdState reads the service's state for the stated wait, at least once, and checks every read
// is the one wanted, and what it accepts when flags is given.
func (service *helperService) holdState(t *testing.T, state, flags string, wait time.Duration) {
	t.Helper()
	until := time.Now().Add(wait)
	for {
		read := service.query(t)
		if read.state != state || (flags != "" && read.flags != flags) {
			t.Fatalf("the service is %s accepting (%s); want %s accepting (%s)", read.state, read.flags, state, flags)
		}
		if time.Now().After(until) {
			return
		}
		<-time.NewTimer(pollInterval).C
	}
}

// removeService stops the service if it still runs, deletes it, and reads back that it is gone.
// A failure here is reported, not fatal: it is the row's cleanup.
func removeService(t *testing.T, name string) {
	t.Helper()
	giveUp := time.Now().Add(testrun.Patient(startBound))
	stopSent := false
	for {
		code, output := serviceControl(t, "query", name)
		if code != 0 {
			t.Errorf("sc.exe query %s ended %d: %s", name, code, output)
			break
		}
		if strings.Contains(output, "STOPPED") {
			break
		}
		if time.Now().After(giveUp) {
			t.Errorf("service %s had not stopped %v on: %s", name, testrun.Patient(startBound), output)
			break
		}
		// The helper's run returns once its connection ends; a stop is sent only when it runs.
		if !stopSent && strings.Contains(output, "RUNNING") {
			_, _ = serviceControl(t, "stop", name)
			stopSent = true
		}
		<-time.NewTimer(pollInterval).C
	}
	if code, output := serviceControl(t, "delete", name); code != 0 {
		t.Errorf("sc.exe delete %s ended %d: %s", name, code, output)
		return
	}
	bound := testrun.Patient(testrun.HangBound)
	giveUp = time.Now().Add(bound)
	for {
		code, output := serviceControl(t, "query", name)
		if code == noSuchService {
			return
		}
		if time.Now().After(giveUp) {
			t.Errorf("service %s was still registered %v after sc.exe delete: %s", name, bound, output)
			return
		}
		<-time.NewTimer(pollInterval).C
	}
}

// serviceControl runs sc.exe, up to the hang bound, and returns its exit code and output.
func serviceControl(t *testing.T, arguments ...string) (int, string) {
	t.Helper()
	bound := testrun.Patient(testrun.HangBound)
	if len(arguments) > 0 && arguments[0] == "start" {
		bound = testrun.Patient(startBound)
	}
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()
	command := exec.CommandContext(ctx, "sc.exe", arguments...)
	command.WaitDelay = bound
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("sc.exe %s had not ended within %v: %s", strings.Join(arguments, " "), bound, output)
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), string(output)
	}
	if err != nil {
		t.Fatalf("running sc.exe %s: %v", strings.Join(arguments, " "), err)
	}
	return 0, string(output)
}
