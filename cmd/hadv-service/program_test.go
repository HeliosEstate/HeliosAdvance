// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The program run from outside: TestMain builds cmd/hadv-service once, and each row starts the
// built program with its own options, reads its standard error as the local log, drives it with
// the scripted Telnet caller over loopback, and waits for it to exit.
package main_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// The loopback addresses and the port option, as the page and the issue name them.
const (
	ipv4Loopback = "127.0.0.1"
	ipv6Loopback = "::1"
	portOption   = "-port"
)

// startLimit bounds how long the program may take to name its listeners or to exit after a
// refusal. The page gives it no limit; this one only keeps a hung program from hanging the run.
const startLimit = 30 * time.Second

var (
	programPath  string
	buildFailure error
)

// TestMain builds the program the rows run, under the race detector when the tests run under
// it. A build that fails fails every row with its reason, rather than stopping before any runs.
func TestMain(tests *testing.M) {
	directory, err := os.MkdirTemp("", "hadv-service-test-")
	if err != nil {
		buildFailure = err
	} else {
		name := "hadv-service"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		programPath = filepath.Join(directory, name)
		arguments := []string{"build", "-o", programPath}
		if raceBuild {
			arguments = append(arguments, "-race")
		}
		arguments = append(arguments, ".")
		output, buildErr := exec.CommandContext(context.Background(), "go", arguments...).CombinedOutput()
		if buildErr != nil {
			buildFailure = fmt.Errorf("%w: %s", buildErr, strings.TrimSpace(string(output)))
		}
	}
	code := tests.Run()
	if directory != "" {
		_ = os.RemoveAll(directory)
	}
	os.Exit(code)
}

// run is one start of the program.
type run struct {
	command *exec.Cmd
	// lines receives each line of the local log as it arrives.
	lines chan string
	// exited is closed once the log has ended and the program has exited.
	exited   chan struct{}
	mutex    sync.Mutex
	log      []byte
	exitCode int
	exitedAt time.Time
}

// startProgram starts the built program with the given options, killed when the test ends.
func startProgram(t *testing.T, options ...string) *run {
	t.Helper()
	return startCommand(t, exec.CommandContext(t.Context(), programPath, options...))
}

// startCommand starts a command that runs the built program, such as the program under sudo.
func startCommand(t *testing.T, command *exec.Cmd) *run {
	t.Helper()
	if buildFailure != nil {
		t.Fatalf("the program did not build: %v", buildFailure)
	}
	command.SysProcAttr = processAttributes()
	command.WaitDelay = 5 * time.Second
	// A program built with the race detector sleeps a second at exit by default, waiting for late
	// reports, which would read as a slow exit; a race it finds still reaches the log and fails
	// the row.
	if raceBuild {
		command.Env = append(os.Environ(), "GORACE=atexit_sleep_ms=0")
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		t.Fatalf("the program's standard error: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("starting the program: %v", err)
	}
	program := &run{command: command, lines: make(chan string, 64), exited: make(chan struct{})}
	go program.read(stderr)
	t.Cleanup(func() {
		select {
		case <-program.exited:
		default:
			_ = command.Process.Kill()
			<-program.exited
		}
	})
	return program
}

// read keeps the whole log, hands each line on as it arrives, and waits for the exit.
func (program *run) read(stderr io.Reader) {
	reader := bufio.NewReader(stderr)
	for {
		line, err := reader.ReadString('\n')
		program.mutex.Lock()
		program.log = append(program.log, line...)
		program.mutex.Unlock()
		if line != "" {
			select {
			case program.lines <- strings.TrimSuffix(line, "\n"):
			default:
			}
		}
		if err != nil {
			break
		}
	}
	waitErr := program.command.Wait()
	program.mutex.Lock()
	program.exitCode = program.command.ProcessState.ExitCode()
	program.exitedAt = time.Now()
	program.mutex.Unlock()
	_ = waitErr
	close(program.exited)
}

// listening waits for the program's first log line, which must be the started line, and returns
// the addresses it names.
func (program *run) listening(t *testing.T) []string {
	t.Helper()
	timer := time.NewTimer(startLimit)
	defer timer.Stop()
	select {
	case line := <-program.lines:
		value, found := strings.CutPrefix(line, "started=")
		if !found {
			t.Fatalf("the program's first log line was %q, want a started line", line)
		}
		return strings.Split(value, ",")
	case <-program.exited:
		t.Fatalf("the program exited with %d before it named a listener; its log:\n%s", program.code(), program.text())
	case <-timer.C:
		t.Fatalf("the program named no listener within %v", startLimit)
	}
	return nil
}

// exit waits for the program to exit, by the deadline, and returns its exit code and when.
func (program *run) exit(t *testing.T, deadline time.Time) (int, time.Time) {
	t.Helper()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-program.exited:
	case <-timer.C:
		t.Fatalf("the program had not exited by the deadline; its log so far:\n%s", program.text())
	}
	program.mutex.Lock()
	defer program.mutex.Unlock()
	return program.exitCode, program.exitedAt
}

func (program *run) code() int {
	program.mutex.Lock()
	defer program.mutex.Unlock()
	return program.exitCode
}

func (program *run) text() string {
	program.mutex.Lock()
	defer program.mutex.Unlock()
	return string(program.log)
}

// logKeys are the only keys the local log may hold.
var logKeys = []string{"started", "start_failed"}

// expectLog checks the whole local log once the program has exited: every line is one key and
// its value, the key one of logKeys and the value more than spaces and quote marks, each line
// ending in LF, and the keys in the order want gives. It returns the values. A value may be
// quoted, so an empty one quoted is as empty as none, and says nothing to the sysop.
func (program *run) expectLog(t *testing.T, want ...string) []string {
	t.Helper()
	<-program.exited
	text := program.text()
	if text != "" && !strings.HasSuffix(text, "\n") {
		t.Fatalf("the local log does not end in LF: %q", text)
	}
	var keys, values []string
	for line := range strings.SplitSeq(strings.TrimSuffix(text, "\n"), "\n") {
		if text == "" {
			break
		}
		key, value, found := strings.Cut(line, "=")
		if !found || !slices.Contains(logKeys, key) || strings.Trim(value, ` "`) == "" || strings.ContainsAny(value, "\r\n") {
			t.Fatalf("a local log line is not one known key and its value: %q, in\n%s", line, text)
		}
		keys = append(keys, key)
		values = append(values, value)
	}
	if !slices.Equal(keys, want) {
		t.Fatalf("the local log's keys were %q, want %q; the log:\n%s", keys, want, text)
	}
	return values
}

// expectRefusal waits for a program that must refuse to start: one start_failed line saying
// why, and a non-zero exit code. It returns the reason.
func (program *run) expectRefusal(t *testing.T) string {
	t.Helper()
	timer := time.NewTimer(startLimit)
	defer timer.Stop()
	select {
	case line := <-program.lines:
		if strings.HasPrefix(line, "started=") {
			t.Fatalf("the program started, %q, where it was to refuse", line)
		}
	case <-program.exited:
	case <-timer.C:
	}
	code, _ := program.exit(t, time.Now().Add(startLimit))
	values := program.expectLog(t, "start_failed")
	if code == 0 {
		t.Fatalf("the program refused to start but exited with 0; its log:\n%s", program.text())
	}
	return values[0]
}

// expectAddresses checks the started line named exactly these listeners, in any order.
func expectAddresses(t *testing.T, got []string, want ...string) {
	t.Helper()
	if !slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want))) {
		t.Fatalf("the started line named %q, want %q", got, want)
	}
}

// loopbackPorts returns the port of the 127.0.0.1 listener and of the ::1 listener the started
// line names; there must be exactly those two.
func loopbackPorts(t *testing.T, addresses []string) (ipv4Port, ipv6Port string) {
	t.Helper()
	for _, address := range addresses {
		host, port, err := net.SplitHostPort(address)
		if err != nil || port == "0" || address != net.JoinHostPort(host, port) {
			t.Fatalf("the started line names %q, which is not a host and a port", address)
		}
		switch host {
		case ipv4Loopback:
			ipv4Port = port
		case ipv6Loopback:
			ipv6Port = port
		}
	}
	if len(addresses) != 2 || ipv4Port == "" || ipv6Port == "" {
		t.Fatalf("the started line named %q, want one listener at 127.0.0.1 and one at [::1]", addresses)
	}
	return ipv4Port, ipv6Port
}

// heldPort finds a port free at both loopback addresses and holds it at both; the caller closes
// the ones the program is to take.
func heldPort(t *testing.T) (port string, ipv4, ipv6 net.Listener) {
	t.Helper()
	for range 50 {
		first, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listening on 127.0.0.1: %v", err)
		}
		var splitErr error
		_, port, splitErr = net.SplitHostPort(first.Addr().String())
		if splitErr != nil {
			t.Fatalf("the listening address %s: %v", first.Addr(), splitErr)
		}
		second, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", net.JoinHostPort(ipv6Loopback, port))
		if err != nil {
			_ = first.Close()
			continue
		}
		t.Cleanup(func() {
			_ = first.Close()
			_ = second.Close()
		})
		return port, first, second
	}
	t.Fatalf("no port was free at both 127.0.0.1 and ::1 in 50 tries")
	return "", nil, nil
}

// expectRefused checks a dial to the address is refused: nothing listens there.
func expectRefused(t *testing.T, address string) {
	t.Helper()
	connection, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(t.Context(), "tcp", address)
	if err == nil {
		_ = connection.Close()
		t.Errorf("a caller reached %s, where the engine may not listen", address)
		return
	}
	if !isRefused(err) {
		t.Errorf("a dial to %s failed other than by a refusal: %v", address, err)
	}
}

// otherAddresses are this machine's addresses that are not loopback and not link-local: a dial
// to a link-local address needs a zone and may time out rather than be refused.
func otherAddresses(t *testing.T) []net.IP {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("listing this machine's addresses: %v", err)
	}
	var others []net.IP
	for _, address := range addresses {
		network, isNetwork := address.(*net.IPNet)
		if isNetwork && !network.IP.IsLoopback() && !network.IP.IsLinkLocalUnicast() {
			others = append(others, network.IP)
		}
	}
	return others
}
