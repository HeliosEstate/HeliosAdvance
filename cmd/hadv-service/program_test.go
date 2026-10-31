// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The program run from outside: TestMain builds cmd/hadv-service once and prepares its database,
// and each row starts the built program with its own options and a connection file for a row of
// its own, reads its standard error as the local log, drives it with the scripted Telnet caller
// over loopback, and waits for it to exit.
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

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// The loopback addresses and the port option, as the page and the issue name them.
const (
	ipv4Loopback = "127.0.0.1"
	ipv6Loopback = "::1"
	portOption   = "-port"
)

// startLimit bounds how long the program may take to name its listeners or to exit after a
// refusal. The page gives it no limit; this one only keeps a hung program from hanging the run.
var startLimit = testrun.Patient(30 * time.Second)

var (
	programPath  string
	buildFailure error
)

// TestMain builds the program the rows run, under the race detector when the tests run under
// it, and prepares the database every run needs. A build or a database that fails fails every
// row with its reason, rather than stopping before any runs. First it makes this run's own
// folder, taking what dead runs left, so that everything the run makes, the program included,
// lands there.
func TestMain(tests *testing.M) {
	runFolder, swept, err := testrun.Enter()
	if swept != nil {
		fmt.Fprintf(os.Stderr, "what dead runs left: %v\n", swept)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "the run's own folder: %v\n", err)
		if err := testrun.Leave(runFolder); err != nil {
			fmt.Fprintf(os.Stderr, "removing the run's own folder: %v\n", err)
		}
		os.Exit(1)
	}
	oracleFailure = prepareOracle()
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
		if testrun.Race {
			arguments = append(arguments, "-race")
		}
		arguments = append(arguments, ".")
		output, buildErr := exec.CommandContext(context.Background(), "go", arguments...).CombinedOutput()
		if buildErr != nil {
			buildFailure = fmt.Errorf("%w: %s", buildErr, strings.TrimSpace(string(output)))
		}
	}
	code := tests.Run()
	stopOracle()
	// Logged, not failed: whether Windows has let go of every file by now is its timing, and
	// the next run takes what is left.
	if err := testrun.Leave(runFolder); err != nil {
		fmt.Fprintf(os.Stderr, "removing the run's own folder: %v\n", err)
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
	entries  []logEntry
	exitCode int
	exitedAt time.Time
}

// logEntry is one line of the local log and when the test read it.
type logEntry struct {
	line string
	read time.Time
}

// startProgram starts the built program with a connection file for a row of its own on the
// shared board, then the given options, killed when the test ends.
func startProgram(t *testing.T, options ...string) *run {
	t.Helper()
	return startBare(t, append([]string{databaseOption, sharedRowFile(t)}, options...)...)
}

// startBare starts the built program with the given options alone, killed when the test ends.
func startBare(t *testing.T, options ...string) *run {
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
	command.WaitDelay = testrun.Patient(testrun.HangBound)
	// A program built with the race detector sleeps a second at exit by default, waiting for late
	// reports, which would read as a slow exit; a race it finds still reaches the log and fails
	// the row.
	if testrun.Race {
		if command.Env == nil {
			command.Env = os.Environ()
		}
		command.Env = append(command.Env, "GORACE=atexit_sleep_ms=0")
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
		if line != "" {
			program.entries = append(program.entries, logEntry{line: strings.TrimSuffix(line, "\n"), read: time.Now()})
		}
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

// listening waits for the started line of a program with SSH off and returns the addresses it
// names, each of which must be a Telnet listener's URL: the program listens for no SSH caller.
func (program *run) listening(t *testing.T) []string {
	t.Helper()
	return telnetAlone(t, program.listeners(t))
}

// telnetAlone returns a started line's Telnet addresses, failing the row if it names an SSH one:
// the program was started with SSH off.
func telnetAlone(t *testing.T, listeners []string) []string {
	t.Helper()
	telnet, ssh := kindsOf(t, listeners)
	if len(ssh) > 0 {
		t.Fatalf("the started line names SSH listeners %q, with SSH off", ssh)
	}
	return telnet
}

// freedPortTries bounds startOnFreedPort: the race it tries again on was met once in all of PR
// 129's runs (HeliosDesign #190), so a row that meets it this often is broken, not unlucky.
const freedPortTries = 5

// startOnFreedPort holds a port free at both loopback addresses, closes the hosts the row names
// in freed, and starts the program with options(port). Between that close and the program's own
// listen, a test running in parallel may bind a freed address, and the program does not reach
// the row's case: with every freed address taken it fails to start, and with one of two taken it
// listens at the other alone. A start_failed line that names a freed address as in use, or a
// started line that leaves a freed address out, is that race, so the row tries a fresh port. Any
// other first line is judged as listeners judges it, so a program that refuses over the address
// the row holds still fails the row. A build that never listens at a freed address leaves it out
// on every port, so the row fails once the tries run out. It returns the port and the started
// line's listeners.
func startOnFreedPort(t *testing.T, freed []string, options func(port string) []string) (string, []string) {
	t.Helper()
	var line string
	for range freedPortTries {
		port, ipv4, ipv6 := heldPort(t)
		for _, host := range freed {
			switch host {
			case ipv4Loopback:
				_ = ipv4.Close()
			case ipv6Loopback:
				_ = ipv6.Close()
			}
		}
		program := startProgram(t, options(port)...)
		line = program.firstLine(t)
		if takenWhileFreed(line, port, freed) {
			t.Logf("a freed address was taken before the program listened, %q: trying a fresh port", line)
			continue
		}
		value, found := strings.CutPrefix(line, "started=")
		if !found {
			t.Fatalf("the program's first log line was %q, want a started line", line)
		}
		listeners := strings.Split(value, ",")
		if address := unnamedFreed(listeners, port, freed); address != "" {
			t.Logf("the started line %q leaves out the freed address %s, which a test running in parallel may have taken: trying a fresh port", line, address)
			_ = program.command.Process.Kill()
			<-program.exited
			continue
		}
		return port, listeners
	}
	t.Fatalf("on each of %d ports the program did not listen at every freed address; the last first line: %q", freedPortTries, line)
	return "", nil
}

// unnamedFreed returns a freed address at the port that no listener in the started line names,
// or "" when it names them all.
func unnamedFreed(listeners []string, port string, freed []string) string {
	for _, host := range freed {
		address := net.JoinHostPort(host, port)
		named := slices.ContainsFunc(listeners, func(listener string) bool {
			return strings.HasSuffix(listener, "://"+address)
		})
		if !named {
			return address
		}
	}
	return ""
}

// takenWhileFreed is whether a start_failed line says a listen at one of the freed addresses
// failed because the address was in use, as Linux and Windows word it.
func takenWhileFreed(line, port string, freed []string) bool {
	if !strings.HasPrefix(line, "start_failed=") {
		return false
	}
	for _, host := range freed {
		_, after, found := strings.Cut(line, net.JoinHostPort(host, port)+": bind: ")
		if !found {
			continue
		}
		reason, _, _ := strings.Cut(after, `\n`)
		if strings.Contains(reason, "address already in use") || strings.Contains(reason, "Only one usage of each socket address") {
			return true
		}
	}
	return false
}

// kinds waits for the started line and returns the addresses it names, Telnet's and SSH's, each
// written as telnet://host:port or ssh://host:port, in the line's order; anything else in the
// line fails the row.
func (program *run) kinds(t *testing.T) (telnet, ssh []string) {
	t.Helper()
	return kindsOf(t, program.listeners(t))
}

// kindsOf sorts a started line's listeners into Telnet's addresses and SSH's.
func kindsOf(t *testing.T, listeners []string) (telnet, ssh []string) {
	t.Helper()
	for _, listener := range listeners {
		if address, found := strings.CutPrefix(listener, "telnet://"); found {
			telnet = append(telnet, address)
		} else if address, found := strings.CutPrefix(listener, "ssh://"); found {
			ssh = append(ssh, address)
		} else {
			t.Fatalf("the started line names %q, which is not a telnet:// or an ssh:// listener", listener)
		}
	}
	return telnet, ssh
}

// listeners waits for the program's first log line, which must be the started line, and returns
// what it names, as written.
func (program *run) listeners(t *testing.T) []string {
	t.Helper()
	line := program.firstLine(t)
	value, found := strings.CutPrefix(line, "started=")
	if !found {
		t.Fatalf("the program's first log line was %q, want a started line", line)
	}
	return strings.Split(value, ",")
}

// firstLine waits for the program's first log line. read hands a line on before it marks the
// exit, so a program that logs a line and exits has that line waiting once the exit shows; it is
// read then, rather than lost to whichever ready case the select picks.
func (program *run) firstLine(t *testing.T) string {
	t.Helper()
	timer := time.NewTimer(startLimit)
	defer timer.Stop()
	select {
	case line := <-program.lines:
		return line
	case <-program.exited:
		select {
		case line := <-program.lines:
			return line
		default:
		}
		t.Fatalf("the program exited with %d before it named a listener; its log:\n%s", program.code(), program.text())
	case <-timer.C:
		t.Fatalf("the program named no listener within %v", startLimit)
	}
	return ""
}

// exit waits for the program to exit, by the deadline, and returns its exit code and when.
func (program *run) exit(t *testing.T, deadline time.Time) (int, time.Time) {
	t.Helper()
	// An exit already made wins over a give-up already run out: a test that came late to wait
	// would otherwise get either, by chance.
	select {
	case <-program.exited:
	default:
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		select {
		case <-program.exited:
		case <-timer.C:
			t.Fatalf("the program had not exited by the deadline; its log so far:\n%s", program.text())
		}
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
var logKeys = []string{"started", "start_failed", "waiting", "lease_lost"}

// waitForLine waits, by the deadline, for the local log's line at index, and returns its key, its
// value and when it was read. A program that exits first, or a line that does not come, fails
// the row.
func (program *run) waitForLine(t *testing.T, index int, deadline time.Time) (string, string, time.Time) {
	t.Helper()
	for {
		program.mutex.Lock()
		var entry *logEntry
		if index < len(program.entries) {
			entry = &program.entries[index]
		}
		program.mutex.Unlock()
		if entry != nil {
			key, value, _ := strings.Cut(entry.line, "=")
			return key, value, entry.read
		}
		select {
		case <-program.exited:
			program.mutex.Lock()
			count := len(program.entries)
			program.mutex.Unlock()
			if index < count {
				continue
			}
			t.Fatalf("the program exited with %d before its log's line %d; its log:\n%s", program.code(), index+1, program.text())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the program's log had no line %d by %v; its log:\n%s", index+1, deadline.Format(time.RFC3339Nano), program.text())
		}
		pause(t, 20*time.Millisecond)
	}
}

// expectLine waits for the local log's line at index and checks its key, returning its value
// and when it was read.
func (program *run) expectLine(t *testing.T, index int, want string, deadline time.Time) (string, time.Time) {
	t.Helper()
	key, value, read := program.waitForLine(t, index, deadline)
	if key != want {
		t.Fatalf("the program's log's line %d is %s=%s, want a %s line; its log:\n%s", index+1, key, value, want, program.text())
	}
	return value, read
}

// lineCount is how many lines the local log holds so far.
func (program *run) lineCount() int {
	program.mutex.Lock()
	defer program.mutex.Unlock()
	return len(program.entries)
}

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
	connection, err := (&net.Dialer{Timeout: testrun.Patient(testrun.HangBound)}).DialContext(t.Context(), "tcp", address)
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
