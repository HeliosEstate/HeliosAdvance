// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package ssh_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

var (
	programPath  string
	buildFailure error
)

// startLimit is how long the program may take to name its listeners.
var startLimit = testrun.Patient(30 * time.Second)

// TestMain builds the program the page's rows run from outside, under the race detector when
// the tests run under it. A build that fails fails every such row with its reason, rather than
// stopping before any runs; the contract's rows need no program. It also prepares the database
// the program needs before it listens. First it makes this run's own folder, taking what dead
// runs left, so that everything the run makes, the program included, lands there.
func TestMain(tests *testing.M) {
	runFolder, swept, err := testrun.Enter()
	if swept != nil {
		fmt.Fprintf(os.Stderr, "what dead runs left: %v\n", swept)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "the run's own folder: %v\n", err)
		_ = testrun.Leave(runFolder)
		os.Exit(1)
	}
	oracleFailure = prepareOracle()
	directory, err := os.MkdirTemp("", "hadv-service-ssh-test-")
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
		arguments = append(arguments, "../../cmd/hadv-service")
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

// engine is one start of the built program, its local log kept as it comes.
type engine struct {
	command   *exec.Cmd
	mutex     sync.Mutex
	log       []byte
	firstLine chan string
	exited    chan struct{}
	exitCode  int
	ssh       string
	telnet    string
	key       string
}

// startEngine starts the program with a host key ssh-keygen made for the row and ports the
// system picks, and waits for its started line.
func startEngine(t *testing.T) *engine {
	t.Helper()
	key := makeKey(t, "ed25519", "")
	program := runProgram(t, "-port", "0", "-ssh-host-key", key, "-ssh-port", "0")
	program.key = key
	line := program.first(t)
	value, found := strings.CutPrefix(line, "started=")
	if !found {
		t.Fatalf("the program's first log line was %q, want a started line", line)
	}
	for _, listener := range strings.Split(value, ",") {
		if address, ok := strings.CutPrefix(listener, "ssh://127.0.0.1:"); ok {
			program.ssh = "127.0.0.1:" + address
		}
		if address, ok := strings.CutPrefix(listener, "telnet://127.0.0.1:"); ok {
			program.telnet = "127.0.0.1:" + address
		}
	}
	if program.ssh == "" || program.telnet == "" {
		t.Fatalf("the started line %q names no SSH or no Telnet listener at 127.0.0.1", line)
	}
	return program
}

// runProgram starts the built program with options, killed when the row ends.
func runProgram(t *testing.T, options ...string) *engine {
	t.Helper()
	if buildFailure != nil {
		t.Fatalf("the program did not build: %v", buildFailure)
	}
	command := exec.CommandContext(t.Context(), programPath, append([]string{databaseOption, sharedRowFile(t)}, options...)...)
	command.WaitDelay = testrun.Patient(5 * time.Second)
	if testrun.Race {
		command.Env = append(os.Environ(), "GORACE=atexit_sleep_ms=0")
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		t.Fatalf("the program's standard error: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("starting the program: %v", err)
	}
	program := &engine{command: command, firstLine: make(chan string, 1), exited: make(chan struct{})}
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

func (program *engine) read(stderr io.Reader) {
	reader := bufio.NewReader(stderr)
	first := true
	for {
		line, err := reader.ReadString('\n')
		program.mutex.Lock()
		program.log = append(program.log, line...)
		program.mutex.Unlock()
		if first && line != "" {
			program.firstLine <- strings.TrimSuffix(line, "\n")
			first = false
		}
		if err != nil {
			break
		}
	}
	_ = program.command.Wait()
	program.mutex.Lock()
	program.exitCode = program.command.ProcessState.ExitCode()
	program.mutex.Unlock()
	close(program.exited)
}

func (program *engine) first(t *testing.T) string {
	t.Helper()
	select {
	case line := <-program.firstLine:
		return line
	case <-program.exited:
		t.Fatalf("the program exited with %d before its first log line; its log:\n%s", program.code(), program.text())
	case <-time.After(startLimit):
		t.Fatalf("the program wrote no log line within %v", startLimit)
	}
	return ""
}

func (program *engine) code() int {
	program.mutex.Lock()
	defer program.mutex.Unlock()
	return program.exitCode
}

func (program *engine) text() string {
	program.mutex.Lock()
	defer program.mutex.Unlock()
	return string(program.log)
}

// expectOnlyStarted fails the row unless the log holds the started line alone.
func (program *engine) expectOnlyStarted(t *testing.T) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(program.text(), "\n"), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "started=") {
		t.Fatalf("the log held %q, want the started line alone", program.text())
	}
}
