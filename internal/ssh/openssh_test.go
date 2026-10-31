// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package ssh_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// openSSHCall is one run of the OpenSSH client, the oracle for the call, against the program.
type openSSHCall struct {
	// terminal is -tt, a terminal asked for whatever the input is; otherwise -T.
	terminal bool
	// options go before the destination; command after it.
	options []string
	command []string
	user    string
	// waitFor is held for before typed is written; the input stays open until the output ends,
	// unless closeInput, when it is closed after typed.
	waitFor    string
	typed      string
	closeInput bool
	verbose    bool
	// afterPrompt runs once waitFor has arrived, before typed is written.
	afterPrompt func()
}

type openSSHResult struct {
	stdout   []byte
	stderr   string
	exitCode int
}

// runOpenSSH runs the client with no configuration of the runner's own, the program's host key as
// the only one it trusts, and no escape character, so any byte typed reaches the engine.
func runOpenSSH(t *testing.T, program *engine, call openSSHCall) openSSHResult {
	t.Helper()
	directory := t.TempDir()
	config := filepath.Join(directory, "config")
	if err := os.WriteFile(config, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	public, err := os.ReadFile(program.key + ".pub")
	if err != nil {
		t.Fatalf("the host key's public half: %v", err)
	}
	host, port, err := net.SplitHostPort(program.ssh)
	if err != nil {
		t.Fatal(err)
	}
	known := filepath.Join(directory, "known_hosts")
	line := "[" + host + "]:" + port + " " + strings.TrimSpace(string(public)) + "\n"
	if err := os.WriteFile(known, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	// The paths go with forward slashes, which every client the rows run reads whole: on Windows a
	// path of backslashes holding a parenthesis, as a row's folder does when its line names a
	// byte as (0x15), was not.
	arguments := []string{"-F", filepath.ToSlash(config), "-o", "UserKnownHostsFile=" + filepath.ToSlash(known), "-o", "StrictHostKeyChecking=yes",
		"-o", "BatchMode=yes", "-e", "none", "-p", port}
	if call.verbose {
		arguments = append(arguments, "-vvv")
	} else {
		arguments = append(arguments, "-o", "LogLevel=ERROR")
	}
	if call.terminal {
		arguments = append(arguments, "-tt")
	} else {
		arguments = append(arguments, "-T")
	}
	arguments = append(arguments, call.options...)
	user := call.user
	if user == "" {
		user = "anyone"
	}
	arguments = append(arguments, user+"@"+host)
	arguments = append(arguments, call.command...)
	ctx, cancel := context.WithTimeout(t.Context(), testrun.Patient(30*time.Second))
	defer cancel()
	command := exec.CommandContext(ctx, "ssh", arguments...)
	command.WaitDelay = testrun.Patient(testrun.HangBound)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var errorOutput bytes.Buffer
	command.Stderr = &errorOutput
	if err := command.Start(); err != nil {
		t.Fatalf("starting the OpenSSH client: %v", err)
	}
	var stdout []byte
	buffer := make([]byte, 4096)
	if call.waitFor != "" {
		for !bytes.Contains(stdout, []byte(call.waitFor)) {
			read, err := output.Read(buffer)
			stdout = append(stdout, buffer[:read]...)
			if err != nil {
				break
			}
		}
	}
	if call.afterPrompt != nil {
		call.afterPrompt()
	}
	if call.typed != "" {
		_, _ = io.WriteString(input, call.typed)
	}
	if call.closeInput {
		_ = input.Close()
	}
	rest, readErr := io.ReadAll(output)
	if readErr != nil {
		t.Logf("the client's output ended with %v", readErr)
	}
	stdout = append(stdout, rest...)
	_ = input.Close()
	err = command.Wait()
	code := 0
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		code = exitError.ExitCode()
	} else if err != nil {
		t.Fatalf("the OpenSSH client: %v; it wrote %q", err, errorOutput.String())
	}
	return openSSHResult{stdout: stdout, stderr: errorOutput.String(), exitCode: code}
}

// forwardingResult is a call that forwarded a local port, and what the forwarded connection read.
type forwardingResult struct {
	openSSHResult
	forwardedBytes int
	forwardedEnd   error
}

// runOpenSSHForwarding runs a call with -L from local to a port on the engine's side, dials the
// forward once the prompt has come, and then types the name.
func runOpenSSHForwarding(t *testing.T, program *engine, local string) forwardingResult {
	t.Helper()
	var result forwardingResult
	call := openSSHCall{options: []string{"-L", local + ":127.0.0.1:9"}, waitFor: prompt, typed: typedBob}
	call.afterPrompt = func() {
		dialer := net.Dialer{Timeout: testrun.Patient(testrun.HangBound)}
		forwarded, err := dialer.DialContext(t.Context(), "tcp4", "127.0.0.1:"+local)
		if err != nil {
			result.forwardedEnd = err
			return
		}
		defer func() { _ = forwarded.Close() }()
		_ = forwarded.SetReadDeadline(time.Now().Add(testrun.Patient(testrun.HangBound)))
		buffer := make([]byte, 64)
		result.forwardedBytes, result.forwardedEnd = forwarded.Read(buffer)
	}
	result.openSSHResult = runOpenSSH(t, program, call)
	return result
}

// freePort is a port the system picked at 127.0.0.1 and released.
func freePort(t *testing.T) string {
	t.Helper()
	socket, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(socket.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = socket.Close()
	return port
}

// expectCall is the OpenSSH client's whole call: exactly want on its output and exit code 0.
func expectCall(t *testing.T, result openSSHResult, want string) {
	t.Helper()
	if string(result.stdout) != want || result.exitCode != 0 {
		t.Fatalf("the client wrote %q and exited %d (%s), want %q and 0", result.stdout, result.exitCode, result.stderr, want)
	}
}

// expectRefused is the OpenSSH client refused: exit code 255, and on its output nothing, or at
// most the greeting and the prompt when the refusal of something it asked after the shell comes
// late.
func expectRefused(t *testing.T, result openSSHResult) {
	t.Helper()
	if result.exitCode != 255 || !strings.HasPrefix(greeting+prompt, string(result.stdout)) {
		t.Fatalf("the client wrote %q and exited %d (%s), want no call and 255", result.stdout, result.exitCode, result.stderr)
	}
}
