// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// What only Windows runs: the stop signal as a console break, and SSH and Telnet over TLS on
// their seeded ports, 22 and 992, which an ordinary user may listen on at loopback on Windows but
// not on Linux.
package main_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// processAttributes puts each program in a process group of its own, so that a console break
// sent to that group reaches the program alone.
func processAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}

// stopSignals is Ctrl-Break: Windows cannot send Ctrl-C to a process group of its own.
func stopSignals() []stopSignal {
	return []stopSignal{{name: "Ctrl-Break", prepare: prepareBreak}}
}

// breakScript sends a console break to each process group whose number arrives on its input.
// The standard library has no GenerateConsoleCtrlEvent and the lint refuses loading a DLL by
// name, so PowerShell calls it; it compiles its type before it says it is ready, because that
// takes seconds and would otherwise fall inside the window a row times.
const breakScript = `$k = Add-Type -PassThru -Name ConsoleBreak -Namespace HeliosTest -MemberDefinition '[DllImport("kernel32.dll", SetLastError=true)] public static extern bool GenerateConsoleCtrlEvent(uint e, uint g);'
[Console]::Out.WriteLine('ready'); [Console]::Out.Flush()
while ($null -ne ($line = [Console]::In.ReadLine())) { $r = $k::GenerateConsoleCtrlEvent(1, [uint32]$line); [Console]::Out.WriteLine("sent=$r"); [Console]::Out.Flush() }`

// prepareBreak starts the sender and waits until it is ready; the returned function sends the
// program a console break and gives a moment before it was sent and one after.
func prepareBreak(t *testing.T) func(*testing.T, *run) (time.Time, time.Time) {
	t.Helper()
	// Not the row's context, which ends, and so kills the sender, before the cleanup below runs:
	// killed that way it left an empty folder in Temp each time on CI, where closing its input
	// first ends it whole.
	sender := exec.CommandContext(context.WithoutCancel(t.Context()), "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", breakScript)
	input, err := sender.StdinPipe()
	if err != nil {
		t.Fatalf("the break sender's input: %v", err)
	}
	output, err := sender.StdoutPipe()
	if err != nil {
		t.Fatalf("the break sender's output: %v", err)
	}
	if err := sender.Start(); err != nil {
		t.Fatalf("starting the break sender: %v", err)
	}
	t.Cleanup(func() {
		_ = input.Close()
		exited := make(chan struct{})
		go func() {
			_ = sender.Wait()
			close(exited)
		}()
		// A sender that does not end with its input is killed, so a stuck one cannot hang the run.
		select {
		case <-exited:
		case <-time.After(testrun.Patient(30 * time.Second)):
			_ = sender.Process.Kill()
			<-exited
		}
	})
	lines := make(chan string, 4)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			lines <- strings.TrimSpace(scanner.Text())
		}
	}()
	if line := nextLine(t, lines, 120*time.Second); line != "ready" {
		t.Fatalf("the break sender said %q, want ready", line)
	}
	return func(t *testing.T, program *run) (time.Time, time.Time) {
		t.Helper()
		from := time.Now()
		if _, err := io.WriteString(input, fmt.Sprintf("%d\n", program.command.Process.Pid)); err != nil {
			t.Fatalf("asking for the break: %v", err)
		}
		if line := nextLine(t, lines, 30*time.Second); line != "sent=True" {
			t.Fatalf("the break sender said %q, want sent=True", line)
		}
		return from, time.Now()
	}
}

func nextLine(t *testing.T, lines chan string, limit time.Duration) string {
	t.Helper()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case line, open := <-lines:
		if !open {
			t.Fatalf("the break sender ended")
		}
		return line
	case <-timer.C:
		t.Fatalf("the break sender said nothing within %v", limit)
	}
	return ""
}

// TestWindowsDefaultPort runs alone, its rows one after the other, so that while a row runs no
// other engine does and a fixed port held then is the machine's own. Beside other rows, an engine
// that wrongly listened at 22 or 992 would hold it in their engines too, and the row would skip
// the very fault it is there to see.
func TestWindowsDefaultPort(t *testing.T) { //nolint:paralleltest // it must run alone
	t.Run("The engine shall listen for SSH callers at 127.0.0.1 and ::1 on its server's `ssh_port`, beside its other listeners.", func(t *testing.T) { //nolint:paralleltest // it must run alone
		t.Run("ssh_port the seeded 22: at 22 where it is free at both addresses; else refused, where an SSH port the system picks starts", func(t *testing.T) { //nolint:paralleltest // it must run alone
			defaultSSHPortRow(t)
		})
	})
	t.Run("The engine shall listen for Telnet over TLS callers at 127.0.0.1 and ::1 on its server's `telnets_port`, beside its other listeners.", func(t *testing.T) { //nolint:paralleltest // it must run alone
		t.Run("telnets_port the seeded 992: at 992 where it opens at each address; refused where it opens at neither, where a TLS port the system picks starts", func(t *testing.T) { //nolint:paralleltest // it must run alone
			defaultTLSPortRow(t)
		})
	})
}
