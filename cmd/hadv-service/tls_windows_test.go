// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main_test

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// lockScript opens the file named in HELIOS_LOCKED, sharing it with every other reader and
// writer, and holds a lock on its whole length until its input ends: another process may open
// the file but not read it. The standard library has no LockFileEx and the lint refuses loading
// a DLL by name, so PowerShell's FileStream takes the lock.
const lockScript = `$f = [System.IO.File]::Open($env:HELIOS_LOCKED, 'Open', 'Read', 'ReadWrite')
$f.Lock(0, [Math]::Max(1, $f.Length))
[Console]::Out.WriteLine('ready'); [Console]::Out.Flush()
[void][Console]::In.ReadToEnd()
$f.Close()`

// keepTLSFileFromReading holds a lock on the whole file until the row ends, so the program can
// open it but not read it. Windows has no file an ordinary process cannot open that an
// administrator whose backup privilege is enabled, as on CI's runner, cannot open too, and the
// folder keepFromReading puts in its place is a refusal of its own here; a lock on the file's
// bytes holds for every reader.
func keepTLSFileFromReading(t *testing.T, path string) {
	t.Helper()
	locker := exec.CommandContext(context.WithoutCancel(t.Context()), "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", lockScript)
	locker.Env = append(os.Environ(), "HELIOS_LOCKED="+path)
	input, err := locker.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := locker.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := locker.Start(); err != nil {
		t.Fatalf("starting the lock holder: %v", err)
	}
	t.Cleanup(func() {
		_ = input.Close()
		exited := make(chan struct{})
		go func() {
			_ = locker.Wait()
			close(exited)
		}()
		timer := time.NewTimer(testrun.Patient(30 * time.Second))
		defer timer.Stop()
		select {
		case <-exited:
		case <-timer.C:
			_ = locker.Process.Kill()
			<-exited
		}
	})
	ready := make(chan string, 1)
	go func() {
		line, err := bufio.NewReader(output).ReadString('\n')
		// A holder that said nothing fails the check below with the reason it said nothing.
		if err != nil && line == "" {
			line = err.Error()
		}
		ready <- strings.TrimSpace(line)
	}()
	timer := time.NewTimer(testrun.Patient(60 * time.Second))
	defer timer.Stop()
	select {
	case line := <-ready:
		if line != "ready" {
			t.Fatalf("the lock holder said %q, want ready", line)
		}
	case <-timer.C:
		t.Fatalf("the lock holder was not ready within %v", testrun.Patient(60*time.Second))
	}
}
