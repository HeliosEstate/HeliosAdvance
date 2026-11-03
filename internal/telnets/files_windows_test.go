// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package telnets_test

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/telnets"
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

// lockFromReading holds a lock on the whole file until the row ends, so it can be opened but not
// read. Windows has no file an ordinary process cannot open that an administrator whose backup
// privilege is enabled, as on CI's runner, cannot open too; a lock on its bytes holds for every
// reader.
func lockFromReading(t *testing.T, path string) {
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

// TestWindowsReadCertificate is Windows' alone because its rows are: a file opened but held from
// reading by a lock on its bytes.
func TestWindowsReadCertificate(t *testing.T) {
	t.Parallel()

	t.Run("If the opened file cannot be read, then ReadCertificate shall return ErrTLSFileUnreadable.", func(t *testing.T) {
		t.Parallel()
		for _, which := range []string{certificateFile, keyFile} {
			t.Run("the "+which+" file locked against reading: ErrTLSFileUnreadable", func(t *testing.T) {
				t.Parallel()
				files := goodFiles(t, ecdsaP256)
				lockFromReading(t, chosen(files, which))
				expectRefusal(t, files, telnets.ErrTLSFileUnreadable)
			})
		}
	})

	t.Run("ReadCertificate shall return an error whose text names the file it is about, the certificate file or the key file, and holds no part of either file's contents.", func(t *testing.T) {
		t.Parallel()
		t.Run("locked against reading, as either file: the certificate file's text differs from the key file's, and neither holds 8 characters in a row of the files", func(t *testing.T) {
			t.Parallel()
			certificateBad := goodFiles(t, ecdsaP256)
			keyBad := goodFiles(t, ecdsaP256)
			parts := append(bodies(t, certificateBad.certificate, keyBad.key), canary)
			lockFromReading(t, certificateBad.certificate)
			lockFromReading(t, keyBad.key)
			certificateErr := refusedWith(t, certificateBad, telnets.ErrTLSFileUnreadable)
			keyErr := refusedWith(t, keyBad, telnets.ErrTLSFileUnreadable)
			if certificateErr.Error() == keyErr.Error() {
				t.Fatalf("the certificate file and the key file gave the same text, %q", certificateErr)
			}
			for _, err := range []error{certificateErr, keyErr} {
				if holdsPart(err.Error(), parts) {
					t.Fatalf("the error's text %q holds part of a file", err)
				}
			}
		})
	})
}
