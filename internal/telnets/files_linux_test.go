// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package telnets_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/telnets"
	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// namedPipe makes a named pipe that nothing ever opens for writing, so a read, or an open for
// reading that waits on a writer, would wait for good.
func namedPipe(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pipe.pem")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("making a named pipe: %v", err)
	}
	return path
}

// refusedBy calls ReadCertificate on its own goroutine and returns when it returned and its
// error, failing the row if it has not returned by the hang bound.
func refusedBy(t *testing.T, files tlsFiles) (time.Time, error) {
	t.Helper()
	type result struct {
		certificate *telnets.Certificate
		err         error
		returned    time.Time
	}
	done := make(chan result, 1)
	go func() {
		certificate, err := telnets.ReadCertificate(files.certificate, files.key)
		done <- result{certificate, err, time.Now()}
	}()
	timer := time.NewTimer(testrun.Patient(testrun.HangBound))
	defer timer.Stop()
	select {
	case got := <-done:
		if got.err == nil || got.certificate != nil {
			t.Fatalf("ReadCertificate gave %v and %v, want a refusal", got.certificate, got.err)
		}
		return got.returned, got.err
	case <-timer.C:
		t.Fatalf("ReadCertificate had not returned within %v: it waited on the file", testrun.Patient(testrun.HangBound))
		return time.Time{}, nil
	}
}

// TestLinuxReadCertificate is Linux's alone because its rows are: a file's mode, a named pipe,
// and a file an ordinary user cannot open.
func TestLinuxReadCertificate(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Fatalf("these rows need an ordinary user: root opens a file of any mode")
	}

	t.Run("ReadCertificate shall check the certificate file and then the key file, in the order of these lines, and return the first refusal that applies.", func(t *testing.T) {
		t.Parallel()
		t.Run("a key file of mode 0644 holding no PEM: ErrKeyReadableByOthers", func(t *testing.T) {
			t.Parallel()
			key := writeFile(t, []byte(canary+" is not PEM\n"))
			setMode(t, key, 0o644)
			expectRefusal(t, tlsFiles{certificate: goodFiles(t, ecdsaP256).certificate, key: key}, telnets.ErrKeyReadableByOthers)
		})
		t.Run("a folder of mode 0755 as the key file: ErrTLSFileNotRegular", func(t *testing.T) {
			t.Parallel()
			folder := t.TempDir()
			setMode(t, folder, 0o755)
			expectRefusal(t, tlsFiles{certificate: goodFiles(t, ecdsaP256).certificate, key: folder}, telnets.ErrTLSFileNotRegular)
		})
	})

	t.Run("If the file cannot be opened, then ReadCertificate shall return ErrTLSFileUnreadable.", func(t *testing.T) {
		t.Parallel()
		for _, which := range []string{certificateFile, keyFile} {
			t.Run("the "+which+" file of mode 0000: ErrTLSFileUnreadable", func(t *testing.T) {
				t.Parallel()
				files := goodFiles(t, ecdsaP256)
				setMode(t, chosen(files, which), 0)
				expectRefusal(t, files, telnets.ErrTLSFileUnreadable)
			})
		}
	})

	t.Run("If the opened file is not a regular file, such as a folder or a named pipe, then ReadCertificate shall return ErrTLSFileNotRegular, without reading it and without waiting on it, its open included.", func(t *testing.T) {
		t.Parallel()
		for _, which := range []string{certificateFile, keyFile} {
			t.Run("a named pipe with no writer as the "+which+" file: ErrTLSFileNotRegular, at once", func(t *testing.T) {
				t.Parallel()
				files := replaced(t, goodFiles(t, ecdsaP256), which, namedPipe(t))
				called := time.Now()
				returned, err := refusedBy(t, files)
				if !errors.Is(err, telnets.ErrTLSFileNotRegular) {
					t.Fatalf("ReadCertificate gave %v, want ErrTLSFileNotRegular", err)
				}
				expectWithin(t, "ReadCertificate's return", returned, called, called.Add(testrun.Patient(margin)))
			})
		}
	})

	t.Run("If, on Linux, the opened key file's mode lets its group or others read it, then ReadCertificate shall return ErrKeyReadableByOthers without reading the file.", func(t *testing.T) {
		t.Parallel()
		for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o444} {
			t.Run(fmt.Sprintf("a key file of mode %04o holding text that is no PEM, so a read first would refuse it otherwise: ErrKeyReadableByOthers", mode), func(t *testing.T) {
				t.Parallel()
				key := writeFile(t, []byte(canary+" is not PEM\n"))
				setMode(t, key, mode)
				expectRefusal(t, tlsFiles{certificate: goodFiles(t, ecdsaP256).certificate, key: key}, telnets.ErrKeyReadableByOthers)
			})
		}
		for _, mode := range []os.FileMode{0o600, 0o400, 0o620} {
			t.Run(fmt.Sprintf("the edge: a good key file of mode %04o is read", mode), func(t *testing.T) {
				t.Parallel()
				files := goodFiles(t, ecdsaP256)
				setMode(t, files.key, mode)
				readCertificate(t, files)
			})
		}
		t.Run("the edge: a certificate file of mode 0644 is read", func(t *testing.T) {
			t.Parallel()
			files := goodFiles(t, ecdsaP256)
			setMode(t, files.certificate, 0o644)
			readCertificate(t, files)
		})
	})

	t.Run("ReadCertificate shall return an error whose text names the file it is about, the certificate file or the key file, and holds no part of either file's contents.", func(t *testing.T) {
		t.Parallel()
		t.Run("mode 0000, as either file: the certificate file's text differs from the key file's, and neither holds 8 characters in a row of the files", func(t *testing.T) {
			t.Parallel()
			certificateBad := goodFiles(t, ecdsaP256)
			keyBad := goodFiles(t, ecdsaP256)
			parts := append(bodies(t, certificateBad.certificate, keyBad.key), canary)
			setMode(t, certificateBad.certificate, 0)
			setMode(t, keyBad.key, 0)
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
		t.Run("a key file of mode 0644: the text holds no 8 characters in a row of either file", func(t *testing.T) {
			t.Parallel()
			files := goodFiles(t, ecdsaP256)
			setMode(t, files.key, 0o644)
			err := refusedWith(t, files, telnets.ErrKeyReadableByOthers)
			if holdsPart(err.Error(), append(bodies(t, files.certificate, files.key), canary)) {
				t.Fatalf("the error's text %q holds part of a file", err)
			}
		})
	})
}
