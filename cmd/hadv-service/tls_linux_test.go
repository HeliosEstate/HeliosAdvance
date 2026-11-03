// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main_test

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// TestLinuxTLSProgram is Linux's alone because its rows are: the key file's mode, cut to Linux by
// the page; a named pipe and a character device; port 992, which Linux keeps from an ordinary
// user; port 65535, which Windows hands out for port 0; and the system's table of sockets.
func TestLinuxTLSProgram(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Fatalf("these rows need an ordinary user: root reads a file of any mode, and listens at 992")
	}

	t.Run("When the sysop passes a TLS certificate file and its key file on the command line, the engine shall listen for Telnet over TLS callers at 127.0.0.1 and ::1 on port 992, beside its other listeners.", func(t *testing.T) {
		t.Parallel()
		t.Run("with a certificate and a key and no TLS port, as an ordinary user who may not listen below 1024: refused, 992 opening at neither address, where a TLS port the system picks starts", func(t *testing.T) {
			t.Parallel()
			setting, err := os.ReadFile("/proc/sys/net/ipv4/ip_unprivileged_port_start")
			if err != nil {
				t.Fatalf("reading the lowest port an ordinary user may listen on: %v", err)
			}
			if lowest, err := strconv.Atoi(strings.TrimSpace(string(setting))); err != nil || lowest <= 992 {
				t.Fatalf("this machine lets an ordinary user listen from port %q", setting)
			}
			defaultTLSPortRow(t)
		})
	})

	t.Run("When the sysop passes a Telnet over TLS port on the command line as well, the engine shall listen for Telnet over TLS callers on that port in place of port 992.", func(t *testing.T) {
		t.Parallel()
		t.Run("with -tls-port 65535, the highest port, it names and serves it", func(t *testing.T) {
			t.Parallel()
			highestPort.Lock()
			defer highestPort.Unlock()
			files := goodTLSFiles(t, tlsP256)
			program := startProgram(t, portOption, "0", tlsCertificateOption, files.certificate, tlsKeyOption, files.key, tlsPortOption, "65535")
			_, _, telnets := threeKinds(t, program.listeners(t))
			expectAddresses(t, telnets, "127.0.0.1:65535", "[::1]:65535")
			for _, address := range telnets {
				expectTLSServed(t, address)
			}
			_ = program.command.Process.Kill()
			<-program.exited
		})
	})

	t.Run("If, on Linux, the key file's mode lets its group or others read it, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o444} {
			t.Run(fmt.Sprintf("a key file of mode %04o: one start_failed line, a non-zero exit, a reason of its own", mode), func(t *testing.T) {
				t.Parallel()
				files := goodTLSFiles(t, tlsP256)
				setMode(t, files.key, mode)
				reason := tlsReason(t, files)
				missing := goodTLSFiles(t, tlsP256)
				missing.key = absentPath(t)
				protected := goodTLSFiles(t, tlsP256)
				protected.key = encryptedKey(t, protected.key, false)
				if slices.Contains([]string{tlsReason(t, missing), tlsReason(t, protected)}, reason) {
					t.Fatalf("the mode's reason %q is the same as another refusal's", reason)
				}
			})
		}
		for _, mode := range []os.FileMode{0o600, 0o400, 0o620} {
			t.Run(fmt.Sprintf("the edge: a key file of mode %04o starts", mode), func(t *testing.T) {
				t.Parallel()
				files := goodTLSFiles(t, tlsP256)
				setMode(t, files.key, mode)
				startTLS(t, files)
			})
		}
		t.Run("the edge: a certificate file of mode 0644 starts", func(t *testing.T) {
			t.Parallel()
			files := goodTLSFiles(t, tlsP256)
			setMode(t, files.certificate, 0o644)
			startTLS(t, files)
		})
	})

	t.Run("If either file's path names anything but a regular file, or the file is longer than 65,536 bytes, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		for _, which := range []string{certificateFile, keyFile} {
			t.Run("a named pipe no writer ever opens, as the "+which+" file: one start_failed line and a non-zero exit within the start limit", func(t *testing.T) {
				t.Parallel()
				pipe := filepath.Join(t.TempDir(), "pipe.pem")
				if err := syscall.Mkfifo(pipe, 0o600); err != nil {
					t.Fatalf("making a named pipe: %v", err)
				}
				tlsReason(t, replacedFile(goodTLSFiles(t, tlsP256), which, pipe))
			})
		}
		t.Run("a character device, /dev/zero, as the certificate file: one start_failed line and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			tlsReason(t, replacedFile(goodTLSFiles(t, tlsP256), certificateFile, "/dev/zero"))
		})
	})

	t.Run("The engine shall not write any part of the private key to the local log.", func(t *testing.T) {
		t.Parallel()
		t.Run("a key file of mode 0644, refused: the log holds no 8 characters in a row of it", func(t *testing.T) {
			t.Parallel()
			files := goodTLSFiles(t, tlsP256)
			setMode(t, files.key, 0o644)
			program := startProgram(t, files.options()...)
			expectFileRefused(t, program)
			expectNoKeyInLog(t, program.text(), files.key)
		})
	})

	t.Run("The engine shall listen for callers at 127.0.0.1 and at ::1, and at no other address.", func(t *testing.T) {
		t.Parallel()
		t.Run("with SSH and Telnet over TLS on, every listening socket the system's table shows for the program is at 127.0.0.1 or ::1, six of them", func(t *testing.T) {
			t.Parallel()
			files := goodTLSFiles(t, tlsP256)
			program := startProgram(t, files.options(hostKeyOption, makeKey(t, "ed25519", ""), sshPortOption, "0")...)
			listeners := program.listeners(t)
			sockets := listeningSockets(t, program.command.Process.Pid)
			if len(sockets) != 6 {
				t.Fatalf("the system's table shows %q for the program, want six listening sockets; it named %q", sockets, listeners)
			}
			for _, socket := range sockets {
				host, _, err := net.SplitHostPort(socket)
				if err != nil || (host != ipv4Loopback && host != ipv6Loopback) {
					t.Errorf("the program listens at %s, which is not 127.0.0.1 or ::1; it named %q", socket, listeners)
				}
			}
		})
	})
}
