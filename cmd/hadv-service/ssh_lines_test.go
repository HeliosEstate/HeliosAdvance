// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The program's lines for SSH: the host key and port options, the refusals they bring, and the
// earlier lines that stand for an SSH caller as for a Telnet one, each driven from outside
// through the built program. An SSH listener is told by the version line it sends; the call
// itself is the ssh package's tests', which run the program too.
package main_test

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

const (
	hostKeyOption = "-ssh-host-key"
	sshPortOption = "-ssh-port"
	// sshVersionLine is the page's version line, which an SSH listener sends first.
	sshVersionLine = "SSH-2.0-HeliosAdvance\r\n"
)

// highestPort keeps the rows that take port 65535 from taking it at once.
var highestPort sync.Mutex

// isEnd is a read the engine ended: end of stream, or a reset.
func isEnd(err error) bool {
	return errors.Is(err, io.EOF) || isReset(err)
}

// makeKey runs ssh-keygen for a key of the given type and passphrase, as the sysop makes one.
func makeKey(t *testing.T, keyType, passphrase string, extra ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "host_key")
	arguments := append([]string{"-q", "-t", keyType, "-N", passphrase, "-C", "", "-f", path}, extra...)
	if output, err := exec.CommandContext(t.Context(), "ssh-keygen", arguments...).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen %v: %v %s", arguments, err, output)
	}
	return path
}

// expectSSHServed dials the address and checks it sends the version line by the margin.
func expectSSHServed(t *testing.T, address string) caller {
	t.Helper()
	call := dial(t, address)
	call.readExactly(t, []byte(sshVersionLine), call.connected.Add(testrun.Patient(margin)))
	return call
}

// malformedReason is the reason the program gives for a command line it cannot read.
func malformedReason(t *testing.T) string {
	t.Helper()
	return startProgram(t, portOption, "abc").expectRefusal(t)
}

// hostKeyReason is the reason the program gives when it refuses the key file at path, which must
// differ from a malformed command line's: the option was read, and the file refused.
func hostKeyReason(t *testing.T, path string) string {
	t.Helper()
	reason := startProgram(t, portOption, "0", hostKeyOption, path, sshPortOption, "0").expectRefusal(t)
	if reason == malformedReason(t) {
		t.Fatalf("the program refused the key file as a malformed command line: %q", reason)
	}
	expectSSHStarts(t)
	return reason
}

// expectSSHStarts is the edge every SSH refusal row ends with: the same program, given an Ed25519
// key with no passphrase and ports the system picks, starts with SSH on, so the refusal before it
// was for what the row changed.
func expectSSHStarts(t *testing.T) {
	t.Helper()
	_, ssh := startProgram(t, portOption, "0", hostKeyOption, makeKey(t, "ed25519", ""), sshPortOption, "0").kinds(t)
	loopbackPorts(t, ssh)
}

// defaultSSHPortRow is the row for port 22 by default. Where 22 is free at both addresses, as
// checked just before, the program listens for SSH there; where something else holds it or the
// system keeps it from an ordinary user, the program refuses to start, while the same command
// with an SSH port the system picks starts.
func defaultSSHPortRow(t *testing.T) {
	t.Helper()
	key := makeKey(t, "ed25519", "")
	free := true
	for _, address := range []string{"127.0.0.1:22", "[::1]:22"} {
		held, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", address)
		if err != nil {
			free = false
			continue
		}
		_ = held.Close()
	}
	program := startProgram(t, portOption, "0", hostKeyOption, key)
	if free {
		_, ssh := program.kinds(t)
		expectAddresses(t, ssh, "127.0.0.1:22", "[::1]:22")
		for _, address := range ssh {
			expectSSHServed(t, address)
		}
		// Stopped here, inside the row's hold on port 22, not at the row's cleanup after it.
		_ = program.command.Process.Kill()
		<-program.exited
		return
	}
	program.expectRefusal(t)
	_, ssh := startProgram(t, portOption, "0", hostKeyOption, key, sshPortOption, "0").kinds(t)
	loopbackPorts(t, ssh)
}

func TestSSHProgram(t *testing.T) {
	t.Parallel()

	t.Run("When the sysop passes an SSH port on the command line as well, the engine shall listen for SSH callers on that port in place of port 22.", func(t *testing.T) {
		t.Parallel()
		t.Run("with -ssh-port and a free port, it names and serves that port at both addresses, beside Telnet's", func(t *testing.T) {
			t.Parallel()
			key := makeKey(t, "ed25519", "")
			port, listeners := startOnFreedPort(t, []string{ipv4Loopback, ipv6Loopback}, func(port string) []string {
				return []string{portOption, "0", hostKeyOption, key, sshPortOption, port}
			})
			telnet, ssh := kindsOf(t, listeners)
			expectAddresses(t, ssh, net.JoinHostPort(ipv4Loopback, port), net.JoinHostPort(ipv6Loopback, port))
			loopbackPorts(t, telnet)
			for _, address := range ssh {
				expectSSHServed(t, address)
			}
			for _, address := range telnet {
				expectServed(t, address)
			}
		})
		t.Run("with -ssh-port 0, it names and serves a port the system picked at each address", func(t *testing.T) {
			t.Parallel()
			program := startProgram(t, portOption, "0", hostKeyOption, makeKey(t, "ed25519", ""), sshPortOption, "0")
			_, ssh := program.kinds(t)
			loopbackPorts(t, ssh)
			for _, address := range ssh {
				expectSSHServed(t, address)
			}
		})
	})

	t.Run("If the host key file is missing, unreadable, not in OpenSSH's format, protected by a passphrase or not an Ed25519 key, then the engine shall write one `start_failed` line saying which, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		files := []struct {
			name string
			path func(t *testing.T) string
		}{
			{"missing", func(t *testing.T) string {
				t.Helper()
				return filepath.Join(t.TempDir(), "absent")
			}},
			{"unreadable", func(t *testing.T) string {
				t.Helper()
				path := makeKey(t, "ed25519", "")
				keepFromReading(t, path)
				return path
			}},
			{"not in OpenSSH's format", func(t *testing.T) string {
				t.Helper()
				path := filepath.Join(t.TempDir(), "host_key")
				if err := os.WriteFile(path, []byte(canary+" is not a key\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			}},
			{"protected by a passphrase", func(t *testing.T) string {
				t.Helper()
				return makeKey(t, "ed25519", "secret")
			}},
			{"not an Ed25519 key", func(t *testing.T) string {
				t.Helper()
				return makeKey(t, "ecdsa", "")
			}},
		}
		t.Run("each of the five: one start_failed line and a non-zero exit, each reason its own", func(t *testing.T) {
			t.Parallel()
			reasons := map[string]string{}
			for _, file := range files {
				reason := hostKeyReason(t, file.path(t))
				for other, otherReason := range reasons {
					if otherReason == reason {
						t.Fatalf("the key file %s and the key file %s gave the same reason, %q", file.name, other, reason)
					}
				}
				reasons[file.name] = reason
			}
		})
		for _, file := range files {
			t.Run("a key file "+file.name+": one start_failed line, and a non-zero exit", func(t *testing.T) {
				t.Parallel()
				hostKeyReason(t, file.path(t))
			})
		}
		t.Run("the edge: an Ed25519 key with no passphrase, as ssh-keygen makes it, starts", func(t *testing.T) {
			t.Parallel()
			program := startProgram(t, portOption, "0", hostKeyOption, makeKey(t, "ed25519", ""), sshPortOption, "0")
			_, ssh := program.kinds(t)
			loopbackPorts(t, ssh)
		})
	})

	t.Run("If a command-line option is malformed, or the engine fails to listen at both addresses for Telnet or, when SSH or Telnet over TLS is on, for that kind, then the engine shall write one `start_failed` line to the local log saying why, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		withKey := func(t *testing.T, options ...string) []string {
			t.Helper()
			return append([]string{portOption, "0", hostKeyOption, makeKey(t, "ed25519", "")}, options...)
		}
		rows := []struct {
			name    string
			options func(t *testing.T) []string
		}{
			{"-ssh-port without -ssh-host-key", func(*testing.T) []string { return []string{portOption, "0", sshPortOption, "0"} }},
			{"-ssh-port abc with a key", func(t *testing.T) []string { t.Helper(); return withKey(t, sshPortOption, "abc") }},
			{"-ssh-port 65536 with a key", func(t *testing.T) []string { t.Helper(); return withKey(t, sshPortOption, "65536") }},
			{"-ssh-port -1 with a key", func(t *testing.T) []string { t.Helper(); return withKey(t, sshPortOption, "-1") }},
			{"-ssh-port with no value", func(t *testing.T) []string { t.Helper(); return withKey(t, sshPortOption) }},
			{"-ssh-host-key with no value", func(*testing.T) []string { return []string{portOption, "0", hostKeyOption} }},
		}
		for _, row := range rows {
			t.Run(row.name+": one start_failed line and a non-zero exit, where a good key starts", func(t *testing.T) {
				t.Parallel()
				options := row.options(t)
				startProgram(t, options...).expectRefusal(t)
				expectSSHStarts(t)
			})
		}
		t.Run("SSH's port taken at both addresses while Telnet's is free: one start_failed line and a non-zero exit, where a free port starts", func(t *testing.T) {
			t.Parallel()
			sshPort, _, _ := heldPort(t)
			// Telnet's port is one the system picks, so it is free and the refusal is SSH's: a
			// port freed for the program could be taken by anything in the gap.
			startProgram(t, portOption, "0", hostKeyOption, makeKey(t, "ed25519", ""), sshPortOption, sshPort).expectRefusal(t)
			expectSSHStarts(t)
		})
	})

	t.Run("While 100 connections are open, the engine shall close each new connection at once, without writing to it.", func(t *testing.T) {
		t.Parallel()
		t.Run("fifty Telnet and fifty SSH callers: the next of either kind is closed at once, an SSH one before any version line", func(t *testing.T) {
			t.Parallel()
			program := startProgram(t, portOption, "0", hostKeyOption, makeKey(t, "ed25519", ""), sshPortOption, "0")
			telnet, ssh := program.kinds(t)
			for range connectionCap / 2 {
				expectServed(t, telnet[0])
				expectSSHServed(t, ssh[0])
			}
			if served(t, telnet[0]) {
				t.Fatalf("a Telnet caller was served with %d connections open", connectionCap)
			}
			call := dial(t, ssh[0])
			received, err := readAll(call, call.connected.Add(testrun.Patient(margin)))
			if len(received) != 0 || !(isEnd(err)) {
				t.Fatalf("an SSH caller with %d connections open got %q and %v, want a close with nothing written", connectionCap, received, err)
			}
		})
	})

	t.Run("The engine shall listen for callers at 127.0.0.1 and at ::1, and at no other address.", func(t *testing.T) {
		t.Parallel()
		t.Run("with SSH on, 127.0.0.2 and this machine's other addresses are refused at the SSH ports too", func(t *testing.T) {
			t.Parallel()
			program := startProgram(t, portOption, "0", hostKeyOption, makeKey(t, "ed25519", ""), sshPortOption, "0")
			_, ssh := program.kinds(t)
			ipv4Port, ipv6Port := loopbackPorts(t, ssh)
			for _, address := range ssh {
				expectSSHServed(t, address)
			}
			targets := []string{net.JoinHostPort("127.0.0.2", ipv4Port), net.JoinHostPort("127.0.0.2", ipv6Port)}
			for _, address := range otherAddresses(t) {
				targets = append(targets, net.JoinHostPort(address.String(), ipv4Port), net.JoinHostPort(address.String(), ipv6Port))
			}
			var group sync.WaitGroup
			for _, target := range targets {
				group.Go(func() { expectRefused(t, target) })
			}
			group.Wait()
		})
	})

	t.Run("If the engine fails to listen at one of 127.0.0.1 and ::1, then the engine shall listen at the other alone.", func(t *testing.T) {
		t.Parallel()
		t.Run("SSH's port taken at 127.0.0.1: it names and serves SSH at ::1 alone", func(t *testing.T) {
			t.Parallel()
			key := makeKey(t, "ed25519", "")
			port, listeners := startOnFreedPort(t, []string{ipv6Loopback}, func(port string) []string {
				return []string{portOption, "0", hostKeyOption, key, sshPortOption, port}
			})
			_, ssh := kindsOf(t, listeners)
			expectAddresses(t, ssh, net.JoinHostPort(ipv6Loopback, port))
			expectSSHServed(t, ssh[0])
		})
	})

	t.Run("When it receives a stop signal, the engine shall close every open connection at once and exit.", func(t *testing.T) {
		t.Parallel()
		signal := stopSignals()[0]
		t.Run(signal.name+": a silent SSH caller that has read the version line is closed, and the program exits, at once", func(t *testing.T) {
			t.Parallel()
			send := signal.prepare(t)
			program := startProgram(t, portOption, "0", hostKeyOption, makeKey(t, "ed25519", ""), sshPortOption, "0")
			_, ssh := program.kinds(t)
			silent := expectSSHServed(t, ssh[0])
			from, sentBy := send(t, program)
			notAfter := sentBy.Add(testrun.Patient(margin))
			_, err := readAll(silent, notAfter)
			if !isEnd(err) {
				t.Fatalf("the silent SSH caller's read ended with %v, want the engine's close", err)
			}
			_, exitedAt := program.exit(t, notAfter)
			expectWithin(t, "the exit", exitedAt, from, notAfter)
		})
	})

	t.Run("The engine shall not write any part of the host key to the local log.", func(t *testing.T) {
		t.Parallel()
		for _, row := range []struct {
			name string
			key  func(t *testing.T) string
		}{
			{"a key protected by a passphrase, refused", func(t *testing.T) string { t.Helper(); return makeKey(t, "ed25519", "secret") }},
			{"an RSA key, refused", func(t *testing.T) string { t.Helper(); return makeKey(t, "rsa", "", "-b", "2048") }},
		} {
			t.Run(row.name+": the log holds no 8 characters in a row of the key file", func(t *testing.T) {
				t.Parallel()
				key := row.key(t)
				program := startProgram(t, portOption, "0", hostKeyOption, key, sshPortOption, "0")
				program.expectRefusal(t)
				expectSSHStarts(t)
				expectNoKeyInLog(t, program.text(), key)
			})
		}
	})
}

// TestLinuxSSHProgram is Linux's alone because its rows are: the mode check, cut to Linux by the
// page, and port 22, which Linux keeps from an ordinary user.
func TestLinuxSSHProgram(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Fatalf("these rows need an ordinary user: root reads a file of any mode, and listens at 22")
	}

	t.Run("When the sysop passes an SSH host key file on the command line, the engine shall listen for SSH callers at 127.0.0.1 and ::1 on port 22, beside its Telnet listener.", func(t *testing.T) {
		t.Parallel()
		t.Run("with a host key and no SSH port, as an ordinary user who may not listen below 1024: refused, where an SSH port the system picks starts", func(t *testing.T) {
			t.Parallel()
			setting, err := os.ReadFile("/proc/sys/net/ipv4/ip_unprivileged_port_start")
			if err != nil {
				t.Fatalf("reading the lowest port an ordinary user may listen on: %v", err)
			}
			if lowest, err := strconv.Atoi(strings.TrimSpace(string(setting))); err != nil || lowest <= 22 {
				t.Fatalf("this machine lets an ordinary user listen from port %q", setting)
			}
			defaultSSHPortRow(t)
		})
	})

	t.Run("If, on Linux, the host key file's mode lets its group or others read it, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o444} {
			t.Run(fmt.Sprintf("an Ed25519 key of mode %04o: one start_failed line, a non-zero exit, a reason of its own", mode), func(t *testing.T) {
				t.Parallel()
				path := makeKey(t, "ed25519", "")
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
				reason := hostKeyReason(t, path)
				others := []string{hostKeyReason(t, filepath.Join(t.TempDir(), "absent")), hostKeyReason(t, makeKey(t, "ed25519", "secret"))}
				if slices.Contains(others, reason) {
					t.Fatalf("the mode's reason %q is the same as another refusal's", reason)
				}
			})
		}
		for _, mode := range []os.FileMode{0o600, 0o400, 0o620} {
			t.Run(fmt.Sprintf("the edge: an Ed25519 key of mode %04o starts", mode), func(t *testing.T) {
				t.Parallel()
				path := makeKey(t, "ed25519", "")
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
				_, ssh := startProgram(t, portOption, "0", hostKeyOption, path, sshPortOption, "0").kinds(t)
				loopbackPorts(t, ssh)
			})
		}
	})

	t.Run("The engine shall not write any part of the host key to the local log.", func(t *testing.T) {
		t.Parallel()
		t.Run("a key file of mode 0644, refused: the log holds no 8 characters in a row of it", func(t *testing.T) {
			t.Parallel()
			path := makeKey(t, "ed25519", "")
			setMode(t, path, 0o644)
			program := startProgram(t, portOption, "0", hostKeyOption, path, sshPortOption, "0")
			program.expectRefusal(t)
			expectSSHStarts(t)
			expectNoKeyInLog(t, program.text(), path)
		})
	})

	t.Run("When the sysop passes an SSH port on the command line as well, the engine shall listen for SSH callers on that port in place of port 22.", func(t *testing.T) {
		t.Parallel()
		t.Run("with -ssh-port 65535, the highest port, it names and serves it", func(t *testing.T) {
			t.Parallel()
			highestPort.Lock()
			defer highestPort.Unlock()
			program := startProgram(t, portOption, "0", hostKeyOption, makeKey(t, "ed25519", ""), sshPortOption, "65535")
			_, ssh := program.kinds(t)
			expectAddresses(t, ssh, "127.0.0.1:65535", "[::1]:65535")
			for _, address := range ssh {
				expectSSHServed(t, address)
			}
			_ = program.command.Process.Kill()
			<-program.exited
		})
	})

	t.Run("The engine shall listen for callers at 127.0.0.1 and at ::1, and at no other address.", func(t *testing.T) {
		t.Parallel()
		t.Run("with SSH on, every listening socket the system's table shows for the program is at 127.0.0.1 or ::1, four of them", func(t *testing.T) {
			t.Parallel()
			program := startProgram(t, portOption, "0", hostKeyOption, makeKey(t, "ed25519", ""), sshPortOption, "0")
			listeners := program.listeners(t)
			sockets := listeningSockets(t, program.command.Process.Pid)
			if len(sockets) != 4 {
				t.Fatalf("the system's table shows %q for the program, want four listening sockets; it named %q", sockets, listeners)
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

// readAll reads until the stream ends or the deadline, and returns what came and why it stopped.
func readAll(call caller, deadline time.Time) ([]byte, error) {
	_ = call.connection.SetReadDeadline(deadline)
	var received []byte
	chunk := make([]byte, 256)
	for {
		got, err := call.connection.Read(chunk)
		received = append(received, chunk[:got]...)
		if err != nil {
			return received, err
		}
	}
}

// setMode gives a file the mode its row is about, one its group or others may read among them.
func setMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("setting %s to %#o: %v", path, mode, err)
	}
}

// expectNoKeyInLog fails the row if the log holds 8 characters in a row of the key file's
// base64 body or of its public half.
func expectNoKeyInLog(t *testing.T, log, keyPath string) {
	t.Helper()
	private, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	var body strings.Builder
	for _, line := range strings.Split(string(private), "\n") {
		if !strings.HasPrefix(line, "-----") {
			body.WriteString(strings.TrimSpace(line))
		}
	}
	parts := []string{body.String()}
	if public, err := os.ReadFile(keyPath + ".pub"); err == nil {
		if fields := strings.Fields(string(public)); len(fields) > 1 {
			parts = append(parts, fields[1])
		}
	}
	for _, part := range parts {
		for start := 0; start+8 <= len(part); start++ {
			if strings.Contains(log, part[start:start+8]) {
				t.Fatalf("the log %q holds part of the host key", log)
			}
		}
	}
}
