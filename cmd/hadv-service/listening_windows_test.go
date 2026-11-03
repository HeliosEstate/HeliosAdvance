// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main_test

import (
	"context"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// netstatBytes bounds what one netstat run may print: a line is under a hundred bytes, and a
// machine running these tests holds thousands of connections at most.
const netstatBytes = 8 << 20

// listeningSockets reads the operating system's own table of listening TCP sockets, through the
// netstat it ships, and returns the address of each socket the process holds. A listening
// socket is told by its foreign address, 0.0.0.0:0 or [::]:0: netstat names its state in the
// system's own language. A table that cannot be read fails the row, never reads as nothing
// listening: a netstat that fails, a line naming the process that does not parse, or no TCP line
// at all.
func listeningSockets(t *testing.T, processID int) []string {
	t.Helper()
	want := strconv.Itoa(processID)
	var sockets []string
	parsed := 0
	for _, protocol := range []string{"TCP", "TCPv6"} {
		for line := range strings.SplitSeq(netstat(t, protocol), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || fields[0] != "TCP" {
				continue
			}
			if len(fields) != 5 {
				if fields[len(fields)-1] == want {
					t.Fatalf("a line of netstat's table naming the program does not parse: %q", line)
				}
				continue
			}
			parsed++
			if fields[4] != want || (fields[2] != "0.0.0.0:0" && fields[2] != "[::]:0") {
				continue
			}
			host, port, err := net.SplitHostPort(fields[1])
			if err != nil {
				t.Fatalf("a local address in netstat's table is not one: %q", fields[1])
			}
			sockets = append(sockets, net.JoinHostPort(host, port))
		}
	}
	if parsed == 0 {
		t.Fatalf("netstat's table held no TCP line that parses, so it cannot say what the program holds")
	}
	return sockets
}

// netstat runs netstat for one protocol's sockets, with their processes, and returns its output.
func netstat(t *testing.T, protocol string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), testrun.Patient(testrun.HangBound))
	defer cancel()
	command := exec.CommandContext(ctx, "netstat", "-ano", "-p", protocol)
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("netstat's output: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("starting netstat: %v", err)
	}
	text, readErr := io.ReadAll(io.LimitReader(output, netstatBytes+1))
	if readErr != nil || len(text) > netstatBytes {
		// Output past the bound leaves netstat waiting to write the rest; it is ended, not waited
		// for.
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("netstat -ano -p %s printed more than %d bytes, or could not be read: %v", protocol, netstatBytes, readErr)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("netstat -ano -p %s: %v", protocol, err)
	}
	return string(text)
}
