// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main_test

import (
	"context"
	"errors"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// netstatBytes bounds what one netstat run may print: a line is under a hundred bytes, and a
// machine running these tests holds thousands of connections at most.
const netstatBytes = 8 << 20

// listeningSockets reads the operating system's own table of listening TCP sockets, through the
// netstat it ships, and returns the address of each socket the process holds. A listening
// socket is told by its foreign address, 0.0.0.0:0 or [::]:0: netstat names its state in the
// system's own language. A netstat that fails fails the row; it is never read as nothing
// listening.
func listeningSockets(t *testing.T, processID int) []string {
	t.Helper()
	want := strconv.Itoa(processID)
	var sockets []string
	for _, protocol := range []string{"TCP", "TCPv6"} {
		for line := range strings.SplitSeq(netstat(t, protocol), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 5 || fields[0] != "TCP" || fields[4] != want || (fields[2] != "0.0.0.0:0" && fields[2] != "[::]:0") {
				continue
			}
			host, port, err := net.SplitHostPort(fields[1])
			if err != nil {
				t.Fatalf("a local address in netstat's table is not one: %q", fields[1])
			}
			sockets = append(sockets, net.JoinHostPort(host, port))
		}
	}
	return sockets
}

// netstat runs netstat for one protocol's sockets, with their processes, and returns its output.
func netstat(t *testing.T, protocol string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "netstat", "-ano", "-p", protocol)
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("netstat's output: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("starting netstat: %v", err)
	}
	buffer := make([]byte, netstatBytes)
	read, readErr := io.ReadFull(output, buffer)
	if !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
		// A full buffer leaves netstat waiting to write the rest; it is ended, not waited for.
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("netstat -ano -p %s printed %d bytes or more, or could not be read: %v", protocol, netstatBytes, readErr)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("netstat -ano -p %s: %v", protocol, err)
	}
	return string(buffer[:read])
}
