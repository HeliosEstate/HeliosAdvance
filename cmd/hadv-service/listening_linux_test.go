// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main_test

import (
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// listeningSockets reads the operating system's own table of listening TCP sockets, the one ss
// shows the sysop, and returns the address of each socket the process holds. Linux alone keeps
// the table and the process's open files in /proc.
func listeningSockets(t *testing.T, processID int) []string {
	t.Helper()
	descriptors := filepath.Join("/proc", strconv.Itoa(processID), "fd")
	entries, err := os.ReadDir(descriptors)
	if err != nil {
		t.Fatalf("listing the program's open files: %v", err)
	}
	held := map[string]bool{}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(descriptors, entry.Name()))
		if err == nil && strings.HasPrefix(target, "socket:[") {
			held[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
		}
	}
	var sockets []string
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		text, err := os.ReadFile(table)
		if err != nil {
			t.Fatalf("reading the socket table %s: %v", table, err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(text)), "\n")[1:] {
			// The fields are the slot, the local address, the remote one, the state (0A is
			// listening), the queues, the timer, the retransmits, the user, the timeout and the
			// socket's inode, which ties it to the process's open files.
			fields := strings.Fields(line)
			if len(fields) < 10 || fields[3] != "0A" || !held[fields[9]] {
				continue
			}
			sockets = append(sockets, tableAddress(t, fields[1]))
		}
	}
	return sockets
}

// tableAddress reads an address as the socket table writes it: the IP in hex, each 32-bit word
// in the machine's byte order, little-endian on every runner, then a colon and the port in hex.
func tableAddress(t *testing.T, text string) string {
	t.Helper()
	ipText, portText, found := strings.Cut(text, ":")
	raw, err := hex.DecodeString(ipText)
	port, portErr := strconv.ParseUint(portText, 16, 16)
	if !found || err != nil || portErr != nil || (len(raw) != net.IPv4len && len(raw) != net.IPv6len) {
		t.Fatalf("an address in the socket table is not one: %q", text)
	}
	for word := 0; word < len(raw); word += 4 {
		slices.Reverse(raw[word : word+4])
	}
	return net.JoinHostPort(net.IP(raw).String(), strconv.FormatUint(port, 10))
}
