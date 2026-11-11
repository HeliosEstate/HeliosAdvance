// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main_test

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
)

// The schema's seeded ports, written here so a changed default cannot move a test with it.
const (
	seededTelnetPort  = 23
	seededSSHPort     = 22
	seededTelnetsPort = 992
)

// services are the six settings of a server's row, which say which of Telnet, SSH and Telnet over
// TLS it runs and on which ports, as a row writes them into the server's row with SQL.
type services struct {
	telnetOn    bool
	telnetPort  int
	sshOn       bool
	sshPort     int
	telnetsOn   bool
	telnetsPort int
}

// allOff is a row's settings as the schema seeds them: every service off, each on its usual port.
func allOff() services {
	return services{telnetPort: seededTelnetPort, sshPort: seededSSHPort, telnetsPort: seededTelnetsPort}
}

// telnetAt is Telnet alone on, at the port.
func telnetAt(port int) services {
	settings := allOff()
	settings.telnetOn = true
	settings.telnetPort = port
	return settings
}

// withSSH turns SSH on at the port.
func (settings services) withSSH(port int) services {
	settings.sshOn = true
	settings.sshPort = port
	return settings
}

// withTelnets turns Telnet over TLS on at the port.
func (settings services) withTelnets(port int) services {
	settings.telnetsOn = true
	settings.telnetsPort = port
	return settings
}

// The kinds as a started line's URLs name them, before "://".
const (
	schemeTelnet  = "telnet"
	schemeSSH     = "ssh"
	schemeTelnets = "telnets"
)

// settingColumns are the six columns, in the order values writes them.
const settingColumns = "telnet_on, telnet_port, ssh_on, ssh_port, telnets_on, telnets_port"

// values writes the six settings as SQL, in the order of settingColumns.
func (settings services) values() string {
	return fmt.Sprintf("%t, %d, %t, %d, %t, %d", settings.telnetOn, settings.telnetPort, settings.sshOn, settings.sshPort,
		settings.telnetsOn, settings.telnetsPort)
}

// turnsOn is whether the settings turn on the kind a started line's listener names, by its scheme:
// telnet, ssh or telnets. A scheme of no kind is not on.
func (settings services) turnsOn(scheme string) bool {
	switch scheme {
	case schemeTelnet:
		return settings.telnetOn
	case schemeSSH:
		return settings.sshOn
	case schemeTelnets:
		return settings.telnetsOn
	}
	return false
}

// expectKindsOn fails the row when the started line names a listener of a kind the settings the
// row wrote turn off: a row whose program listens for a kind it was not asked for has not reached
// its case.
func (settings services) expectKindsOn(t *testing.T, listeners []string) {
	t.Helper()
	for _, listener := range listeners {
		scheme, _, found := strings.Cut(listener, "://")
		if found && !settings.turnsOn(scheme) {
			t.Fatalf("the started line names %q, a kind the row's settings turn off (%s = %s)", listeners, settingColumns, settings.values())
		}
	}
}

// expectListensNowhere checks a started line's value says the engine listens nowhere: words of
// the build's own, not empty, naming no listener.
func expectListensNowhere(t *testing.T, value string) {
	t.Helper()
	if strings.Trim(value, ` "`) == "" || strings.Contains(value, "://") {
		t.Fatalf("the started line's value is %q, want words saying the engine listens nowhere", value)
	}
}

// expectPickedPorts checks a kind's addresses are one at 127.0.0.1 and one at ::1, each on a port
// that is not the seeded one: a port setting of 0 read as the kind's usual port, or any fixed one
// the row would know, is not a port the system picked.
func expectPickedPorts(t *testing.T, addresses []string, seeded string) {
	t.Helper()
	ipv4Port, ipv6Port := loopbackPorts(t, addresses)
	if ipv4Port == seeded || ipv6Port == seeded {
		t.Fatalf("the started line names %q, the seeded port %s, for a port setting of 0", addresses, seeded)
	}
}

// expectServedAtColumn is the control a refusal row on a held port ends with: the same kind on at
// a port the test frees for it, written in its column, is named at that port at both addresses,
// so the refusal before it was for the port the row held, and the column is what the engine read.
func expectServedAtColumn(t *testing.T, scheme string, settings func(port int) services, options ...string) {
	t.Helper()
	port, listeners := startOnFreedPort(t, []string{ipv4Loopback, ipv6Loopback}, settings, options...)
	var named []string
	for _, listener := range listeners {
		if address, found := strings.CutPrefix(listener, scheme+"://"); found {
			named = append(named, address)
		}
	}
	expectAddresses(t, named, net.JoinHostPort(ipv4Loopback, port), net.JoinHostPort(ipv6Loopback, port))
}

// portNumber reads a port the tests hold, such as heldPort's, as the number a setting holds.
func portNumber(t *testing.T, port string) int {
	t.Helper()
	number, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("the port %q is not a number", port)
	}
	return number
}
