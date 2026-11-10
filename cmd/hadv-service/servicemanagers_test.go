// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main_test

import (
	"strings"
	"testing"
	"time"
)

// pendingHold is how long a row reads the service as still starting from the engine's first try
// while the row is locked: a stated wait inside the try's 10 seconds, so on a slow machine it can
// miss a late fault but never fail a sound engine.
const pendingHold = 2 * time.Second

// Where the engine listens for Telnet callers with no port option: the page's port 23, at each
// loopback address.
const (
	defaultIPv4Telnet = "127.0.0.1:23"
	defaultIPv6Telnet = "[::1]:23"
)

// expectStartedAtPort23 checks a local log, read from the log file or the journal, is the started
// line alone, naming Telnet at 127.0.0.1 and ::1 on port 23.
func expectStartedAtPort23(t *testing.T, text string) {
	t.Helper()
	values := expectLogText(t, text, "started")
	expectAddresses(t, telnetAlone(t, strings.Split(values[0], ",")), defaultIPv4Telnet, defaultIPv6Telnet)
}
