// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package main_test

import "testing"

// keepTLSFileFromReading makes a certificate or key file one the program cannot open, as
// keepFromReading does for the host key.
func keepTLSFileFromReading(t *testing.T, path string) {
	t.Helper()
	keepFromReading(t, path)
}
