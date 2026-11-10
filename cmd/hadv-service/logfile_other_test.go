// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !windows

package main_test

import "testing"

// unopenableLogFiles has no case of its own on a system the engine does not ship to.
func unopenableLogFiles() map[string]func(t *testing.T) (string, func(t *testing.T)) {
	return nil
}
