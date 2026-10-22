// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package main_test

import (
	"syscall"
	"testing"
	"time"
)

// processAttributes leaves the program in the test's own process group off Windows.
func processAttributes() *syscall.SysProcAttr { return nil }

// stopSignals are SIGINT and SIGTERM, the issue's stop signals off Windows.
func stopSignals() []stopSignal {
	return []stopSignal{
		{name: "SIGINT", prepare: prepareSignal(syscall.SIGINT)},
		{name: "SIGTERM", prepare: prepareSignal(syscall.SIGTERM)},
	}
}

func prepareSignal(signal syscall.Signal) func(*testing.T) func(*testing.T, *run) (time.Time, time.Time) {
	return func(*testing.T) func(*testing.T, *run) (time.Time, time.Time) {
		return func(t *testing.T, program *run) (time.Time, time.Time) {
			t.Helper()
			from := time.Now()
			if err := program.command.Process.Signal(signal); err != nil {
				t.Fatalf("sending %v: %v", signal, err)
			}
			return from, time.Now()
		}
	}
}
