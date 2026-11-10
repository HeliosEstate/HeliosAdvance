// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap_test

import "testing"

// TestWindowsReadBound proves the refusal alone: nothing on Windows tells what Open read of one
// file. A byte-range lock from the byte past the bound would fail a sound Open that asks for more
// than it gets back, and the process's count of bytes read comes only through a raw pointer or
// from another program. Linux's rows bound the read, and the reading is the same code here.
func TestWindowsReadBound(t *testing.T) {
	t.Parallel()
	for _, line := range readBoundLines() {
		t.Run(line.line, func(t *testing.T) {
			t.Parallel()
			for _, row := range line.rows {
				t.Run(row.name, func(t *testing.T) {
					t.Parallel()
					made := row.make(t)
					contents, err := open(t, made.folder)
					expectError(t, contents, err, row.want)
				})
			}
		})
	}
}
