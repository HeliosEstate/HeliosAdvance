// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package zzprobe

import "testing"

func TestLarger(t *testing.T) {
	t.Parallel()
	if got := Larger(1, 1); got != 1 {
		t.Fatalf("Larger(1, 1) = %d, want 1", got)
	}
}
