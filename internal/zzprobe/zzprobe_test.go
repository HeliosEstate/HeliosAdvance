// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// This test reaches every line but checks too little, so most mutants live.
package zzprobe

import "testing"

func TestGrade(t *testing.T) {
	t.Parallel()
	for _, score := range []int{95, 85, 60, 10} {
		if Grade(score) == "" {
			t.Fatalf("no grade for %d", score)
		}
	}
}
