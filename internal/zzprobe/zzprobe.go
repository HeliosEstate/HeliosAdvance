// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package zzprobe exists only to prove the mutation gate on a pull request, and is removed
// before it merges.
package zzprobe

// Grade gives the letter so that the gate has comparisons to mutate.
func Grade(score int) string {
	if score >= 90 {
		return "A"
	}
	if score >= 80 {
		return "B"
	}
	if score > 50 {
		return "C"
	}
	return "F"
}
