// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package zzprobe is a probe, removed before merge: code whose test checks too little.
package zzprobe

// Larger returns the larger of first and second.
func Larger(first, second int) int {
	if first > second {
		return first
	}
	return second
}
