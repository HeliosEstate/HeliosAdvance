// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !windows

package testrun

// stopPrograms finds no program by its file on a system the engine does not ship to; a sweep
// there takes no folder anyway, since processStart cannot tell its owner has ended.
func stopPrograms(string) error {
	return nil
}
