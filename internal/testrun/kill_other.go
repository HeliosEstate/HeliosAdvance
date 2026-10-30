// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package testrun

// stopPrograms finds no program by its file here. On Windows a program still running from the
// run's folder keeps the folder from being removed, and the removal's error says so.
func stopPrograms(string) error {
	return nil
}
