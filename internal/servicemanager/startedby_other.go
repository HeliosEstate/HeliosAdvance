// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package servicemanager

func startedByWindowsServiceManager() (bool, error) {
	return false, nil
}
