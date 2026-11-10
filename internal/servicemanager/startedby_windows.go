// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package servicemanager

import "golang.org/x/sys/windows/svc"

func startedByWindowsServiceManager() (bool, error) {
	started, err := svc.IsWindowsService()
	if err != nil {
		return false, ErrStartedHowUnknown
	}
	return started, nil
}
