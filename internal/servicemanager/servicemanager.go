// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package servicemanager

import "errors"

// The contract's operations hand their work to the unexported functions below, so the contract
// builds before the package is built and the build never needs to change the contract. Each
// placeholder here is replaced by the issue that builds it, and fails every call until then, so
// nothing calls it yet and no row passes against it.

// errNotBuilt is what a placeholder returns until its issue builds it.
var errNotBuilt = errors.New("servicemanager: not built yet")

func startedByWindowsServiceManager() (bool, error) {
	return false, errNotBuilt
}

func runWindowsService(_ Run) (int, error) {
	return 0, errNotBuilt
}

func notifySystemdReady() {}
