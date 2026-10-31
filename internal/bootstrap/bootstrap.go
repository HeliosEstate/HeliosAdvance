// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import "errors"

// The contract's operations hand their work to the unexported functions in this package's other
// files, so the contract builds before the package is built and the build never needs to change
// the contract. Until bootstrap Part 1's build, every call fails.

var errNotBuilt = errors.New("bootstrap: not built yet")

func open(string) ([]byte, error) {
	return nil, errNotBuilt
}
