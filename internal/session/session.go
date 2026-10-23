// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"context"
	"errors"
)

// The contract's operations hand their work to the unexported functions below, so the contract
// builds before the package is built and the build never needs to change the contract. Each
// placeholder here is replaced by the issue that builds it.

// errNotBuilt is what a placeholder returns until its issue builds it.
var errNotBuilt = errors.New("session: not built yet")

func run(_ context.Context, _ Connection) (Ending, error) {
	return 0, errNotBuilt
}
