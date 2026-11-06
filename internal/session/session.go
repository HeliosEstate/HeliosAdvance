// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"context"
	"errors"

	"github.com/heliosestate/heliosadvance/internal/language"
)

// The contract's operations hand their work to the unexported functions below, so the contract
// builds before the package is built and the build never needs to change the contract. Until
// Languages Part 1's build, Run fails with an error of its own, never one the contract names.

var errNotBuilt = errors.New("session: not built yet")

func run(context.Context, Connection, *language.Texts) (Ending, error) {
	return 0, errNotBuilt
}
