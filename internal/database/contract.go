// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package database holds what every unit that goes to the database shares. Only the one
// error and the transaction type are here until the database-access unit's own session
// decides the rest.
package database

import "errors"

// ErrUnavailable is returned by any operation that could not reach the database or could
// not complete against it. A caller never turns it into a default: the board has no
// degraded mode.
var ErrUnavailable = errors.New("database: unavailable")

// Tx is a change's own transaction, carrying its deadline. A unit that must write inside
// another unit's change (the audit entry inside a Set) takes one. Its operations are
// decided in the database-access unit's session; until then it exists so that contracts
// taking a transaction can be written.
type Tx interface{}
