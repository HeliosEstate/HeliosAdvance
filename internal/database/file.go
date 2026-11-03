// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package database

import "errors"

// Until bootstrap Part 1's build, ParseConnection fails: the connection settings now come unsealed
// from the bootstrap file, and the build writes their parsing.

var errNotBuilt = errors.New("database: not built yet")

func parseConnection([]byte) (Connection, error) {
	return Connection{}, errNotBuilt
}
