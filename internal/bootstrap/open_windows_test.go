// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The Windows rows of issue #148: a missing or unreadable folder or file, which open meets
// before it asks any key holder. Named to run on CI's Windows runner, which needs no oracle
// for them.
package bootstrap

import "testing"

func TestWindowsOpenPlaces(t *testing.T) {
	t.Parallel()
	placeRows(t)
}
