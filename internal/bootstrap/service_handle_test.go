// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import "testing"

// TestServiceHandleOffersNoRewrite proves the line "The ServiceHandle shall offer no operation
// that changes any field other than the vault-key fields." for the handle UnlockForService returns:
// a type assertion to SetupHandle, which carries Rewrite, must fail.
func TestServiceHandleOffersNoRewrite(t *testing.T) {
	t.Parallel()
	rows := []struct {
		name   string
		handle any
	}{
		{"the handle UnlockForService returns", ServiceHandle(serviceHandle{&setupHandle{}})},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			if _, ok := row.handle.(SetupHandle); ok {
				t.Fatal("the service's handle satisfies SetupHandle, so Rewrite is reachable")
			}
			if _, ok := row.handle.(ServiceHandle); !ok {
				t.Fatal("the service's handle does not satisfy ServiceHandle")
			}
		})
	}
}
