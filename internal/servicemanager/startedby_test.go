// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package servicemanager_test

import (
	"testing"

	"github.com/heliosestate/heliosadvance/internal/servicemanager"
)

func TestStartedByWindowsServiceManager(t *testing.T) {
	t.Parallel()
	t.Run("When this process was started any other way, StartedByWindowsServiceManager shall return false.", func(t *testing.T) {
		t.Parallel()
		t.Run("the test process, started by go test", func(t *testing.T) {
			t.Parallel()
			started, err := servicemanager.StartedByWindowsServiceManager()
			// The line names no error, but the unbuilt code returns false with one: only false
			// with no error tells that it was asked and answered.
			if started || err != nil {
				t.Fatalf("StartedByWindowsServiceManager returned %t, %v; want false and no error", started, err)
			}
		})
	})
}
