// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"context"
)

func buildOnPlatform(_ context.Context, _ string, fields Fields, _ BuildPath, _ string, source KeySource) (KeyMode, error) {
	if !isElevated() {
		return 0, &Refusal{Cause: NotElevated}
	}
	if source == FromKeyFile || source == FromContainer || (source != FromOSStore) {
		return 0, &Refusal{Cause: SourceRefused}
	}
	if err := validateFields(fields); err != nil {
		return 0, err
	}
	return 0, errNotBuilt
}
