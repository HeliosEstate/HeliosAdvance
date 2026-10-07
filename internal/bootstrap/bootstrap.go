// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"context"
)

// New returns the Bootstrap.
func New() Bootstrap { return builder{} }

// builder holds the package operations already available.
type builder struct{}

func (builder) Build(ctx context.Context, folder string, fields Fields, path BuildPath, account string, source KeySource) (KeyMode, error) {
	return buildOnPlatform(ctx, folder, fields, path, account, source)
}

func (builder) Check(folder string, mode KeyMode, account string) ([]Finding, error) {
	return checkPermissions(folder, mode, account)
}

func (builder) UnlockForSetup(ctx context.Context, folder string, mode KeyMode, account string) (SetupHandle, error) {
	return unlockSetupOnPlatform(ctx, folder, mode, account)
}

func (builder) SetToRule(finding Finding, account string) error {
	return setToRule(finding, account)
}

func (builder) UnlockForService(ctx context.Context, folder string, mode KeyMode) (ServiceHandle, error) {
	return unlockServiceOnPlatform(ctx, folder, mode)
}
