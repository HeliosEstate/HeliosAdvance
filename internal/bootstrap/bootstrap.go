// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"context"
	"errors"
)

// errNotBuilt marks operations owned by later bootstrap issues.
var errNotBuilt = errors.New("bootstrap: not built")

// New returns the Bootstrap.
func New() Bootstrap { return builder{} }

// builder holds the package operations already available.
type builder struct{ unbuilt }

func (builder) Build(ctx context.Context, folder string, fields Fields, path BuildPath, account string, source KeySource) (KeyMode, error) {
	return buildOnPlatform(ctx, folder, fields, path, account, source)
}

func (builder) Check(folder string, mode KeyMode, account string) ([]Finding, error) {
	return checkPermissions(folder, mode, account)
}

func (builder) SetToRule(finding Finding, account string) error {
	return setToRule(finding, account)
}

// unbuilt retains the operations handled by later bootstrap work.
type unbuilt struct{}

func (unbuilt) UnlockForSetup(context.Context, string, KeyMode) (SetupHandle, error) {
	return nil, errNotBuilt
}

func (unbuilt) UnlockForService(context.Context, string, KeyMode) (ServiceHandle, error) {
	return nil, errNotBuilt
}
