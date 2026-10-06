// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"context"
	"errors"
)

// errNotBuilt is what every operation not yet built returns, so that every approved test
// fails rather than stops the run.
var errNotBuilt = errors.New("bootstrap: not built")

// New returns the Bootstrap.
func New() Bootstrap { return checker{} }

// checker has the permission checks built, and refuses the rest until they are.
type checker struct{ unbuilt }

func (checker) Check(folder string, mode KeyMode, account string) ([]Finding, error) {
	return checkPermissions(folder, mode, account)
}

func (checker) SetToRule(finding Finding, account string) error {
	return setToRule(finding, account)
}

// unbuilt refuses every operation.
type unbuilt struct{}

func (unbuilt) Build(context.Context, string, Fields, BuildPath, string, KeySource) (KeyMode, error) {
	return 0, errNotBuilt
}

func (unbuilt) UnlockForSetup(context.Context, string, KeyMode) (SetupHandle, error) {
	return nil, errNotBuilt
}

func (unbuilt) Check(string, KeyMode, string) ([]Finding, error) { return nil, errNotBuilt }

func (unbuilt) SetToRule(Finding, string) error { return errNotBuilt }

func (unbuilt) UnlockForService(context.Context, string, KeyMode) (ServiceHandle, error) {
	return nil, errNotBuilt
}
