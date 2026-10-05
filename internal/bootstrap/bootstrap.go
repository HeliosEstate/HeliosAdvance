// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"context"
	"errors"
	"fmt"
)

// errNotBuilt is what every operation returns until the unit is built, so that every
// approved test fails rather than stops the run.
var errNotBuilt = errors.New("bootstrap: not built")

// New returns the Bootstrap.
func New() Bootstrap { return unbuilt{} }

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

// Error makes a *Refusal an error, which errors.As needs; the contract does not declare it.
func (refusal *Refusal) Error() string {
	return fmt.Sprintf("bootstrap: refused: cause %d, path %q", refusal.Cause, refusal.Path)
}
