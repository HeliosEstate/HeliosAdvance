// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package orchestrator

import "errors"

// The contract's operations hand their work to the unexported functions below, so the contract
// builds before the package is built and the build never needs to change the contract. Each
// placeholder here is replaced by the issue that builds it, and fails every call until then, so
// nothing calls it yet and no row passes against it.

type orchestratorState struct{}

// errNotBuilt is what a placeholder returns until its issue builds it.
var errNotBuilt = errors.New("orchestrator: not built yet")

func newOrchestrator(_ []Service) (*Orchestrator, error) {
	return nil, errNotBuilt
}

func (orchestrator *Orchestrator) start() {
	if orchestrator != nil {
		_ = orchestrator.state
	}
}

func (orchestrator *Orchestrator) stop() {
	if orchestrator != nil {
		_ = orchestrator.state
	}
}
