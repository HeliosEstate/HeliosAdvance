// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package audit records operator actions. Only what other units need to compile is here
// until the audit unit's own session decides the rest.
package audit

// Actor identifies who performed an operator action. Its fields are decided in the audit
// unit's session; until then it exists so that contracts taking an actor can be written.
type Actor struct{}
