// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package settings is every sysop setting, board-wide or per-server: board-wide unless it
// describes the server's own hardware or network. A feature declares its settings in code
// at start, with scope, kind, default, bounds and whether a change needs a restart; the
// store holds only what the sysop has set and refuses anything a declaration does not
// allow. Reading is on use, from the database, every time, with the default when nothing
// is set: a change is seen on the next read on every server, with no cache and no
// notification. A setting that needs a restart is read once at start by its feature, and
// Set says so to the tool that set it. A Set and its audit entry are one transaction. The
// package owns nothing on disk (the bootstrap record is the setup tool's) and no theme or
// language file. A Get that cannot reach the database returns database.ErrUnavailable and
// never the default; the caller decides, and the allocator refuses the caller.
//
// This file is the developer's contract (HeliosDesign records/skeleton/Settings.pas) and
// is locked: a loop session does not edit it.
package settings

import (
	"context"
	"time"

	"github.com/heliosestate/heliosadvance/internal/audit"
	"github.com/heliosestate/heliosadvance/internal/board"
)

// Scope is whether a setting is one value for the board, one per server, or one per
// role. A role-scoped setting may be set on any role, grant roles included; a feature
// reads it for an account's primary role only, never for its grants.
type Scope uint8

// Scopes.
const (
	Board Scope = iota + 1
	Server
	Role
)

// Kind is the type of a setting's value. There are four and no more: a list or a
// structured value is a table of its own feature, not a setting.
type Kind uint8

// Kinds.
const (
	Integer Kind = iota + 1
	Text
	Boolean
	Duration
)

// Value is a value of exactly one kind; the field for that kind is the meaningful one.
type Value struct {
	Kind     Kind
	Integer  int64
	Text     string
	Boolean  bool
	Duration time.Duration
}

// Declaration is what a feature says about one of its settings.
type Declaration struct {
	Name         string // unique; dotted by feature, e.g. cluster.node_limit
	Scope        Scope
	Kind         Kind
	Default      Value
	Min, Max     int64 // bounds for Integer and Duration (seconds); ignored otherwise
	NeedsRestart bool
}

// Target names a value: a setting, and for a per-server or per-role one, the server or
// the role. Both are 0 for a board-wide setting; the wrong one given is refused
// (WrongScope).
type Target struct {
	Name   string
	Server board.ServerID
	Role   board.RoleID
}

// SetResult is the outcome of Set or Clear.
type SetResult uint8

// Set results. RestartNeeded is a success that the tool must report to the sysop.
const (
	Set SetResult = iota + 1
	RestartNeeded
	UnknownName
	WrongKind
	OutOfBounds
	WrongScope
)

// Settings is the contract. Every method that reaches the database carries a context
// with a deadline.
type Settings interface {
	// Register is called at start, once per feature. A second declaration of the same name
	// with a different shape is a programming error and fails start.
	Register(declarations []Declaration) error

	// Declarations is what is declared, for the setup and configuration tools to show.
	Declarations() []Declaration

	// Get is the value in the database, or the declared default when nothing is set.
	Get(ctx context.Context, target Target) (Value, error)

	// Set validates against the declaration, then writes the value and its audit entry
	// (actor, target, before, after) in one transaction. Two sysops setting the same
	// target both succeed in order; the last write stands.
	Set(ctx context.Context, target Target, value Value, actor audit.Actor) (SetResult, error)

	// Clear returns the setting to its declared default, audited like a Set.
	Clear(ctx context.Context, target Target, actor audit.Actor) (SetResult, error)
}
