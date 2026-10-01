// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package rbac is role-based access control: roles, permissions, who holds what, and the
// one check every gate asks. Each subsystem registers its permissions at start under its
// own prefix; a duplicate stops the start and an unregistered name is always denied.
// Five roles are seeded by fixed ID, because names are editable, and none can be deleted:
// 1 Sysop, 2 Co-Sysop, 3 User, 4 Guest, 5 New User. Sysop's display name is editable and
// nothing else about it is. An account has one primary role and any number of grant
// roles; grants only add. Account #1 holds Sysop always and is permitted everything.
// Every check fails closed on any error. Every write is audited. A requirement based on
// what a caller is or has done (age, ratio, time of day) is the requirements unit's, and
// a gate asks both; this unit never evaluates one. The settings a role carries are the
// settings store's, role scope, read for the primary role only.
//
// This file is the developer's contract (HeliosDesign
// records/skeleton/RoleBasedAccessControl.pas) and is locked: a loop session does not
// edit it.
package rbac

import (
	"context"

	"github.com/heliosestate/heliosadvance/internal/audit"
	"github.com/heliosestate/heliosadvance/internal/board"
)

// Permission is a name, dotted under the registering subsystem's prefix.
type Permission string

// The IDs the schema's seed SQL inserts at first run. Fixed because names are editable;
// the engine never inserts, renames or deletes these rows itself.
const (
	RoleSysop   board.RoleID = 1
	RoleCoSysop board.RoleID = 2
	RoleUser    board.RoleID = 3
	RoleGuest   board.RoleID = 4
	RoleNewUser board.RoleID = 5

	// AccountSysop is account #1, seeded by the same SQL: Sysop always, permitted
	// everything, its primary role changed by no write.
	AccountSysop board.AccountID = 1
)

// RoleKind is whether a role carries an account's settings (primary) or only adds
// permissions (grant).
type RoleKind uint8

// Role kinds.
const (
	Primary RoleKind = iota + 1
	Grant
)

// Role is one role as the unit holds it.
type Role struct {
	ID          board.RoleID
	DisplayName string
	Kind        RoleKind
	Seeded      bool // 1..5: cannot be deleted; 1 edits its name only
}

// Target is what a permission applies to when it is not board-wide: an area by kind and
// ID. The kinds are registered with the permissions that use them.
type Target struct {
	Kind string // empty: board-wide
	ID   uint32
}

// Registration is one permission as a subsystem declares it.
type Registration struct {
	Name           Permission
	DefaultHolders []board.RoleID // seed values at first run; never imposed again
	FixedToSysop   bool           // cannot be granted elsewhere, ever
}

// WriteResult is why a write was refused. Checks are never refused; they answer no.
type WriteResult uint8

// Write results.
const (
	Done WriteResult = iota + 1
	UnknownRole
	UnknownPermission
	UnknownAccount
	SeededRole
	RoleInUse
	FixedToSysop
	ActorMayNot
	AccountOne
)

// RoleUse is what uses a role: for the editor, and for the refusal that names it.
type RoleUse struct {
	Accounts []board.AccountID
	Grants   []Permission
}

// AccountRoles is what an account holds: its one primary role and every grant role.
type AccountRoles struct {
	Primary board.RoleID
	Grants  []board.RoleID
}

// RBAC is the contract. Every method that reaches the database carries a context with
// a deadline.
type RBAC interface {
	// Register is called at start, once per subsystem; by an add-on at install. A
	// duplicate name fails start.
	Register(registrations []Registration) error

	// Permissions is everything registered, for the sysop's editor.
	Permissions() []Registration

	// Test is the check. Yes only if the permission is registered, and the primary
	// role or a grant role holds it, and no restriction on the target denies it for that
	// role. Account #1: yes. Any error: no. This is the hottest path in the engine: an
	// implementation may cache a role's permissions for a short, stated lifetime, the one
	// bounded exception to nothing cached. Not audited.
	Test(ctx context.Context, account board.AccountID, permission Permission, target Target) bool

	// Roles is every role.
	Roles(ctx context.Context) ([]Role, error)

	// NewRole makes a sysop role of the given kind and returns its ID.
	NewRole(ctx context.Context, displayName string, kind RoleKind, actor audit.Actor) (board.RoleID, WriteResult, error)

	// RenameRole changes a display name; the only edit Sysop allows.
	RenameRole(ctx context.Context, id board.RoleID, displayName string, actor audit.Actor) (WriteResult, error)

	// RemoveRole refuses a seeded role, and a role in use, naming what uses it.
	RemoveRole(ctx context.Context, id board.RoleID, actor audit.Actor) (WriteResult, RoleUse, error)

	// Grant gives a role a permission, on a target or board-wide. Refused for a
	// permission fixed to Sysop, and when the actor's own role may not confer it: a
	// Co-Sysop cannot hand out Sysop's or Co-Sysop's.
	Grant(ctx context.Context, role board.RoleID, permission Permission, target Target, actor audit.Actor) (WriteResult, error)

	// Revoke takes a grant back, under the same actor rule.
	Revoke(ctx context.Context, role board.RoleID, permission Permission, target Target, actor audit.Actor) (WriteResult, error)

	// RolesOf is what an account holds.
	RolesOf(ctx context.Context, account board.AccountID) (AccountRoles, error)

	// Holders is who holds a role, as primary or as grant.
	Holders(ctx context.Context, role board.RoleID) (RoleUse, error)

	// SetPrimaryRole changes an account's one primary role. Account #1's is Sysop and no
	// write changes it. Same actor rule: a Co-Sysop cannot make anyone Sysop or Co-Sysop.
	SetPrimaryRole(ctx context.Context, account board.AccountID, role board.RoleID, actor audit.Actor) (WriteResult, error)

	// AddGrantRole and RemoveGrantRole change an account's grant roles, same actor rule.
	AddGrantRole(ctx context.Context, account board.AccountID, role board.RoleID, actor audit.Actor) (WriteResult, error)
	RemoveGrantRole(ctx context.Context, account board.AccountID, role board.RoleID, actor audit.Actor) (WriteResult, error)
}
