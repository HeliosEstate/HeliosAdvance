// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package registry is the set of servers that make up one board: who each is, whether it
// is admitted, and the board's minimum engine version. It owns admission at start,
// removal, renaming, and the audit of each. It owns nothing about leases, node ranges,
// per-server settings, join or the bootstrap record. Every operation goes to the
// database; nothing is cached, because the board has no degraded mode. A database failure
// is returned as database.ErrUnavailable and never turned into a default.
//
// This file is the developer's contract (HeliosDesign records/skeleton/ServerRegistry.pas)
// and is locked: a loop session does not edit it.
package registry

import (
	"context"
	"errors"

	"github.com/heliosestate/heliosadvance/internal/audit"
	"github.com/heliosestate/heliosadvance/internal/board"
)

// Every method may also return database.ErrUnavailable.

// EngineVersion is a server's engine version as it reports it at admission.
type EngineVersion struct {
	Major, Minor, Patch uint16
}

// ServerState is whether a server is part of the board or has been removed.
type ServerState uint8

// Server states. A removed server's ID is never reused.
const (
	StateAdmitted ServerState = iota + 1
	StateRemoved
)

// Server is one server's standing facts as the registry holds them.
type Server struct {
	ID          board.ServerID
	DisplayName string        // lives only in the database; the sysop may rename
	Version     EngineVersion // as last reported at admission
	State       ServerState
}

// AdmissionResult is why a server was or was not admitted. Refusal is the only output of a
// failed start. Skew is one minor version either side of the board's minimum, the fixed
// policy backstop.
type AdmissionResult uint8

// Admission results.
const (
	ResultAdmitted AdmissionResult = iota + 1
	ResultUnknownServer
	ResultRemoved
	ResultVersionTooOld
	ResultVersionTooNew
)

// Admission is the outcome of Admit. Required accompanies the two version refusals so the
// operator is told what to install.
type Admission struct {
	Result   AdmissionResult
	Required EngineVersion
}

// ErrUnknownServer is returned by Server for an ID that was never allocated. A caller
// tests it with errors.Is.
var ErrUnknownServer = errors.New("registry: unknown server")

// Registry is the contract. Every method carries a context with a deadline.
type Registry interface {
	// Admit checks, in this order: the ID exists and is not removed; the version is within
	// one minor of the board's minimum; then records the version and marks the server
	// admitted. The lease is the lease unit's and begins after this.
	Admit(ctx context.Context, id board.ServerID, version EngineVersion) (Admission, error)

	// AdmittedServers is the board as one: for the session layer and who's-online.
	AdmittedServers(ctx context.Context) ([]Server, error)

	// AllServers is every server ever, removed ones included, for the sysop's tools.
	AllServers(ctx context.Context) ([]Server, error)

	// Server is one server by ID; ErrUnknownServer if there is none.
	Server(ctx context.Context, id board.ServerID) (Server, error)

	// Remove marks the server removed and audits; it does nothing else. The server's next
	// lease renewal is refused, so it ends its own sessions; its lease expires, which frees
	// its nodes; the allocator retires the range on its next derivation; the database login
	// is revoked by the tool performing the removal, which holds the administrator
	// credential. Idempotent: removing a removed server succeeds and audits nothing.
	Remove(ctx context.Context, id board.ServerID, actor audit.Actor) error

	// Rename is audited with the name before and after. Idempotent on an unchanged name.
	Rename(ctx context.Context, id board.ServerID, newName string, actor audit.Actor) error

	// MinimumVersion is the board's minimum engine version.
	MinimumVersion(ctx context.Context) (EngineVersion, error)

	// RaiseMinimumVersion is called only by the setup tool, under the administrator
	// credential, when it applies a data-model change that needs it.
	RaiseMinimumVersion(ctx context.Context, version EngineVersion, actor audit.Actor) error
}
