// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package lease is the liveness of admitted servers: one row per server, on the
// database's clock. A lease is live while its last renewal is younger than the timeout
// (three missed renewals, sysop tunable); expiry is computed by every reader from the
// clock, never raised as an event. A generation increases on every acquisition so a stale
// holder can be told apart from the current one, and renewal is one write that succeeds
// only for the current generation of an admitted server. The unit owns nothing about what
// a server does when refused; that protocol is stated on RenewalResult and lived in the
// engine. Every operation may return database.ErrUnavailable.
//
// This file is the developer's contract (HeliosDesign records/skeleton/Lease.pas) and is
// locked: a loop session does not edit it.
package lease

import (
	"context"

	"github.com/heliosestate/heliosadvance/internal/board"
)

// Generation increases on every Acquire for a server. A holder presents it on Renew and
// Release.
type Generation uint64

// RenewalResult is why a renewal was refused, and what the engine does about it.
//
//   - Superseded: another process acquired this ID; end sessions and stay down.
//   - Expired: the lease lapsed on the database's clock; end sessions, then Admit and
//     Acquire again on its own, refusing new callers until Acquire succeeds.
//   - NotAdmitted: the server was removed; end sessions and stay down.
//
// A renewal that cannot reach the database returns database.ErrUnavailable instead: the
// engine counts a missed renewal and tries again at the interval.
type RenewalResult uint8

// Renewal results.
const (
	Renewed RenewalResult = iota + 1
	Superseded
	Expired
	NotAdmitted
)

// Lease is the contract. Every method carries a context with a deadline.
type Lease interface {
	// Acquire is called after admission. It creates or replaces the row with a new
	// generation and returns it. It always succeeds: a live lease for the same ID is
	// superseded, so a second process started with the same bootstrap record evicts the
	// first, which learns at its next renewal. A misconfiguration is contained to that
	// server and never blocks a restart.
	Acquire(ctx context.Context, id board.ServerID) (Generation, error)

	// Renew is one write: it succeeds only if the row's generation matches and the server
	// is admitted.
	Renew(ctx context.Context, id board.ServerID, generation Generation) (RenewalResult, error)

	// Release is clean shutdown: the lease is expired now rather than in three intervals,
	// so a planned stop frees the nodes immediately. Same generation check; a stale holder
	// is ignored.
	Release(ctx context.Context, id board.ServerID, generation Generation) error

	// Live is the servers whose lease is live at the moment of asking, on the database's
	// clock. The allocator's occupancy rule, who's-online's filter and health's one line
	// all read this and nothing else.
	Live(ctx context.Context) ([]board.ServerID, error)
}
