// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package nodes is one board-wide pool of node numbers, from 1 upward. A node row holds
// the server that has it and nothing else; sessions are the session layer's, which records
// the node on its own row. Taking a node is one database statement: the lowest free
// number, granted only if the taker's lease is live and it holds fewer nodes than its node
// limit. A node held by a server whose lease is not live counts as free, so expiry frees
// nodes with nobody sweeping. The pool has no fixed size. The limit is read from the
// settings store at every Acquire and never cached; lowering it evicts nobody. Every
// operation may return database.ErrUnavailable, on which the engine refuses the caller.
// Take and Free renamed Acquire and Release at the developer's request, 2026-10-01, to
// pair with the lease.
//
// This file is the developer's contract (HeliosDesign records/skeleton/NodeAllocator.pas)
// and is locked: a loop session does not edit it.
package nodes

import (
	"context"

	"github.com/heliosestate/heliosadvance/internal/board"
)

// Node is a board-wide node number, 1 upward; 0 is never a node.
type Node uint32

// AcquireResult is why an Acquire was refused.
type AcquireResult uint8

// Acquire results.
const (
	Acquired AcquireResult = iota + 1
	AtLimit
	NotLive
)

// Acquisition is the outcome of Allocator.Acquire. Node is meaningful only when Result
// is Acquired.
type Acquisition struct {
	Result AcquireResult
	Node   Node
}

// Allocator is the contract. Every method carries a context with a deadline.
type Allocator interface {
	// Acquire is called at a caller's login. One statement: the lowest free number on the
	// board, if the server's lease is live and it holds fewer than its limit; two servers
	// or two callers cannot race past a limit. A web caller takes a node here at login and
	// never before.
	Acquire(ctx context.Context, server board.ServerID) (Acquisition, error)

	// Release is called at logout, by the same server. Releasing a node the server does not
	// hold does nothing and returns false.
	Release(ctx context.Context, server board.ServerID, node Node) (bool, error)

	// Held is the nodes a server holds, if its lease is live; empty otherwise. Health
	// reports the count against the limit from settings.
	Held(ctx context.Context, server board.ServerID) ([]Node, error)
}
