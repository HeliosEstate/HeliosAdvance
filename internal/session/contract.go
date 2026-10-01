// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package session is one caller, on one server, from the moment a transport hands over a
// connection until it is disconnected, by telnet, SSH or the web alike. It owns the
// session's identity, its lifecycle from arrived to logged in to disconnected, its
// server, transport, account and node, and its row in the database, from which
// who's-online is the logged-in sessions on live servers. It owns disconnecting sessions
// on this server when the engine says so. It does not own authentication, the terminal,
// the listeners, what the caller does, or what they may do. Times are the database's UTC
// clock. Every operation may return database.ErrUnavailable; at arrival the caller is
// refused before anything is shown.
//
// This file is the developer's contract (HeliosDesign records/skeleton/Session.pas) and
// is locked: a loop session does not edit it.
package session

import (
	"context"
	"time"

	"github.com/heliosestate/heliosadvance/internal/audit"
	"github.com/heliosestate/heliosadvance/internal/board"
	"github.com/heliosestate/heliosadvance/internal/nodes"
)

// ID is minted at arrival, random, 128 bits, unique across the board by construction. It
// is not a secret: it appears in logs and audit targets. A web transport that needs a
// secret for its cookie keeps its own token and maps it to the session.
type ID [16]byte

// Transport is how the caller arrived. Later features add a kind; adding one reopens
// nothing.
type Transport uint8

// Transports.
const (
	Telnet Transport = iota + 1
	SSH
	Web
)

// State is where a session is in its life.
type State uint8

// States.
const (
	Arrived State = iota + 1
	LoggedIn
	Disconnecting
	Disconnected
)

// DisconnectReason is why a session ended or is ending.
type DisconnectReason uint8

// Disconnect reasons.
const (
	HungUp DisconnectReason = iota + 1
	LoggedOff
	DisconnectedBySysop
	ServerEnding
	ServerRestarted
	Busy
	NotHonoured
)

// Row is a session as the database holds it. Who's-online is built from these joined to
// the accounts feature for the handle; the row holds only the account ID. Before login a
// session counts toward the board-wide callers-online number and shows nothing else.
type Row struct {
	ID           ID
	Server       board.ServerID
	Transport    Transport
	Source       string          // the caller's address as the transport saw it
	Arrived      time.Time       // UTC
	LoggedIn     time.Time       // zero until login
	Account      board.AccountID // 0 until login
	Node         nodes.Node      // 0 until a node is held
	State        State
	Disconnected time.Time        // zero until disconnected
	Reason       DisconnectReason // meaningful once disconnecting or disconnected
}

// LoginResult is what LoggedIn answers. On BusyResult the session keeps its account and
// no node, long enough for the transport to show the busy screen and then Disconnect it
// with Busy.
type LoginResult uint8

// Login results.
const (
	NodeTaken LoginResult = iota + 1
	BusyResult
)

// View is what a script is handed of its own session: read-only but for two actions.
type View interface {
	Row() Row

	// Disconnecting is true once a soft disconnect has been asked for. A script checks
	// it at every screen boundary and finishes; that is its one promise to this unit.
	// If the promise is not kept within the bound (sysop tunable), the disconnect
	// becomes hard, reason NotHonoured.
	Disconnecting() bool

	// LogOff is a soft disconnect, reason LoggedOff.
	LogOff(ctx context.Context) error
}

// Sessions is the contract. Every method carries a context with a deadline.
type Sessions interface {
	// Arrive is called by a transport. A database failure refuses the caller before
	// anything is shown.
	Arrive(ctx context.Context, server board.ServerID, transport Transport, source string) (View, error)

	// LoggedIn is called by the accounts feature once it knows who. It records the
	// account and takes the node from the allocator; BusyResult when the server is at
	// its limit.
	LoggedIn(ctx context.Context, id ID, account board.AccountID) (LoginResult, error)

	// Disconnect is soft when the transport is still there: it marks the session
	// disconnecting and the script finishes at its next screen boundary. It is hard when
	// the transport is gone: disconnected at once. Every disconnect frees the node and
	// marks the row. DisconnectedBySysop is audited with actor.
	Disconnect(ctx context.Context, id ID, reason DisconnectReason, hard bool, actor audit.Actor) error

	// DisconnectAll is for the engine's loop when the lease is refused or the database is
	// gone: a soft disconnect, ServerEnding, for every session on this server.
	DisconnectAll(ctx context.Context, server board.ServerID) error

	// Reconcile is called by the engine right after it acquires a lease: every row of this
	// server still open from before is disconnected, ServerRestarted, because those
	// callers are gone and only this server can know it. Who's-online was already hiding
	// them.
	Reconcile(ctx context.Context, server board.ServerID) error

	// Online is the logged-in sessions on servers whose lease is live: the board as one.
	Online(ctx context.Context) ([]Row, error)

	// OnServer is every session on a server, arrived and recently disconnected included,
	// for the sysop's tools.
	OnServer(ctx context.Context, server board.ServerID) ([]Row, error)

	// OpenCount is the open sessions on a server, for health.
	OpenCount(ctx context.Context, server board.ServerID) (uint32, error)
}
