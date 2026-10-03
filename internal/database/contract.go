// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package database is the board's one PostgreSQL database, as every other unit reaches
// it. It owns the connection, from what the bootstrap record supplies, over TLS with the
// chain and the host name verified; the transaction a change runs in; what counts as the
// database being unavailable; the one numbered sequence of migrations and the runner
// hadv-setup applies them with; and the test harness that gives every test a database of
// its own (databasetest, not declared here: no unit calls it). It does not own the
// bootstrap record or how it is protected on disk, the key-encryption key included (the
// setup tool's); any table's columns or queries (the unit that owns the rows); creating
// or revoking logins, or the administrator's credential (first-run setup and the join
// feature); what the engine does when the database is gone (the engine's loop); failover
// and pooling across servers (a PostgreSQL proxy, per the sysop guide); any bus between
// servers.
//
// Every operation may return ErrUnavailable, which wraps its cause. A statement error,
// the database answering that the statement is wrong (syntax, an unknown column, a wrong
// type, a value out of range, a missing grant, a constraint violation the unit should
// have checked for first, a NULL read as a value, a second row for QueryRow), is any
// other error: a bug, never a reason to treat the database as gone, and no unit branches
// on it.
//
// Migrations are plain SQL under migrations/, one sequence for the board, named for the
// unit they serve, seed rows included, written in the QA session with the developer
// present and committed with the tests. They are additive: a migration may not break a
// server running the previous version's SQL, so new tables, and new columns nullable or
// defaulted; no rename, no type change, no constraint the old writes could violate; a
// field no longer used waits two minor versions before it is removed. They grant table
// rights to one group role, hadv_server, that every server's login joins; a server's
// login holds no right to change the schema. The driver, pgx v5, is imported by this
// package and no other.
//
// This file is the developer's contract (HeliosDesign records/skeleton/Database.pas) and
// is locked: a loop session does not edit it.
package database

import (
	"context"
	"errors"
	"time"

	"github.com/heliosestate/heliosadvance/internal/board"
)

// ErrUnavailable is returned when the database could not be reached or the work could not
// finish against it: connection refused or lost, a certificate that does not verify, a
// login refused, the deadline passed or the caller cancelled, the server shutting down or
// out of resources, a collision still colliding after the retries, a commit whose outcome
// is unknown. It wraps the cause for the log. A caller never turns it into a default: the
// board has no degraded mode. This package never retries it; the next call tries afresh,
// which is how a server resumes without operator action when the database returns.
var ErrUnavailable = errors.New("database: unavailable")

// ErrConfiguration is returned when the connection settings are refused before anything
// is sent: plaintext asked for to an address that is not loopback or a local socket, or a
// pool size of 0. Start fails.
var ErrConfiguration = errors.New("database: connection settings refused")

// ErrSchema is returned when the database does not match what this build carries: a
// migration it needs is missing, or an applied one has changed. Start fails; hadv-setup's
// upgrade is the fix.
var ErrSchema = errors.New("database: schema does not match this build")

// Connection is what the bootstrap record supplies. Opening checks it and connects
// nothing; the first call connects, so a database unreachable at start is ErrUnavailable
// at the engine's first Approve, and no listener opens before that succeeds. Every
// connection verifies the chain and the host name against TrustAnchor, and is set to UTC.
type Connection struct {
	Address          string // host:port, or a local socket path
	DatabaseName     string
	TrustAnchor      string // PEM: the authority the database's certificate must chain to
	Login            string // this server's own login; SCRAM-SHA-256
	Password         string
	PlaintextAllowed bool           // the sysop's explicit choice; loopback or a local socket only
	PoolSize         uint32         // connections this server holds at most; setup writes the default
	Server           board.ServerID // named on every connection, so the sysop sees which server holds which; 0 for hadv-setup
}

// Columns is the current row's columns, by the name the statement selected. Each As
// method returns an error if the column is NULL: a NULL never passes for an empty value.
// Ask IsNull first where the column allows it.
type Columns interface {
	AsInteger(column string) (int64, error) // IDs, node numbers, durations in seconds
	AsText(column string) (string, error)
	AsBoolean(column string) (bool, error)
	AsTime(column string) (time.Time, error) // UTC
	AsBytes(column string) ([]byte, error)
	IsNull(column string) (bool, error)
}

// Rows is a result set, read a row at a time. Next returns ErrUnavailable if the
// connection is lost partway through.
type Rows interface {
	Columns
	Next() (bool, error)
	// Close frees the connection. Required: an unclosed result holds its connection. The
	// test harness fails a test that leaves one open.
	Close()
}

// Row is at most one row, already read; the connection is free before QueryRow returns.
// A statement that matches a second row is a statement error: its WHERE is wrong.
type Row interface {
	Columns
	Found() bool // false: the statement matched nothing
}

// Transaction is a change's own transaction. It carries the deadline Transact was given,
// so its operations take none. Statements are each unit's own SQL against its own tables.
// A unit that inserts a key that could collide checks for it first in the same
// transaction: then a race is a serialization failure, which Transact retries, and a
// duplicate the check finds is the unit's own refusal.
type Transaction interface {
	Query(statement string, arguments ...any) (Rows, error)
	QueryRow(statement string, arguments ...any) (Row, error)
	Execute(statement string, arguments ...any) (int64, error) // rows affected
}

// Work runs inside one SERIALIZABLE transaction, and again from the start if the database
// reports a serialization failure or a deadlock. It touches nothing outside the
// transaction (no sends, no files, no session state) and returns what it found through
// the caller's own variables; the caller acts only after Transact returns.
type Work func(transaction Transaction) error

// Database is the contract.
type Database interface {
	// Transact begins under ctx, runs work, commits if work returns nil and rolls back if
	// it returns an error, which is returned unchanged. On a serialization failure or a
	// deadlock it runs work again up to three more times, with a short random pause,
	// inside the deadline. Every write goes through here, even a single statement. No
	// exactly-once: a commit whose connection drops is ErrUnavailable, and each unit's
	// contract makes its changes safe to repeat or says how they are reconciled.
	Transact(ctx context.Context, work Work) error
	// Query and QueryRow are a read of one statement, outside any transaction, which
	// PostgreSQL runs in its own. Settings are read on every use with no cache; this saves
	// the BEGIN and COMMIT round trips Transact costs.
	Query(ctx context.Context, statement string, arguments ...any) (Rows, error)
	QueryRow(ctx context.Context, statement string, arguments ...any) (Row, error)
	// Verify returns ErrSchema if a migration this build carries is unapplied or an
	// applied one's checksum differs. Later migrations it does not carry pass: they are
	// additive, and the registry's version check decides whether this server may join.
	// The engine calls it at start, before Approve.
	Verify(ctx context.Context) error
	// Migrate applies every unapplied migration in number order, each in its own
	// transaction, recording its number and checksum. hadv-setup only, under the
	// administrator's login; a server's login gets a statement error.
	Migrate(ctx context.Context) error
	// Close is the clean stop, after the lease's Release: it waits for work in progress
	// until ctx's deadline, then closes every connection.
	Close(ctx context.Context) error
}
