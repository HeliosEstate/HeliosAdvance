// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package database is the engine's side of the board's database: the connection settings the
// bootstrap file seals, signing in, the checks made each time the lease is taken, and the server's
// lease.
//
// It owns reading the connection settings, the JSON the bootstrap unit unseals; connecting to
// PostgreSQL over TLS and signing in by SCRAM-SHA-256 with channel binding, on
// github.com/jackc/pgx/v5 at v5.11.0 or later; refusing a login that could change the schema;
// reading the schema version and the server's row; and the lease: taking it, renewing it every
// RenewSeconds while it is held, telling the program once it is lost, and ending it at a stop. The
// schema and what a server's login may do with it are schema.sql, beside this file, and Schema
// holds it.
//
// It does not own waiting and trying again, the listeners, or the local log: the program decides
// from each error whether to wait or to stop, opens and closes the listeners, and writes every log
// line in its own words. The command line, which names the bootstrap folder, is the program's; the
// bootstrap folder, its key file and the sealing are the bootstrap unit's. Creating the database,
// the owner, the server's login and row, and the bootstrap file belong to hadv-setup; acting on
// another server's ended lease, and the cleanup after a run whose lease ended, to later layers.
//
// What the engine does as a whole, this package included, is in docs/behavior.md.
//
// # Untrusted input
//
// The connection to the database crosses a trust boundary: until the database's certificate
// chains to the Connection's certificate authority and names its host, the other end may be
// anyone, and nothing is sent to it but the TLS handshake. After it, the library reads every reply
// from the database: the sign-in, the rows and the errors, each message at most ReplyMostBytes.
// This package reads one integer, one row of three columns and the login's rights from those
// replies, and keeps none of the database's text in an error. The connection settings are
// hadv-setup's, sealed in the bootstrap file, not a caller's; they reach this package only once
// the bootstrap unit has unsealed them, which bounds them. No caller's byte reaches this package.
// There is no fuzz target here: the standard library parses the JSON and the library the wire.
//
// # Oracles
//
// PostgreSQL itself, a real server driven from outside: the tests create the database from Schema
// as the owner, a server's login as a member of hadv_server, the row and the bootstrap folder, as
// hadv-setup will; read and write hadv.servers with SQL; stop and start the server; change its
// sign-in rules; and make their own certificate authority, signing with ECDSA P-256 and SHA-256.
// Tests run on Linux x86-64, Linux ARM64 and Windows x86-64, as an ordinary user.
//
// # What it needs from its callers
//
// One ServerDatabase per run of the engine, made from the Connection once. One Take at a
// time, and a new Take only once the Lease it returned is lost or ended. A context that a stop
// cancels.
//
// # Lines for the package
//
//   - The database package shall write nothing to the local log, standard output or standard
//     error. [read]
//   - No error the database package returns shall hold, in its text, the Connection's password,
//     any other part of the connection settings, or any text the database sent.
//   - The database package shall take where it connects, its login and its password from the
//     Connection alone, whatever PostgreSQL's environment variables, password file or service
//     file give.
//   - If a message from the database is longer than ReplyMostBytes, then the database package
//     shall treat the connection as failed, ErrUnreachable at a take, without reading the rest.
//   - The database package shall import nothing outside the Go standard library,
//     github.com/jackc/pgx/v5, github.com/jackc/pgx/v5/pgconn and
//     github.com/jackc/pgx/v5/pgproto3. [read]
package database

import (
	"context"
	_ "embed" // Schema is schema.sql, embedded.
	"errors"
)

const (
	// SchemaVersionMadeFor is the schema version this engine was made for. It also accepts the
	// next, so servers one version apart share the database during a rolling update.
	SchemaVersionMadeFor = 1
	// LeaseSeconds is how long after the database's time a take or a renewal ends the lease.
	LeaseSeconds = 30
	// LossSeconds is how long after it sent its last take or renewal that succeeded the Lease
	// counts the lease lost: short of LeaseSeconds, so the program has closed its listeners and
	// callers before the database's lease ends and another run can take it.
	LossSeconds = 25
	// RenewSeconds is how often a held lease is renewed, so two renewals can fail before a loss.
	RenewSeconds = 10
	// TrySeconds is how long one take or one renewal waits on the database before it gives up,
	// so none hangs past the lease.
	TrySeconds = 10
	// EndWaitMilliseconds is the longest EndLease waits on the database, so a stop stays quick.
	EndWaitMilliseconds = 1000
	// ReplyMostBytes bounds each message read from the database, so what the engine reads from
	// the network has a bound; this part's replies are far shorter.
	ReplyMostBytes = 1048576
)

// Schema is the board's schema, version SchemaVersionMadeFor, and the rights of a server's login:
// schema.sql, run once by the owner login.
//
//go:embed schema.sql
var Schema string

// Why ParseConnection refused the connection settings. None holds any part of them, so the
// program can write it to the local log as it is.
var (
	// ErrFormat means the connection settings are not in their format: not one JSON object, a
	// field given twice, or a field not of its kind.
	ErrFormat = errors.New("database: the bootstrap file's connection settings are not in their format")
	// ErrFieldUnknown means the connection settings hold a field the format does not name.
	ErrFieldUnknown = errors.New("database: the bootstrap file's connection settings hold a field the format does not name")
	// ErrFieldMissing means the connection settings lack one of the format's seven fields.
	ErrFieldMissing = errors.New("database: the bootstrap file's connection settings are missing a field")
)

// Why Take failed. ErrUnreachable, ErrNotReady, ErrNoConnectionFree, ErrReadOnly and ErrLeaseHeld
// fix themselves, so the program waits and takes again; every other one does not, so the program
// stops. None holds the password or any text the database sent.
var (
	// ErrUnreachable means the database did not answer within TrySeconds, refused the
	// connection, or the connection failed after it was made.
	ErrUnreachable = errors.New("database: the database does not answer")
	// ErrNotReady means the database answered that it is starting up, shutting down or
	// recovering.
	ErrNotReady = errors.New("database: the database is starting up, shutting down or recovering")
	// ErrNoConnectionFree means the database answered that it has no connection free.
	ErrNoConnectionFree = errors.New("database: the database has no connection free")
	// ErrReadOnly means the database answered that it is read-only, as one is until a failover
	// completes.
	ErrReadOnly = errors.New("database: the database is read-only")
	// ErrRefused means the database refused for any reason no other error names.
	ErrRefused = errors.New("database: the database refuses")
	// ErrLeaseHeld means the server's lease has not ended and its holder is not this run's own.
	ErrLeaseHeld = errors.New("database: the server's lease is held by another run")
	// ErrCertificate means the database's certificate does not chain to the Connection's
	// certificate authority, does not name its host, or cannot be used for channel binding.
	ErrCertificate = errors.New("database: the database's certificate fails its check")
	// ErrSignInMethod means the database asked for a way of signing in other than SCRAM-SHA-256
	// with channel binding.
	ErrSignInMethod = errors.New("database: the database asks for another way of signing in")
	// ErrSignInRefused means the database refused the login or its password.
	ErrSignInRefused = errors.New("database: the database refuses the sign-in")
	// ErrTooPowerful means the login holds a right beyond those schema.sql grants a server's
	// login, or the power to take one.
	ErrTooPowerful = errors.New("database: the login holds more rights than a server's login is granted")
	// ErrNoServerRow means hadv.servers holds no row for the Connection's server ID.
	ErrNoServerRow = errors.New("database: no row for this server's ID")
	// ErrSchemaVersion is what a SchemaVersionError matches through errors.Is.
	ErrSchemaVersion = errors.New("database: the schema version is not one this engine accepts")
)

// SchemaVersionError means hadv.schema_version is missing, holds no row, holds anything but one
// integer, or holds a version other than SchemaVersionMadeFor and the next. It matches
// ErrSchemaVersion through errors.Is, and holds a number, never text the database sent.
type SchemaVersionError struct {
	// Found is the version read, when Missing is false.
	Found int32
	// Missing is true when the table, its row or an integer version is missing.
	Missing bool
}

// Error names the version found, or says none was.
func (failure *SchemaVersionError) Error() string {
	return schemaVersionText(failure)
}

// Unwrap returns ErrSchemaVersion, so errors.Is matches it.
func (failure *SchemaVersionError) Unwrap() error {
	return ErrSchemaVersion
}

// Connection is what the connection settings hold: where the database is and how this server signs
// in. The bootstrap file seals them as one JSON object, its fields named server_id (an integer),
// host, port (an integer), database, login, password and ca_certificate (PEM text), each required,
// no other.
type Connection struct {
	// ServerID is this server's row in hadv.servers.
	ServerID int64
	// Host is the database's address, and the name its certificate carries.
	Host string
	// Port is the database's port.
	Port uint16
	// Database is the database's name on that server.
	Database string
	// Login is this server's own login.
	Login string
	// Password is the login's password. It never reaches a log or an error.
	Password string
	// CACertificate is the certificate authority, as PEM text, the database's certificate chains
	// to.
	CACertificate string
}

// ParseConnection reads the connection settings, the JSON the bootstrap unit unsealed. The checks
// run in the order of the lines below, and the first that applies is the result. The caller wipes
// contents once ParseConnection returns; nothing ParseConnection returns shares its memory.
//
//   - ParseConnection shall check the connection settings in the order of these lines and return
//     the first refusal that applies.
//   - If the connection settings are not one JSON object, or give a field twice, then
//     ParseConnection shall return ErrFormat.
//   - If the object holds a field whose name is not exactly one of server_id, host, port,
//     database, login, password and ca_certificate, then ParseConnection shall return
//     ErrFieldUnknown.
//   - If the object lacks one of those seven fields, then ParseConnection shall return
//     ErrFieldMissing.
//   - If server_id is not an integer, port is not an integer from 1 to 65535, another field is
//     not a non-empty string, or ca_certificate is not one or more PEM blocks of type CERTIFICATE,
//     each an X.509 certificate, and nothing else, then ParseConnection shall return ErrFormat.
//   - ParseConnection shall return an error whose text holds no part of the connection settings.
func ParseConnection(contents []byte) (Connection, error) {
	return parseConnection(contents)
}

// ServerDatabase is one run of the engine against its database. It remembers the lease holder it
// last sent, whether or not the reply came back, so the run can take its own lease back at once
// after a loss.
type ServerDatabase struct {
	state serverDatabaseState
}

// NewServerDatabase makes the run's ServerDatabase from the Connection. Nothing is connected until
// Take.
//
//   - NewServerDatabase shall connect to nothing.
func NewServerDatabase(connection Connection) *ServerDatabase {
	return newServerDatabase(connection)
}

// Take connects, signs in, makes the checks in the order below, and takes the server's lease,
// waiting on the database at most TrySeconds. On an error it closes the connection it made and
// returns a nil Lease. When the context ends, the context's error wins.
//
//   - Take shall connect to the Connection's host and port over TLS 1.2 or 1.3 only, and accept
//     the database's certificate only when it chains to the Connection's certificate authority
//     and names its host.
//   - Take shall sign in as the Connection's login, to its database, only by SCRAM-SHA-256
//     with channel binding.
//   - Take shall make the checks in the order of the lines below, and return the first failure;
//     until it has signed in, the first failure is the one the connection meets first.
//   - If the database does not answer within TrySeconds, refuses the connection, or the
//     connection fails after it is made, then Take shall return ErrUnreachable.
//   - If the database answers that it is starting up, shutting down or recovering, then Take
//     shall return ErrNotReady.
//   - If the database answers that it has no connection free, then Take shall return
//     ErrNoConnectionFree.
//   - If the database will not use TLS 1.2 or 1.3, then Take shall return ErrRefused without
//     sending the password.
//   - If the database's certificate fails its check, or cannot be used for channel binding, then
//     Take shall return ErrCertificate without sending the password.
//   - If the database asks for any other way of signing in, then Take shall return
//     ErrSignInMethod without sending the password.
//   - If the database refuses the sign-in, then Take shall return ErrSignInRefused.
//   - If the login holds any role attribute but LOGIN and INHERIT (SUPERUSER, CREATEROLE,
//     CREATEDB, REPLICATION and BYPASSRLS among them), is a member of any role but hadv_server,
//     may grant hadv_server to another role, owns anything in the database, or holds, itself or
//     through PUBLIC, a right on the database or on any schema or object in it that schema.sql
//     does not grant hadv_server; or if hadv_server holds any role attribute but INHERIT; then
//     Take shall return ErrTooPowerful. Connecting to the database; USAGE on a language, on a data
//     type and on the schema public, which PostgreSQL gives every login by default; and the
//     rights PostgreSQL gives every login by default on its own catalogs, are not counted; a right
//     granted beyond those defaults on a catalog object, such as EXECUTE on pg_read_file, is.
//   - If the database answers that it is read-only, then Take shall return ErrReadOnly.
//   - If hadv.schema_version is missing, holds no row, holds anything but one integer, or holds a
//     version other than SchemaVersionMadeFor and the next, then Take shall return a
//     *SchemaVersionError naming the version found, or Missing.
//   - If hadv.servers holds no row for the Connection's server ID, then Take shall return
//     ErrNoServerRow.
//   - When the server's row's lease has ended, or its lease holder is the one this ServerDatabase
//     last sent, Take shall write a new random lease holder and a lease end LeaseSeconds after
//     the database's current time to that row, and return the Lease.
//   - If the lease has not ended and its holder is not the one this ServerDatabase last sent,
//     then Take shall return ErrLeaseHeld and change nothing.
//   - If the database refuses for any reason the lines above do not name, then Take shall return
//     ErrRefused.
//   - If the context has ended when Take is called, or ends while it waits, then Take shall
//     return the context's error, wrapped.
func (server *ServerDatabase) Take(ctx context.Context) (*Lease, error) {
	return server.take(ctx)
}

// Lease is the server's lease while this run holds it. It renews itself every RenewSeconds, over
// its own connection, until it is lost or ended.
//
//   - While it is held, the Lease shall renew it every RenewSeconds, writing a lease end
//     LeaseSeconds after the database's current time, only while the row's lease holder is its
//     own, and waiting on the database at most TrySeconds.
//   - If a renewal fails for any reason but finding the row's lease holder is not its own, then
//     the Lease shall try again at the next renewal, over a new connection when its connection
//     failed.
//   - When LossSeconds have passed since it sent its last take or renewal that succeeded, the
//     Lease shall close the channel Lost returns.
//   - When a renewal finds the row's lease holder is not its own, the Lease shall close the channel
//     Lost returns at once.
//   - Once the channel Lost returns is closed, the Lease shall renew no more and close its
//     connection.
type Lease struct {
	state leaseState
}

// Lost returns a channel that is closed once, when the lease is lost. It is never closed by
// EndLease.
func (lease *Lease) Lost() <-chan struct{} {
	return lease.lost()
}

// EndLease ends the lease at a stop: it renews no more, sets the lease end to the database's
// current time while the holder is its own, waiting at most EndWaitMilliseconds, and closes its
// connection. It returns nothing: when the database does not answer, the lease ends LeaseSeconds
// after its last renewal anyway.
//
//   - EndLease shall set the row's lease end to the database's current time, only while the row's
//     lease holder is its own, waiting on the database at most EndWaitMilliseconds.
//   - EndLease shall stop the renewals and close the Lease's connection before it returns.
func (lease *Lease) EndLease() {
	lease.endLease()
}
