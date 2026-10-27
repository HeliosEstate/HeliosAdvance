// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package database is the engine's side of the board's database: the connection file, signing in,
// the checks made each time the lease is taken, and the server's lease.
//
// It owns reading the connection file the sysop names; connecting to PostgreSQL over TLS and
// signing in by SCRAM-SHA-256 with channel binding, on github.com/jackc/pgx/v5 at v5.11.0 or
// later; refusing a login that could change the schema; reading the schema version and the
// server's row; and the lease: taking it, renewing it every RenewSeconds while it is held, telling
// the program once it is lost, and ending it at a stop. The schema and what a server's login may
// do with it are schema.sql, beside this file, and Schema holds it.
//
// It does not own waiting and trying again, the listeners, or the local log: the program decides
// from each error whether to wait or to stop, opens and closes the listeners, and writes every log
// line in its own words. The command line, which names the connection file, is the program's.
// Creating the database, the owner, the server's login and row, and the connection file belong to
// hadv-setup; acting on another server's ended lease, and the cleanup after a run whose lease
// ended, to later layers.
//
// What the engine does as a whole, this package included, is in docs/behavior.md.
//
// # Untrusted input
//
// The connection to the database crosses a trust boundary: until the database's certificate
// chains to the connection file's certificate authority and names its host, the other end may be
// anyone, and nothing is sent to it but the TLS handshake. After it, the library reads every reply
// from the database: the sign-in, the rows and the errors. This package reads one integer, one row
// of three columns and the login's rights from those replies, and keeps none of the database's
// text in an error. The connection file is the sysop's, not a caller's; it is read once, at most
// ConnectionFileMostBytes. No caller's byte reaches this package. There is no fuzz target here:
// the standard library parses the file and the library the wire.
//
// # Oracles
//
// PostgreSQL itself, a real server driven from outside: the tests create the database from Schema
// as the owner, a server's login as a member of hadv_server, the row and the connection file, as
// hadv-setup will; read and write hadv.servers with SQL; stop and start the server; change its
// sign-in rules; and make their own certificate authority, signing with ECDSA P-256 and SHA-256.
// Tests run on Linux x86-64, Linux ARM64 and Windows x86-64, as an ordinary user.
//
// # What it needs from its callers
//
// One ServerDatabase per run of the engine, made from the connection file once. One Take at a
// time, and a new Take only once the Lease it returned is lost or ended. A context that a stop
// cancels.
//
// # Lines for the package
//
//   - The database package shall write nothing to the local log, standard output or standard
//     error. [read]
//   - No error the database package returns shall hold, in its text, the connection file's
//     password or any text the database sent.
//   - The database package shall take where it connects, its login and its password from the
//     ConnectionFile alone, whatever PostgreSQL's environment variables, password file or service
//     file give.
//   - Once a Lease is lost or ended, the database package shall leave no goroutine of its own, or
//     of the library's for that Lease, running. [read]
//   - The database package shall import nothing outside the Go standard library,
//     github.com/jackc/pgx/v5 and github.com/jackc/pgx/v5/pgconn. [read]
package database

import (
	"context"
	_ "embed" // Schema is schema.sql, embedded.
	"errors"
)

const (
	// ConnectionFileMostBytes bounds the connection file: a longer one is refused, so what is
	// read has a bound.
	ConnectionFileMostBytes = 65536
	// SchemaVersionMadeFor is the schema version this engine was made for. It also accepts the
	// next, so servers one version apart share the database during a rolling update.
	SchemaVersionMadeFor = 1
	// LeaseSeconds is how long after the database's time a take or a renewal ends the lease.
	LeaseSeconds = 30
	// RenewSeconds is how often a held lease is renewed, so two renewals can fail before it ends.
	RenewSeconds = 10
	// TrySeconds is how long one take or one renewal waits on the database before it gives up,
	// so none hangs past the lease.
	TrySeconds = 10
	// EndWaitMilliseconds is the longest EndLease waits on the database, so a stop stays quick.
	EndWaitMilliseconds = 1000
)

// Schema is the board's schema, version SchemaVersionMadeFor, and the rights of a server's login:
// schema.sql, run once by the owner login.
//
//go:embed schema.sql
var Schema string

// Why ReadConnectionFile refused the file. None holds any part of the file's contents, so the
// program can write it to the local log as it is.
var (
	// ErrFileMissing means no file is at the path given.
	ErrFileMissing = errors.New("database: the connection file does not exist")
	// ErrFileReadableByOthers means, on Linux, the file's mode lets its group or others read it.
	ErrFileReadableByOthers = errors.New("database: the connection file's mode lets its group or others read it")
	// ErrFileUnreadable means the file is there but cannot be read.
	ErrFileUnreadable = errors.New("database: the connection file cannot be read")
	// ErrFileTooLarge means the file is longer than ConnectionFileMostBytes.
	ErrFileTooLarge = errors.New("database: the connection file is too large")
	// ErrFileFormat means the file is not in the connection file's format: not one JSON object
	// holding the seven fields of ConnectionFile, each of its kind, and no other.
	ErrFileFormat = errors.New("database: the connection file is not in the connection file's format")
)

// Why Take failed. ErrUnreachable and ErrLeaseHeld fix themselves, so the program waits and takes
// again; every other one does not, so the program stops. None holds the password or any text the
// database sent.
var (
	// ErrUnreachable means the database did not answer within TrySeconds, refused the
	// connection, said it is starting up, or the connection failed after it was made.
	ErrUnreachable = errors.New("database: the database does not answer")
	// ErrLeaseHeld means the server's lease has not ended and its holder is not this run's own.
	ErrLeaseHeld = errors.New("database: the server's lease is held by another run")
	// ErrCertificate means the database's certificate does not chain to the connection file's
	// certificate authority, does not name its host, or cannot be used for channel binding.
	ErrCertificate = errors.New("database: the database's certificate fails its check")
	// ErrSignInMethod means the database asked for a way of signing in other than SCRAM-SHA-256
	// with channel binding.
	ErrSignInMethod = errors.New("database: the database asks for another way of signing in")
	// ErrSignInRefused means the database refused the login or its password.
	ErrSignInRefused = errors.New("database: the database refuses the sign-in")
	// ErrTooPowerful means the login could change the schema.
	ErrTooPowerful = errors.New("database: the login could change the schema")
	// ErrNoServerRow means hadv.servers holds no row for the connection file's server ID.
	ErrNoServerRow = errors.New("database: no row for this server's ID")
	// ErrSchemaVersion is what a SchemaVersionError matches through errors.Is.
	ErrSchemaVersion = errors.New("database: the schema version is not one this engine accepts")
)

// SchemaVersionError means hadv.schema_version is missing, holds no row, or holds a version other
// than SchemaVersionMadeFor and the next. It matches ErrSchemaVersion through errors.Is.
type SchemaVersionError struct {
	// Found is the version as read, or empty when the table or its row is missing.
	Found string
}

// Error names the version found, or says none was.
func (failure *SchemaVersionError) Error() string {
	return schemaVersionText(failure)
}

// Unwrap returns ErrSchemaVersion, so errors.Is matches it.
func (failure *SchemaVersionError) Unwrap() error {
	return ErrSchemaVersion
}

// ConnectionFile is what the connection file holds: where the database is and how this server
// signs in. On disk it is one JSON object, its fields named server_id (an integer), host, port (an
// integer), database, login, password and ca_certificate (PEM text), each required, no other.
type ConnectionFile struct {
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

// ReadConnectionFile reads the connection file at path once and closes it. The checks run in the
// order of the lines below, and the first that applies is the result.
//
//   - ReadConnectionFile shall check the file in the order of these lines and return the first
//     refusal that applies.
//   - If no file is at path, then ReadConnectionFile shall return ErrFileMissing.
//   - If, on Linux, the file's mode lets its group or others read it, then ReadConnectionFile
//     shall return ErrFileReadableByOthers without reading the file.
//   - If the file cannot be read, then ReadConnectionFile shall return ErrFileUnreadable.
//   - If the file is longer than ConnectionFileMostBytes, then ReadConnectionFile shall return
//     ErrFileTooLarge.
//   - If the file is not one JSON object holding server_id, host, port, database, login, password
//     and ca_certificate and no other field, server_id an integer, port an integer from 1 to
//     65535, every other field a non-empty string, and ca_certificate one or more PEM blocks of
//     type CERTIFICATE and nothing else, then ReadConnectionFile shall return ErrFileFormat.
//   - ReadConnectionFile shall return an error whose text holds no part of the file's contents.
//   - ReadConnectionFile shall read at most ConnectionFileMostBytes and one byte more from the
//     file, and close it before it returns. [read]
func ReadConnectionFile(path string) (ConnectionFile, error) {
	return readConnectionFile(path)
}

// ServerDatabase is one run of the engine against its database. It remembers the lease holder it
// last wrote, so the run can take its own lease back at once after a loss.
type ServerDatabase struct {
	state serverDatabaseState
}

// NewServerDatabase makes the run's ServerDatabase from the connection file. Nothing is connected
// until Take.
//
//   - NewServerDatabase shall connect to nothing.
func NewServerDatabase(file ConnectionFile) *ServerDatabase {
	return newServerDatabase(file)
}

// Take connects, signs in, makes the checks in the order below, and takes the server's lease,
// waiting on the database at most TrySeconds. On an error it closes the connection it made and
// returns a nil Lease. When the context ends, the context's error wins.
//
//   - Take shall connect to the ConnectionFile's host and port over TLS 1.2 or 1.3 only, and accept
//     the database's certificate only when it chains to the ConnectionFile's certificate authority
//     and names its host.
//   - Take shall sign in as the ConnectionFile's login, to its database, only by SCRAM-SHA-256
//     with channel binding.
//   - Take shall make the checks in the order of the lines below, and return the first failure.
//   - If the database does not answer within TrySeconds, refuses the connection, says it is
//     starting up, or the connection fails after it is made, then Take shall return
//     ErrUnreachable.
//   - If the database's certificate fails its check, or cannot be used for channel binding, then
//     Take shall return ErrCertificate without sending the password.
//   - If the database asks for any other way of signing in, then Take shall return
//     ErrSignInMethod without sending the password.
//   - If the database refuses the sign-in, then Take shall return ErrSignInRefused.
//   - If the login is a superuser, owns the hadv schema or a table in it, is a member of a role
//     that does, or holds the right to create in the schema, then Take shall return
//     ErrTooPowerful.
//   - If hadv.schema_version is missing, holds no row, or holds a version other than
//     SchemaVersionMadeFor and the next, then Take shall return a *SchemaVersionError naming the
//     version found.
//   - If hadv.servers holds no row for the ConnectionFile's server ID, then Take shall return
//     ErrNoServerRow.
//   - When the server's row's lease has ended, or its lease holder is the one this ServerDatabase
//     last wrote, Take shall write a new random lease holder and a lease end LeaseSeconds after
//     the database's current time to that row, and return the Lease.
//   - If the lease has not ended and its holder is not the one this ServerDatabase last wrote,
//     then Take shall return ErrLeaseHeld and change nothing.
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
//   - If a renewal fails because the database does not answer, then the Lease shall try again at
//     the next renewal, over a new connection when its connection failed.
//   - When LeaseSeconds have passed since it sent its last take or renewal that succeeded, the
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
