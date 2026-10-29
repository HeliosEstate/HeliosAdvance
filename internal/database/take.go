// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package database

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// leaseEndSQL is the new lease end, LeaseSeconds after the database's own time.
var leaseEndSQL = "now() + interval '" + strconv.Itoa(LeaseSeconds) + " seconds'"

// takeSQL writes the new holder only while the lease has ended or the holder is the one last
// sent. A holder that is NULL matches nothing, which is right for a run that has sent none.
var takeSQL = "UPDATE hadv.servers SET lease_holder = $2::text::uuid, lease_until = " + leaseEndSQL +
	" WHERE id = $1 AND (lease_until <= now() OR lease_holder = $3::text::uuid)"

// The SQLSTATE codes of a missing schema or table.
const (
	undefinedTable = "42P01"
	invalidSchema  = "3F000"
)

func takeLease(callerContext context.Context, server *ServerDatabase) (*Lease, error) {
	if err := callerContext.Err(); err != nil {
		return nil, fmt.Errorf("database: take: %w", err)
	}
	tryContext, release := context.WithTimeout(callerContext, TrySeconds*time.Second)
	defer release()

	connection, made, err := server.connect(tryContext)
	if err != nil {
		if errors.Is(err, errLocalSettings) {
			return nil, err
		}
		return nil, classify(callerContext, tryContext, made, err, true)
	}
	holder, sent, err := server.takeOver(tryContext, connection)
	if err != nil {
		closeErr := closeConnection(callerContext, connection)
		return nil, classify(callerContext, tryContext, nil, errors.Join(err, closeErr), false)
	}
	return startLease(callerContext, server, connection, holder, sent), nil
}

// takeOver makes the checks on the signed-in connection, in order, then the take. The errors it
// returns that are the package's own pass through classify unchanged.
func (server *ServerDatabase) takeOver(ctx context.Context, connection *pgx.Conn) (string, time.Time, error) {
	var tooPowerful bool
	if err := connection.QueryRow(ctx, tooPowerfulQuery).Scan(&tooPowerful); err != nil {
		return "", time.Time{}, err
	}
	if tooPowerful {
		return "", time.Time{}, ErrTooPowerful
	}
	var readOnly string
	if err := connection.QueryRow(ctx, "SHOW transaction_read_only").Scan(&readOnly); err != nil {
		return "", time.Time{}, err
	}
	if readOnly != "off" {
		return "", time.Time{}, ErrReadOnly
	}
	if err := checkSchemaVersion(ctx, connection); err != nil {
		return "", time.Time{}, err
	}

	holder := uuid.NewV4().String()
	previous := server.state.lastHolder
	server.state.lastHolder = &holder
	sent := time.Now()
	tag, err := connection.Exec(ctx, takeSQL, server.state.file.ServerID, holder, previous)
	if err != nil {
		return "", time.Time{}, err
	}
	if tag.RowsAffected() == 0 {
		var present bool
		if err := connection.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM hadv.servers WHERE id = $1)",
			server.state.file.ServerID).Scan(&present); err != nil {
			return "", time.Time{}, err
		}
		if !present {
			return "", time.Time{}, ErrNoServerRow
		}
		return "", time.Time{}, ErrLeaseHeld
	}
	return holder, sent, nil
}

// checkSchemaVersion reads the version from the one row whose column is a not-null integer; the
// type is read in the query, since a text column holding "abc" would not scan as a number.
func checkSchemaVersion(ctx context.Context, connection *pgx.Conn) error {
	rows, err := connection.Query(ctx,
		"SELECT CASE WHEN pg_typeof(version) = 'integer'::regtype THEN version::text END FROM hadv.schema_version LIMIT 2")
	if err != nil {
		return missingTable(err)
	}
	var versions []*string
	for rows.Next() {
		var text *string
		if err := rows.Scan(&text); err != nil {
			rows.Close()
			return err
		}
		versions = append(versions, text)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return missingTable(err)
	}
	if len(versions) != 1 || versions[0] == nil {
		return &SchemaVersionError{Missing: true}
	}
	found, err := strconv.ParseInt(*versions[0], 10, 32)
	if err != nil {
		return &SchemaVersionError{Missing: true}
	}
	if found != SchemaVersionMadeFor && found != SchemaVersionMadeFor+1 {
		return &SchemaVersionError{Found: int32(found)}
	}
	return nil
}

// missingTable reads a missing schema or table as a missing version; any other error stays.
func missingTable(err error) error {
	var refusal *pgconn.PgError
	if errors.As(err, &refusal) && (refusal.Code == undefinedTable || refusal.Code == invalidSchema) {
		return &SchemaVersionError{Missing: true}
	}
	return err
}

// closeConnection closes a connection the engine is done with, waiting at most a second for the
// database to take the goodbye, whatever has ended the context it is closed on behalf of.
func closeConnection(ctx context.Context, connection *pgx.Conn) error {
	closeContext, release := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer release()
	return connection.Close(closeContext)
}
