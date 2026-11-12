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

// leaseEndSQL takes its time from the database, so a run whose clock is wrong cannot hold a lease
// too long.
var leaseEndSQL = "now() + interval '" + strconv.Itoa(LeaseSeconds) + " seconds'"

// takeSQL writes the new holder only while the lease has ended or the holder is the one last
// sent. A holder that is NULL matches nothing, which is right for a run that has sent none.
var takeSQL = "UPDATE hadv.servers SET lease_holder = $2::text::uuid, lease_until = " + leaseEndSQL +
	" WHERE id = $1 AND (lease_until <= now() OR lease_holder = $3::text::uuid)"

// A missing schema, table or version column reads as a missing version, since in each no version
// is there.
const (
	undefinedTable  = "42P01"
	invalidSchema   = "3F000"
	undefinedColumn = "42703"
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
	holder, sent, settings, err := server.takeOver(tryContext, connection)
	if err != nil {
		closeErr := closeConnection(callerContext, connection)
		return nil, classify(callerContext, tryContext, made, errors.Join(err, closeErr), false)
	}
	return startLease(callerContext, server, connection, holder, sent, settings), nil
}

// takeOver makes the checks on the signed-in connection, in order, then the take. The errors it
// returns that are the package's own pass through classify unchanged. The write and the read of
// the settings are one transaction, so the settings are those the lease was written with and a
// refused setting rolls the write back.
func (server *ServerDatabase) takeOver(ctx context.Context, connection *pgx.Conn) (string, time.Time, Settings, error) {
	var none Settings
	var tooPowerful bool
	if err := connection.QueryRow(ctx, tooPowerfulQuery).Scan(&tooPowerful); err != nil {
		return "", time.Time{}, none, err
	}
	if tooPowerful {
		return "", time.Time{}, none, ErrTooPowerful
	}
	var readOnly string
	if err := connection.QueryRow(ctx, "SHOW transaction_read_only").Scan(&readOnly); err != nil {
		return "", time.Time{}, none, err
	}
	if readOnly != "off" {
		return "", time.Time{}, none, ErrReadOnly
	}
	if err := checkSchemaVersion(ctx, connection); err != nil {
		return "", time.Time{}, none, err
	}

	holder := uuid.NewV4().String()
	previous := server.state.lastHolder
	server.state.lastHolder = &holder
	// Before the transaction begins: the database's now() inside it is the transaction's start,
	// so the loss clock must start no later than that.
	sent := time.Now()
	var settings Settings
	err := pgx.BeginFunc(ctx, connection, func(transaction pgx.Tx) error {
		var err error
		settings, err = server.writeTake(ctx, transaction, holder, previous)
		return err
	})
	if err != nil {
		return "", time.Time{}, none, err
	}
	return holder, sent, settings, nil
}

// writeTake writes the new holder and reads the settings back from the row it wrote.
func (server *ServerDatabase) writeTake(ctx context.Context, transaction pgx.Tx, holder string, previous *string) (Settings, error) {
	var texts [settingCount]*string
	err := transaction.QueryRow(ctx, takeSQL+" RETURNING "+settingsSQL,
		server.state.file.ServerID, holder, previous).
		Scan(&texts[0], &texts[1], &texts[2], &texts[3], &texts[4], &texts[5])
	if errors.Is(err, pgx.ErrNoRows) {
		var present bool
		if err := transaction.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM hadv.servers WHERE id = $1)",
			server.state.file.ServerID).Scan(&present); err != nil {
			return Settings{}, err
		}
		if !present {
			return Settings{}, ErrNoServerRow
		}
		return Settings{}, ErrLeaseHeld
	}
	if err != nil {
		return Settings{}, err
	}
	return parseSettings(texts)
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

// missingTable reads a missing schema, table or column as a missing version; any other error
// stays.
func missingTable(err error) error {
	var refusal *pgconn.PgError
	if errors.As(err, &refusal) &&
		(refusal.Code == undefinedTable || refusal.Code == invalidSchema || refusal.Code == undefinedColumn) {
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
