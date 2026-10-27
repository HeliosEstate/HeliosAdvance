// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package database

import (
	"context"
	"errors"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The contract's operations hand their work to the unexported functions below, so the contract
// builds before the package is built and the build never needs to change the contract. Each
// placeholder here is replaced by the issue that builds it, and fails until then, so nothing calls
// it yet.

type serverDatabaseState struct {
	config *pgconn.Config
}

type leaseState struct {
	connection *pgx.Conn
	lostSignal chan struct{}
}

// errNotBuilt is what a placeholder returns until its issue builds it.
var errNotBuilt = errors.New("database: not built yet")

func schemaVersionText(failure *SchemaVersionError) string {
	if failure == nil || failure.Missing {
		return "database: no schema version was found"
	}
	return "database: the schema version " + strconv.FormatInt(int64(failure.Found), 10) +
		" is not one this engine accepts"
}

func readConnectionFile(_ string) (ConnectionFile, error) {
	return ConnectionFile{}, errNotBuilt
}

func newServerDatabase(_ ConnectionFile) *ServerDatabase {
	return &ServerDatabase{}
}

func (server *ServerDatabase) take(_ context.Context) (*Lease, error) {
	if server == nil || server.state.config == nil {
		return nil, errNotBuilt
	}
	return nil, errNotBuilt
}

func (lease *Lease) lost() <-chan struct{} {
	if lease == nil || lease.state.lostSignal == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return lease.state.lostSignal
}

func (lease *Lease) endLease() {
	if lease == nil || lease.state.connection == nil {
		return
	}
	lease.state.connection = nil
}
