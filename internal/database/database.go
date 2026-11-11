// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package database

import (
	"context"
	"crypto/x509"
	"strconv"
	"sync"

	"github.com/jackc/pgx/v5"
)

// The contract's operations hand their work to the unexported functions in this package's other
// files, so the contract builds before the package is built and the build never needs to change
// the contract.

type serverDatabaseState struct {
	file Connection
	// config and roots are made at the first Take and kept, since parsing writes and reads a file.
	config *pgx.ConnConfig
	roots  *x509.CertPool
	// lastHolder is the lease holder last sent, whether or not the reply came back.
	lastHolder *string
}

type leaseState struct {
	server     *ServerDatabase
	holder     string
	connection *pgx.Conn
	lostSignal chan struct{}
	cancel     context.CancelFunc
	stopped    chan struct{}
	endOnce    sync.Once
	// settings is a placeholder until the build reads them with the lease.
	settings Settings
}

func settingText(failure *SettingError) string {
	if failure == nil {
		return ErrSetting.Error()
	}
	return "database: the setting " + failure.Setting + " is empty, not of its kind, or a port outside 0 to 65535"
}

func (lease *Lease) settings() Settings {
	return lease.state.settings
}

func schemaVersionText(failure *SchemaVersionError) string {
	if failure == nil || failure.Missing {
		return "database: no schema version was found"
	}
	return "database: the schema version " + strconv.FormatInt(int64(failure.Found), 10) +
		" is not one this engine accepts"
}

func newServerDatabase(file Connection) *ServerDatabase {
	return &ServerDatabase{state: serverDatabaseState{file: file}}
}

func (server *ServerDatabase) take(ctx context.Context) (*Lease, error) {
	return takeLease(ctx, server)
}

func (lease *Lease) lost() <-chan struct{} {
	return lease.state.lostSignal
}

func (lease *Lease) endLease() {
	lease.state.endOnce.Do(lease.end)
}
