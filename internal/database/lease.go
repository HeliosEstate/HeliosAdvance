// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package database

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// Both write only while the row's holder is this Lease's own, so a run that lost the lease cannot
// take it back by renewing or by ending it.
var (
	renewSQL = "UPDATE hadv.servers SET lease_until = " + leaseEndSQL + " WHERE id = $1 AND lease_holder = $2::text::uuid"
	endSQL   = "UPDATE hadv.servers SET lease_until = now() WHERE id = $1 AND lease_holder = $2::text::uuid"
)

// startLease hands the taken connection to a goroutine that owns it until the lease is lost or
// ended. The Lease has a context of its own, keeping the caller's values but not its end: a stop
// cancels the program's, and the program ends the lease itself.
func startLease(callerContext context.Context, server *ServerDatabase, connection *pgx.Conn, holder string, sent time.Time) *Lease {
	ctx, cancel := context.WithCancel(context.WithoutCancel(callerContext))
	lease := &Lease{state: leaseState{server: server, holder: holder, connection: connection,
		lostSignal: make(chan struct{}), cancel: cancel, stopped: make(chan struct{})}}
	go lease.run(ctx, sent)
	return lease
}

// run renews every RenewSeconds and watches the clock from the last send that succeeded. The
// clock is the engine's monotonic one, so a change of the wall clock cannot extend a lease.
func (lease *Lease) run(ctx context.Context, lastSent time.Time) {
	state := &lease.state
	defer close(state.stopped)
	ticker := time.NewTicker(RenewSeconds * time.Second)
	defer ticker.Stop()
	expiry := time.NewTimer(time.Until(lastSent.Add(LeaseSeconds * time.Second)))
	defer expiry.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-expiry.C:
			lease.lose(ctx)
			return
		case <-ticker.C:
			sent, found := lease.renew(ctx, lastSent.Add(LeaseSeconds*time.Second))
			switch {
			case ctx.Err() != nil:
				return
			case found == notOwn:
				lease.lose(ctx)
				return
			case found == renewed:
				lastSent = sent
				expiry.Reset(time.Until(lastSent.Add(LeaseSeconds * time.Second)))
			case !time.Now().Before(lastSent.Add(LeaseSeconds * time.Second)):
				lease.lose(ctx)
				return
			}
		}
	}
}

type renewal int

const (
	failed renewal = iota
	renewed
	notOwn
)

// renew makes one renewal, waiting on the database until TrySeconds on or the lease's end,
// whichever comes first, and connects anew when the connection is closed.
func (lease *Lease) renew(ctx context.Context, end time.Time) (time.Time, renewal) {
	state := &lease.state
	deadline := time.Now().Add(TrySeconds * time.Second)
	if end.Before(deadline) {
		deadline = end
	}
	attemptContext, release := context.WithDeadline(ctx, deadline)
	defer release()
	if state.connection == nil {
		connection, _, err := state.server.connect(attemptContext)
		if err != nil {
			return time.Time{}, failed
		}
		state.connection = connection
	}
	sent := time.Now()
	tag, err := state.connection.Exec(attemptContext, renewSQL, state.server.state.file.ServerID, state.holder)
	if err != nil {
		if state.connection.IsClosed() {
			state.connection = nil
		}
		return time.Time{}, failed
	}
	if tag.RowsAffected() == 0 {
		return time.Time{}, notOwn
	}
	return sent, renewed
}

// lose closes the channel Lost returns first, so the program is told at once, then the
// connection.
func (lease *Lease) lose(ctx context.Context) {
	state := &lease.state
	close(state.lostSignal)
	if state.connection != nil {
		closeConnection(ctx, state.connection)
		state.connection = nil
	}
}

// end stops the goroutine, then sets the lease end to the database's time over the Lease's
// connection, or a new one when it has none, all within EndWaitMilliseconds, and closes the
// connection. Lost stays open: a stop is not a loss.
func (lease *Lease) end() {
	state := &lease.state
	endContext, release := context.WithTimeout(context.Background(), EndWaitMilliseconds*time.Millisecond)
	defer release()
	state.cancel()
	<-state.stopped
	if state.connection != nil && state.connection.IsClosed() {
		state.connection = nil
	}
	if state.connection == nil {
		connection, _, err := state.server.connect(endContext)
		if err != nil {
			return
		}
		state.connection = connection
	}
	state.connection.Exec(endContext, endSQL, state.server.state.file.ServerID, state.holder)
	state.connection.Close(endContext)
	state.connection = nil
}
