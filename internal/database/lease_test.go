// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The lease once taken: its renewals, read from the tests' record of every update to the row;
// its loss, 25 seconds after it sent its last take or renewal that succeeded, or at once when
// another run's holder is found;
// what it does once lost; and ending it. Each row waits on the clock, since the clock is what
// these lines are about.
package database_test

import (
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/database"
)

// takeBoard takes a new board's lease on the server, and returns the board, the Lease and the
// take's update.
func takeBoard(t *testing.T, server *postgres) (*board, *database.Lease, update) {
	t.Helper()
	created := server.newBoard(t)
	lease, err := take(t, created.file())
	expectTaken(t, lease, err, created)
	changes := created.updates(t)
	if len(changes) != 1 {
		t.Fatalf("the take made %d updates, want 1: %+v", len(changes), changes)
	}
	return created, lease, changes[0]
}

// waitForLost waits for the Lease to be lost, by the deadline, and returns when.
func waitForLost(t *testing.T, lease *database.Lease, deadline time.Time) time.Time {
	t.Helper()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-lease.Lost():
		return time.Now()
	case <-timer.C:
		t.Fatalf("the Lease was not lost by %v", deadline.Format(time.RFC3339Nano))
	}
	return time.Time{}
}

// expectHeld checks the Lease is not lost through the moment given. Called after that moment, it
// can tell only whether the Lease is lost now, not when, so it looks without waiting: a choice
// between a lost Lease and a timer already run out would otherwise go either way. A loss seen that
// late may be the test's own lateness, so under the race detector, which slows the test as much
// as the engine, it is logged rather than failed.
func expectHeld(t *testing.T, lease *database.Lease, through time.Time) {
	t.Helper()
	if !time.Now().Before(through) {
		select {
		case <-lease.Lost():
			if raceBuild {
				t.Logf("under the race detector, timing is not judged: the Lease was lost when the test first looked, %v after %v",
					time.Since(through), through.Format(time.RFC3339Nano))
				return
			}
			t.Fatalf("the Lease was lost when the test first looked, %v after %v", time.Since(through), through.Format(time.RFC3339Nano))
		default:
		}
		return
	}
	timer := time.NewTimer(time.Until(through))
	defer timer.Stop()
	select {
	case <-lease.Lost():
		t.Fatalf("the Lease was lost at %v, before %v", time.Now().Format(time.RFC3339Nano), through.Format(time.RFC3339Nano))
	case <-timer.C:
	}
}

// waitForNoBackend waits, by the deadline, until the server holds no connection of the login.
func waitForNoBackend(t *testing.T, created *board, deadline time.Time) time.Time {
	t.Helper()
	for {
		if len(created.backends(t)) == 0 {
			return time.Now()
		}
		if time.Now().After(deadline) {
			t.Fatalf("the server still held the login's connections %v at %v", created.backends(t), deadline.Format(time.RFC3339Nano))
		}
		pause(t, 50*time.Millisecond)
	}
}

// expectNoUpdateAfter checks no update to the row came after the count already seen, through the
// moment given.
func expectNoUpdateAfter(t *testing.T, created *board, seen int, through time.Time) {
	t.Helper()
	pause(t, time.Until(through))
	if changes := created.updates(t); len(changes) != seen {
		t.Fatalf("the row was updated after it should have been left alone: %+v", changes[seen:])
	}
}

func TestLease(t *testing.T) {
	t.Parallel()

	t.Run("While it is held, the Lease shall renew it every RenewSeconds, writing a lease end LeaseSeconds after the database's current time, only while the row's lease holder is its own, and waiting on the database at most TrySeconds.", func(t *testing.T) {
		t.Parallel()
		t.Run("two renewals, each 10 s after the one before, each 30 s after the database's time, the holder kept", func(t *testing.T) {
			t.Parallel()
			created, _, taken := takeBoard(t, sharedServer(t))
			changes := created.waitForUpdates(t, 3, taken.transactionStart.Add(2*renewEvery+patient(timingMargin+time.Second)))
			for index := 1; index < 3; index++ {
				expectWithin(t, "a renewal", changes[index].transactionStart,
					changes[index-1].transactionStart.Add(renewEvery-timingMargin), changes[index-1].transactionStart.Add(renewEvery+timingMargin))
				expectExactEnd(t, changes[index], leaseLength)
				if changes[index].newHolder != taken.newHolder {
					t.Fatalf("a renewal wrote the holder %s, want the take's %s", changes[index].newHolder, taken.newHolder)
				}
			}
		})
		t.Run("a renewal kept waiting by a locked row: the next is sent 10 s after it, the row still locked", func(t *testing.T) {
			t.Parallel()
			server := startPostgres(t, serverOptions{settings: []string{"log_statement = 'all'"}})
			created, _, taken := takeBoard(t, server)
			locked := time.Now()
			created.lockRow(t)
			sent := server.waitForUpdatesSent(t, created.login, locked, 2, taken.transactionStart.Add(2*renewEvery+patient(2*timingMargin)))
			expectWithin(t, "the renewal after the one kept waiting", sent[1], sent[0].Add(renewEvery-timingMargin), sent[0].Add(tryLimit+timingMargin))
		})
		t.Run("another run's holder written after the take: the renewal leaves the row as that run wrote it", func(t *testing.T) {
			t.Parallel()
			created, lease, taken := takeBoard(t, sharedServer(t))
			foreign := foreignHolder
			created.setRow(t, foreign, "now() + interval '1 hour'")
			written := created.row(t)
			waitForLost(t, lease, taken.transactionStart.Add(renewEvery+patient(timingMargin)))
			if after := created.row(t); after.holder != foreign || !after.until.Equal(written.until) {
				t.Fatalf("the row became %+v, want the other run's %+v", after, written)
			}
		})
	})

	t.Run("If a renewal fails for any reason but finding the row's lease holder is not its own, then the Lease shall try again at the next renewal, over a new connection when its connection failed.", func(t *testing.T) {
		t.Parallel()
		t.Run("its connection ended by the server: the next renewal comes over a new connection, the Lease held", func(t *testing.T) {
			t.Parallel()
			created, lease, taken := takeBoard(t, sharedServer(t))
			created.server.sql(t, superuser, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = "+quoteLiteral(created.login))
			changes := created.waitForUpdates(t, 2, taken.transactionStart.Add(2*renewEvery+patient(timingMargin)))
			if changes[1].backend == taken.backend {
				t.Fatalf("the renewal came over the ended connection, %s", taken.backend)
			}
			expectHeld(t, lease, taken.transactionStart.Add(leaseLength+timingMargin))
		})
		t.Run("a renewal kept waiting past 10 s, then the row freed: the next renewal lands, the Lease held past 30 s", func(t *testing.T) {
			t.Parallel()
			server := startPostgres(t, serverOptions{settings: []string{"log_statement = 'all'"}})
			created, lease, taken := takeBoard(t, server)
			locked := time.Now()
			lock := created.lockRow(t)
			sent := server.waitForUpdatesSent(t, created.login, locked, 2, taken.transactionStart.Add(2*renewEvery+patient(2*timingMargin)))
			lock.release(t)
			// When the renewal landed is read from the database's own record, not from when a
			// poll saw it: on a loaded machine one psql call can outlast the deadline. A
			// statement's transaction starts a little before the database logs the statement, so
			// a renewal is told from the one kept waiting by starting a second after that one's
			// log line, not by starting after its own.
			deadline := taken.transactionStart.Add(lossAfter)
			var landed time.Time
			for landed.IsZero() {
				for _, change := range created.updates(t)[1:] {
					if change.transactionStart.After(sent[0].Add(time.Second)) {
						landed = change.recorded
						break
					}
				}
				if landed.IsZero() {
					if time.Now().After(deadline.Add(patient(timingMargin))) {
						t.Fatalf("no renewal sent after the one kept waiting landed by %v", deadline.Format(time.RFC3339Nano))
					}
					pause(t, 100*time.Millisecond)
				}
			}
			expectWithin(t, "the renewal sent after the one kept waiting", landed, sent[1].Truncate(time.Millisecond), deadline.Add(timingMargin))
			expectHeld(t, lease, taken.transactionStart.Add(leaseLength+timingMargin))
		})
	})

	t.Run("When LossSeconds have passed since it sent its last take or renewal that succeeded, the Lease shall close the channel Lost returns.", func(t *testing.T) {
		t.Parallel()
		t.Run("the row locked straight after the take: lost 25 s after the take", func(t *testing.T) {
			t.Parallel()
			created, lease, taken := takeBoard(t, sharedServer(t))
			created.lockRow(t)
			lost := waitForLost(t, lease, taken.transactionStart.Add(lossAfter+patient(2*timingMargin)))
			expectWithin(t, "the loss", lost, taken.transactionStart.Add(lossAfter-timingMargin), taken.transactionStart.Add(lossAfter+timingMargin))
		})
		t.Run("the server stopped straight after the first renewal: lost 25 s after that renewal", func(t *testing.T) {
			t.Parallel()
			server := startPostgres(t, serverOptions{})
			created, lease, taken := takeBoard(t, server)
			changes := created.waitForUpdates(t, 2, taken.transactionStart.Add(renewEvery+patient(timingMargin+time.Second)))
			server.control(t, "stop", "-m", "fast", "-w", "-t", "60")
			renewed := changes[1].transactionStart
			lost := waitForLost(t, lease, renewed.Add(lossAfter+patient(2*timingMargin)))
			expectWithin(t, "the loss", lost, renewed.Add(lossAfter-timingMargin), renewed.Add(lossAfter+timingMargin))
		})
	})

	t.Run("When a renewal finds the row's lease holder is not its own, the Lease shall close the channel Lost returns at once.", func(t *testing.T) {
		t.Parallel()
		t.Run("another run's holder written straight after the take: lost by the first renewal", func(t *testing.T) {
			t.Parallel()
			created, lease, taken := takeBoard(t, sharedServer(t))
			created.setRow(t, foreignHolder, "now() + interval '1 hour'")
			lost := waitForLost(t, lease, taken.transactionStart.Add(renewEvery+patient(2*timingMargin)))
			expectWithin(t, "the loss", lost, taken.transactionStart.Add(renewEvery-timingMargin), taken.transactionStart.Add(renewEvery+timingMargin))
		})
	})

	t.Run("Once the channel Lost returns is closed, the Lease shall renew no more and close its connection.", func(t *testing.T) {
		t.Parallel()
		t.Run("lost to another run's holder: its connection closed at once, no update for the next 10 s", func(t *testing.T) {
			t.Parallel()
			created, lease, taken := takeBoard(t, sharedServer(t))
			created.setRow(t, foreignHolder, "now() + interval '1 hour'")
			lost := waitForLost(t, lease, taken.transactionStart.Add(renewEvery+patient(2*timingMargin)))
			closed := waitForNoBackend(t, created, lost.Add(patient(timingMargin)))
			expectWithin(t, "the connection's close", closed, lost, lost.Add(timingMargin))
			seen := len(created.updates(t))
			expectNoUpdateAfter(t, created, seen, lost.Add(renewEvery+timingMargin))
		})
		t.Run("lost to a stopped server, the server started again: no connection and no update for the next 10 s", func(t *testing.T) {
			t.Parallel()
			server := startPostgres(t, serverOptions{})
			created, lease, taken := takeBoard(t, server)
			server.control(t, "stop", "-m", "fast", "-w", "-t", "60")
			lost := waitForLost(t, lease, taken.transactionStart.Add(lossAfter+patient(2*timingMargin)))
			server.control(t, "start", "-w", "-t", "60", "-l", server.logPath)
			through := time.Now().Add(renewEvery + timingMargin)
			expectNoUpdateAfter(t, created, 1, through)
			if backends := created.backends(t); len(backends) != 0 {
				t.Fatalf("the lost Lease connected again after %v: %v", time.Since(lost), backends)
			}
		})
	})

	t.Run("EndLease shall set the row's lease end to the database's current time, only while the row's lease holder is its own, waiting on the database at most EndWaitMilliseconds.", func(t *testing.T) {
		t.Parallel()
		t.Run("ended: the lease end is the database's time, the holder kept", func(t *testing.T) {
			t.Parallel()
			created, lease, taken := takeBoard(t, sharedServer(t))
			lease.EndLease()
			changes := created.updates(t)
			last := changes[len(changes)-1]
			if len(changes) < 2 || last.newHolder != taken.newHolder {
				t.Fatalf("the end made no update keeping the holder %s: %+v", taken.newHolder, changes)
			}
			expectExactEnd(t, last, 0)
		})
		// Halfway between the renewal that fails over the ended connection and the next, which
		// would connect anew, so the end finds the Lease with no connection.
		t.Run("its connection ended by the server and the renewal after it failed: the lease end is the database's time, the holder kept", func(t *testing.T) {
			t.Parallel()
			created, lease, taken := takeBoard(t, sharedServer(t))
			created.server.sql(t, superuser, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = "+quoteLiteral(created.login))
			pause(t, time.Until(taken.transactionStart.Add(renewEvery*3/2)))
			lease.EndLease()
			changes := created.updates(t)
			if len(changes) != 2 || changes[1].newHolder != taken.newHolder {
				t.Fatalf("want the take and the end, keeping the holder %s: %+v", taken.newHolder, changes)
			}
			expectExactEnd(t, changes[1], 0)
		})
		t.Run("another run's holder written first: the row left as that run wrote it", func(t *testing.T) {
			t.Parallel()
			created, lease, _ := takeBoard(t, sharedServer(t))
			foreign := foreignHolder
			created.setRow(t, foreign, "now() + interval '1 hour'")
			written := created.row(t)
			lease.EndLease()
			if after := created.row(t); after.holder != foreign || !after.until.Equal(written.until) {
				t.Fatalf("the row became %+v, want the other run's %+v", after, written)
			}
		})
		t.Run("the row locked: EndLease returns within 1 s", func(t *testing.T) {
			t.Parallel()
			created, lease, _ := takeBoard(t, sharedServer(t))
			created.lockRow(t)
			called := time.Now()
			lease.EndLease()
			expectWithin(t, "EndLease's return", time.Now(), called, called.Add(endWait+timingMargin))
		})
		t.Run("the server stopped: EndLease returns within 1 s", func(t *testing.T) {
			t.Parallel()
			server := startPostgres(t, serverOptions{})
			_, lease, _ := takeBoard(t, server)
			server.control(t, "stop", "-m", "fast", "-w", "-t", "60")
			called := time.Now()
			lease.EndLease()
			expectWithin(t, "EndLease's return", time.Now(), called, called.Add(endWait+timingMargin))
		})
	})

	t.Run("EndLease shall stop the renewals and close the Lease's connection before it returns.", func(t *testing.T) {
		t.Parallel()
		t.Run("ended: its connection closed, no update for the next 10 s, the Lease not lost", func(t *testing.T) {
			t.Parallel()
			created, lease, _ := takeBoard(t, sharedServer(t))
			lease.EndLease()
			ended := time.Now()
			closed := waitForNoBackend(t, created, ended.Add(patient(timingMargin)))
			expectWithin(t, "the connection's close", closed, ended, ended.Add(timingMargin))
			expectNoUpdateAfter(t, created, len(created.updates(t)), ended.Add(renewEvery+timingMargin))
			select {
			case <-lease.Lost():
				t.Fatalf("EndLease closed the channel Lost returns")
			default:
			}
		})
	})

	t.Run("When the server's row's lease has ended, or its lease holder is the one this ServerDatabase last sent, Take shall write a new random lease holder and a lease end LeaseSeconds after the database's current time to that row, and return the Lease.", func(t *testing.T) {
		t.Parallel()
		t.Run("lost to a locked row, its end then pushed an hour on with the holder kept: the same ServerDatabase takes it, a new holder; another gets ErrLeaseHeld", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			made := serverDatabase(t, created.file())
			lease, err := takeWith(t, made)
			first := expectTaken(t, lease, err, created)
			lock := created.lockRow(t)
			waitForLost(t, lease, time.Now().Add(lossAfter+patient(2*timingMargin)))
			lock.release(t)
			created.setRow(t, first.holder, "now() + interval '1 hour'")
			other, err := take(t, created.file())
			expectTakeError(t, other, err, database.ErrLeaseHeld, created.password)
			again, err := takeWith(t, made)
			if second := expectTaken(t, again, err, created); second.holder == first.holder {
				t.Fatalf("the take kept the old holder %s", first.holder)
			}
		})
	})
}
