// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The contract's lines of the per-server settings, against real servers the tests make: the six
// refusals that pass on their own, each made on the real database; a setting Take cannot use; the
// Lease's settings; and EndLease after the database ended the Lease's connection, connecting again
// only as Take does.
package database_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/database"
)

// The six settings' columns, as the contract names them.
var settingColumns = []string{"telnet_on", "telnet_port", "ssh_on", "ssh_port", "telnets_on", "telnets_port"}

// portChecks are the port columns and the range check each carries in the schema.
var portChecks = map[string]string{
	"telnet_port":  "telnet_port_range",
	"ssh_port":     "ssh_port_range",
	"telnets_port": "telnets_port_range",
}

// heldSession is a psql session of the test's own that runs its statements and then sleeps,
// holding what they took, until release ends it.
type heldSession struct {
	command *exec.Cmd
	server  *postgres
	name    string
}

// startSession starts the session and returns at once: its statements may wait on a lock.
func (server *postgres) startSession(t *testing.T, database, statements string) *heldSession {
	t.Helper()
	name := uniqueName("qa_hold")
	path, err := exec.LookPath("psql")
	if err != nil {
		t.Fatalf("PostgreSQL's psql is not on the PATH, so the oracle cannot run: %v", err)
	}
	command := exec.CommandContext(context.WithoutCancel(t.Context()), path, "-X", "-q", "-h", databaseHost,
		"-p", strconv.Itoa(server.port), "-U", superuser, "-d", database, "-c", statements+"; SELECT pg_sleep(600);")
	command.Env = append(server.superuserEnvironment(), "PGAPPNAME="+name)
	if err := command.Start(); err != nil {
		t.Fatalf("starting the psql that holds a session: %v", err)
	}
	session := &heldSession{command: command, server: server, name: name}
	t.Cleanup(func() { session.release() })
	return session
}

// holdSession starts the session and returns once its statements have run and it sleeps.
func (server *postgres) holdSession(t *testing.T, database, statements string) *heldSession {
	t.Helper()
	session := server.startSession(t, database, statements)
	server.awaitActivity(t, "application_name = "+quoteLiteral(session.name)+" AND wait_event = 'PgSleep'")
	return session
}

// release ends the session, freeing what it held.
func (session *heldSession) release() {
	if session.command.Process == nil || session.command.ProcessState != nil {
		return
	}
	_, _ = session.server.trySQL(superuser, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = "+quoteLiteral(session.name))
	_ = session.command.Process.Kill()
	_ = session.command.Wait()
}

// awaitActivity waits until the server's list of what its connections are doing shows one that
// meets the condition: the server announces no change in that list, so the wait reads it again
// at a short interval, up to a bound that only a hung row reaches.
func (server *postgres) awaitActivity(t *testing.T, condition string) {
	t.Helper()
	deadline := time.Now().Add(takeLimit)
	for server.sql(t, superuser, "SELECT count(*) > 0 FROM pg_stat_activity WHERE "+condition) != "t" {
		if time.Now().After(deadline) {
			t.Fatalf("no connection on the server met %q within %v", condition, takeLimit)
		}
		pause(t, 20*time.Millisecond)
	}
}

// ownTrigger adds a trigger before every update of hadv.servers, its function run with its
// owner's rights and no one else's to run, and returns a fix that drops it.
func (created *board) ownTrigger(t *testing.T, name, body string) func(t *testing.T) {
	t.Helper()
	created.server.sql(t, created.database, `CREATE FUNCTION qa_audit.`+name+`() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
			SET search_path = pg_catalog AS $$
		BEGIN
			`+body+`
			RETURN NEW;
		END $$`,
		"REVOKE EXECUTE ON FUNCTION qa_audit."+name+"() FROM PUBLIC",
		"CREATE TRIGGER qa_"+name+" BEFORE UPDATE ON hadv.servers FOR EACH ROW EXECUTE FUNCTION qa_audit."+name+"()")
	return func(t *testing.T) {
		t.Helper()
		created.server.sql(t, created.database, "DROP TRIGGER qa_"+name+" ON hadv.servers")
	}
}

// loginWaitsOnLock is the condition that the board's login has a connection waiting on a lock.
func (created *board) loginWaitsOnLock() string {
	return "usename = " + quoteLiteral(created.login) + " AND wait_event_type = 'Lock'"
}

// temporaryCause is one of the six refusals that pass on their own, made on the real database for
// a board of the row's own. stage makes it before Take is called, and returns meet, which runs
// while Take waits and returns once Take has met the cause. A cause made by a trigger that raises
// its code is planted: the real database gave the code, but not from a full disk or memory.
type temporaryCause struct {
	name   string
	code   string
	reason database.TemporaryReason
	// logged is what the server logs for the take's error when the staging gave the code.
	logged string
	stage  func(t *testing.T) (created *board, meet func(t *testing.T))
}

// expectLoginError waits, up to the take's bound, for the server's log to show an error of the
// login's holding the text: the staging gave the take the code it is there to give. A log without
// it cannot tell which code Take met, so the row fails as one that cannot tell.
func (server *postgres) expectLoginError(t *testing.T, login, text string) {
	t.Helper()
	deadline := time.Now().Add(takeLimit)
	for {
		for line := range strings.SplitSeq(server.log(t), "\n") {
			match := logPrefix.FindStringSubmatch(line)
			if match != nil && match[2] == login && strings.HasPrefix(line[len(match[0]):], "ERROR:") && strings.Contains(line, text) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("cannot tell: the server's log shows no error of %s's holding %q, so the staging may not have given its code:\n%s",
				login, text, server.log(t))
		}
		pause(t, 100*time.Millisecond)
	}
}

// temporaryCauses are the six, each staged as the QA probes found the real database gives it at a
// take.
func temporaryCauses() []temporaryCause {
	none := func(*testing.T) {}
	return []temporaryCause{
		{"the take's write slowed 2 s by a trigger under a statement limit of 500 ms", "57014", database.TemporaryCancelled, "canceling statement due to statement timeout",
			func(t *testing.T) (*board, func(t *testing.T)) {
				t.Helper()
				created := sharedServer(t).newBoard(t)
				created.ownTrigger(t, "slow", "PERFORM pg_sleep(2);")
				created.server.sql(t, superuser, "ALTER ROLE "+created.login+" SET statement_timeout = '500ms'")
				return created, none
			}},
		{"the row held under a lock limit of 100 ms", "55P03", database.TemporaryLockNotAvailable, "canceling statement due to lock timeout",
			func(t *testing.T) (*board, func(t *testing.T)) {
				t.Helper()
				created := sharedServer(t).newBoard(t)
				created.server.sql(t, superuser, "ALTER ROLE "+created.login+" SET lock_timeout = '100ms'")
				created.lockRow(t)
				return created, none
			}},
		{"the take at repeatable read meeting another transaction's update committed while it waits", "40001", database.TemporaryClash, "could not serialize access",
			func(t *testing.T) (*board, func(t *testing.T)) {
				t.Helper()
				created := sharedServer(t).newBoard(t)
				created.server.sql(t, superuser, "ALTER ROLE "+created.login+" SET default_transaction_isolation = 'repeatable read'")
				key := strconv.FormatInt(counter.Add(1), 10)
				gate := created.server.holdSession(t, created.database, "SELECT pg_advisory_lock("+key+")")
				other := created.server.startSession(t, created.database, fmt.Sprintf(
					"BEGIN; UPDATE hadv.servers SET lease_until = lease_until WHERE id = %d; SELECT pg_advisory_lock(%s); COMMIT", created.serverID, key))
				created.server.awaitActivity(t, "application_name = "+quoteLiteral(other.name)+" AND wait_event = 'advisory'")
				return created, func(t *testing.T) {
					t.Helper()
					created.server.awaitActivity(t, created.loginWaitsOnLock())
					gate.release()
				}
			}},
		{"a deadlock the take's trigger closes, the login's deadlock check the sooner", "40P01", database.TemporaryClash, "deadlock detected",
			func(t *testing.T) (*board, func(t *testing.T)) {
				t.Helper()
				created := sharedServer(t).newBoard(t)
				first := strconv.FormatInt(counter.Add(1), 10)
				second := strconv.FormatInt(counter.Add(1), 10)
				created.ownTrigger(t, "two_locks", "PERFORM pg_advisory_xact_lock("+first+"); PERFORM pg_advisory_xact_lock("+second+");")
				created.server.sql(t, superuser, "ALTER ROLE "+created.login+" SET deadlock_timeout = '100ms'")
				gate := created.server.holdSession(t, created.database, "SELECT pg_advisory_lock("+first+")")
				return created, func(t *testing.T) {
					t.Helper()
					// The take's write holds the row and waits in the trigger on the first lock.
					created.server.awaitActivity(t, created.loginWaitsOnLock())
					// The test's own transaction takes the second lock, then waits on the row.
					other := created.server.startSession(t, created.database, fmt.Sprintf(
						"SET deadlock_timeout = '60s'; BEGIN; SELECT pg_advisory_xact_lock(%s); UPDATE hadv.servers SET lease_until = lease_until WHERE id = %d; COMMIT",
						second, created.serverID))
					created.server.awaitActivity(t, "application_name = "+quoteLiteral(other.name)+" AND wait_event_type = 'Lock'")
					// Freed, the first lock lets the trigger reach the second, which closes
					// the cycle; the login checks for a deadlock first.
					gate.release()
				}
			}},
		{"planted by a trigger that raises the code", "53100", database.TemporaryRanOut, "planted by the test: 53100",
			func(t *testing.T) (*board, func(t *testing.T)) {
				t.Helper()
				created := sharedServer(t).newBoard(t)
				created.ownTrigger(t, "raise_code", "RAISE EXCEPTION 'planted by the test: 53100' USING ERRCODE = '53100';")
				return created, none
			}},
		{"planted by a trigger that raises the code", "53200", database.TemporaryRanOut, "planted by the test: 53200",
			func(t *testing.T) (*board, func(t *testing.T)) {
				t.Helper()
				created := sharedServer(t).newBoard(t)
				created.ownTrigger(t, "raise_code", "RAISE EXCEPTION 'planted by the test: 53200' USING ERRCODE = '53200';")
				return created, none
			}},
	}
}

// takeResult is what a Take run on a goroutine of its own returned.
type takeResult struct {
	lease *database.Lease
	err   error
}

// takeAside runs Take on a goroutine of its own, so the row can act while it waits, and returns
// the channel its result comes back on. A Lease it returns is ended when the row ends.
func takeAside(t *testing.T, made *database.ServerDatabase) <-chan takeResult {
	t.Helper()
	result := make(chan takeResult, 1)
	ctx, cancel := context.WithTimeout(t.Context(), takeLimit)
	go func() {
		defer cancel()
		lease, err := made.Take(ctx)
		result <- takeResult{lease, err}
	}()
	return result
}

// awaitTake waits for the result of takeAside, bounded beyond Take's own limit.
func awaitTake(t *testing.T, result <-chan takeResult) takeResult {
	t.Helper()
	timer := time.NewTimer(takeLimit + timingMargin)
	defer timer.Stop()
	select {
	case got := <-result:
		if got.lease != nil {
			t.Cleanup(got.lease.EndLease)
		}
		return got
	case <-timer.C:
		t.Fatalf("Take had not returned %v on", takeLimit+timingMargin)
	}
	return takeResult{}
}

// expectUnchanged checks the row's holder and end are as before and the tests' record holds no
// update with a holder in it: the rows that use it start from a row never held, and the test's own
// updates keep it so.
func expectUnchanged(t *testing.T, created *board, before lease) {
	t.Helper()
	if after := created.row(t); after.holder != before.holder || !after.until.Equal(before.until) {
		t.Fatalf("the row changed from %+v to %+v", before, after)
	}
	for _, change := range created.updates(t) {
		if change.newHolder != "" {
			t.Fatalf("Take wrote the row: %+v", change)
		}
	}
}

// badSetting is one way a setting cannot be used, made by the owner on a board of the row's own.
type badSetting struct {
	column string
	kind   string
	change string
}

// badSettings are each column empty, each switch a text holding yes, each port a text holding abc,
// and each port at -1, 65536 and 70000, its range check dropped.
func badSettings() []badSetting {
	var rows []badSetting
	for _, column := range settingColumns {
		rows = append(rows, badSetting{column, "empty", "ALTER TABLE hadv.servers ALTER COLUMN " + column + " DROP NOT NULL; UPDATE hadv.servers SET " + column + " = NULL"})
	}
	for _, column := range []string{"telnet_on", "ssh_on", "telnets_on"} {
		rows = append(rows, badSetting{column, "a text holding yes",
			"ALTER TABLE hadv.servers ALTER COLUMN " + column + " TYPE text USING " + column + "::text; UPDATE hadv.servers SET " + column + " = 'yes'"})
	}
	for column, check := range portChecks {
		rows = append(rows, badSetting{column, "a text holding abc",
			"ALTER TABLE hadv.servers DROP CONSTRAINT " + check + "; ALTER TABLE hadv.servers ALTER COLUMN " + column + " TYPE text USING " + column + "::text; UPDATE hadv.servers SET " + column + " = 'abc'"})
		for _, value := range []string{"-1", "65536", "70000"} {
			rows = append(rows, badSetting{column, value, "ALTER TABLE hadv.servers DROP CONSTRAINT " + check + "; UPDATE hadv.servers SET " + column + " = " + value})
		}
	}
	return rows
}

// expectSettingError checks Take failed with a *SettingError naming the column and nothing else.
func expectSettingError(t *testing.T, lease *database.Lease, err error, created *board, column string) {
	t.Helper()
	expectTakeError(t, lease, err, database.ErrSetting, created.password)
	var found *database.SettingError
	if !errors.As(err, &found) || found.Setting != column {
		t.Fatalf("the error is %#v, want a *SettingError naming %s", err, column)
	}
}

// setSettings writes the six settings into the board's row as its owner.
func (created *board) setSettings(t *testing.T, settings database.Settings) {
	t.Helper()
	created.sqlAsOwner(t, fmt.Sprintf("UPDATE hadv.servers SET (%s) = (%t, %d, %t, %d, %t, %d) WHERE id = %d",
		strings.Join(settingColumns, ", "), settings.TelnetOn, settings.TelnetPort, settings.SSHOn, settings.SSHPort,
		settings.TelnetsOn, settings.TelnetsPort, created.serverID))
}

func TestSettings(t *testing.T) {
	t.Parallel()

	t.Run("If the database answers with SQLSTATE 57014, 55P03, 40001, 40P01, 53100 or 53200, then Take shall return a *TemporaryError naming which: TemporaryCancelled for 57014, TemporaryLockNotAvailable for 55P03, TemporaryClash for 40001 and 40P01, TemporaryRanOut for 53100 and 53200; and change nothing.", func(t *testing.T) {
		t.Parallel()
		for _, cause := range temporaryCauses() {
			t.Run(cause.code+", "+cause.name+": a *TemporaryError naming its reason, matching ErrTemporary alone, the row unchanged", func(t *testing.T) {
				t.Parallel()
				created, meet := cause.stage(t)
				before := created.row(t)
				result := takeAside(t, serverDatabase(t, created.file()))
				meet(t)
				got := awaitTake(t, result)
				created.server.expectLoginError(t, created.login, cause.logged)
				expectTakeError(t, got.lease, got.err, database.ErrTemporary, created.password)
				var found *database.TemporaryError
				if !errors.As(got.err, &found) || found.Reason != cause.reason {
					t.Fatalf("the error is %#v, want a *TemporaryError naming %d", got.err, cause.reason)
				}
				expectUnchanged(t, created, before)
			})
		}
	})

	t.Run("If the database refuses for any reason the lines above do not name, then Take shall return ErrRefused.", func(t *testing.T) {
		t.Parallel()
		// A code beside the six, of the same class: configuration_limit_exceeded stays a stop,
		// and a clash is only the two codes the contract names.
		for _, code := range []string{"53400", "40002"} {
			t.Run(code+", planted by a trigger that raises it: ErrRefused, matching no *TemporaryError, the row unchanged", func(t *testing.T) {
				t.Parallel()
				created := sharedServer(t).newBoard(t)
				created.ownTrigger(t, "raise_code", "RAISE EXCEPTION 'planted by the test: "+code+"' USING ERRCODE = '"+code+"';")
				before := created.row(t)
				lease, err := take(t, created.file())
				created.server.expectLoginError(t, created.login, "planted by the test: "+code)
				expectTakeError(t, lease, err, database.ErrRefused, created.password)
				var temporary *database.TemporaryError
				if errors.As(err, &temporary) {
					t.Fatalf("the error is %#v, a *TemporaryError, for %s", err, code)
				}
				expectUnchanged(t, created, before)
			})
		}
	})

	t.Run("If one of the six settings in the server's row is empty, not of its kind, or a port outside 0 to 65535, then Take shall return a *SettingError naming that column, and change nothing.", func(t *testing.T) {
		t.Parallel()
		for _, row := range badSettings() {
			t.Run(row.column+" "+row.kind+": a *SettingError naming "+row.column+", the row unchanged", func(t *testing.T) {
				t.Parallel()
				created := sharedServer(t).newBoard(t)
				created.sqlAsOwner(t, row.change)
				before := created.row(t)
				lease, err := take(t, created.file())
				expectSettingError(t, lease, err, created, row.column)
				expectUnchanged(t, created, before)
			})
		}
		t.Run("the edges, every port 0 and every port 65535: each taken, its Lease's Settings naming those ports", func(t *testing.T) {
			t.Parallel()
			for _, port := range []uint16{0, 65535} {
				created := sharedServer(t).newBoard(t)
				want := database.Settings{TelnetPort: port, SSHPort: port, TelnetsPort: port}
				created.setSettings(t, want)
				lease, err := take(t, created.file())
				expectTaken(t, lease, err, created)
				if got := lease.Settings(); got != want {
					t.Fatalf("the Lease's Settings are %+v, want the row's %+v", got, want)
				}
			}
		})
		t.Run("a held lease and telnet_port 70000: ErrLeaseHeld; that lease ended, the same Take: a *SettingError naming telnet_port", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			created.sqlAsOwner(t, "ALTER TABLE hadv.servers DROP CONSTRAINT telnet_port_range; UPDATE hadv.servers SET telnet_port = 70000")
			created.setRow(t, foreignHolder, "now() + interval '1 hour'")
			made := serverDatabase(t, created.file())
			lease, err := takeWith(t, made)
			expectTakeError(t, lease, err, database.ErrLeaseHeld, created.password)
			created.setRow(t, foreignHolder, "now()")
			lease, err = takeWith(t, made)
			expectSettingError(t, lease, err, created, "telnet_port")
		})
		t.Run("version 7 and telnet_port 70000: a *SchemaVersionError; the version made 2: a *SettingError naming telnet_port", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			created.sqlAsOwner(t, "UPDATE hadv.schema_version SET version = 7; ALTER TABLE hadv.servers DROP CONSTRAINT telnet_port_range; UPDATE hadv.servers SET telnet_port = 70000")
			lease, err := take(t, created.file())
			expectTakeError(t, lease, err, database.ErrSchemaVersion, created.password)
			created.sqlAsOwner(t, "UPDATE hadv.schema_version SET version = 2")
			lease, err = take(t, created.file())
			expectSettingError(t, lease, err, created, "telnet_port")
		})
	})

	t.Run("Take shall return a Lease whose Settings are the six settings the server's row holds, read in the same Take.", func(t *testing.T) {
		t.Parallel()
		t.Run("six values, the switches mixed and the ports 0, 1 and 65535: Settings the same; the row changed after the take: Settings unchanged; ended and taken again: the new values", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			first := database.Settings{TelnetOn: true, TelnetPort: 0, SSHOn: false, SSHPort: 1, TelnetsOn: true, TelnetsPort: 65535}
			created.setSettings(t, first)
			made := serverDatabase(t, created.file())
			lease, err := takeWith(t, made)
			expectTaken(t, lease, err, created)
			if got := lease.Settings(); got != first {
				t.Fatalf("the Lease's Settings are %+v, want the row's %+v", got, first)
			}
			// telnet_on and telnets_on differ here, so a Lease that swaps them is told.
			second := database.Settings{TelnetOn: false, TelnetPort: 2323, SSHOn: true, SSHPort: 0, TelnetsOn: true, TelnetsPort: 992}
			created.setSettings(t, second)
			if got := lease.Settings(); got != first {
				t.Fatalf("after the row changed the Lease's Settings are %+v, want those of its take, %+v", got, first)
			}
			lease.EndLease()
			again, err := takeWith(t, made)
			expectTaken(t, again, err, created)
			if got := again.Settings(); got != second {
				t.Fatalf("the second Lease's Settings are %+v, want the row's %+v", got, second)
			}
		})
	})

	t.Run("When the database has ended the Lease's connection, EndLease shall still set the lease end within the same EndWaitMilliseconds, connecting as Take does: over TLS 1.2 or 1.3, only to a certificate that passes Take's check, and only by SCRAM-SHA-256 with channel binding.", func(t *testing.T) {
		t.Parallel()
		t.Run("taken, every connection of the login ended and gone: EndLease within 1 s sets the end to the database's time over a new connection, signed in by SCRAM-SHA-256 over TLS", func(t *testing.T) {
			t.Parallel()
			server := startPostgres(t, serverOptions{})
			created, lease, taken := takeBoard(t, server)
			// From before the end, so a sign-in made as soon as the connection dropped counts too.
			since := time.Now()
			endConnections(t, created)
			expectBeforeRenewal(t, taken)
			called := time.Now()
			lease.EndLease()
			expectWithin(t, "EndLease's return", time.Now(), called, called.Add(endWait+timingMargin))
			changes := created.updates(t)
			if len(changes) != 2 || changes[1].newHolder != taken.newHolder {
				t.Fatalf("want the take and the end, keeping the holder %s: %+v", taken.newHolder, changes)
			}
			expectExactEnd(t, changes[1], 0)
			if changes[1].backend == taken.backend {
				t.Fatalf("the end was written over the connection the database ended, %s", taken.backend)
			}
			log, _ := server.logSince(since, created.login)
			if !strings.Contains(log, `connection authenticated: identity="`+created.login+`" method=scram-sha-256`) ||
				!strings.Contains(log, "connection authorized: user="+created.login+" ") || !strings.Contains(log, "SSL enabled") {
				t.Fatalf("the server's log since the connection ended shows no SCRAM sign-in over TLS by %s:\n%s", created.login, log)
			}
		})
		// Each of Take's refusals of a connection, made on the server after the take, as Take's own
		// rows make them. A trusted sign-in is logged by the server before any client can refuse
		// it, so that row reads only that nothing was written.
		changes := []struct {
			name    string
			trusted bool
			change  func(t *testing.T, server *postgres, created *board)
		}{
			{"the certificate reloaded to one from another authority", false, func(t *testing.T, server *postgres, _ *board) {
				t.Helper()
				server.authority = newAuthority(t)
				server.reloadCertificate(t, serverCertificate{})
			}},
			{"the certificate reloaded to one naming db.invalid alone", false, func(t *testing.T, server *postgres, _ *board) {
				t.Helper()
				server.reloadCertificate(t, serverCertificate{names: []string{"db.invalid"}})
			}},
			{"the certificate reloaded to one naming 127.0.0.2 alone", false, func(t *testing.T, server *postgres, _ *board) {
				t.Helper()
				server.reloadCertificate(t, serverCertificate{addresses: []net.IP{net.ParseIP("127.0.0.2")}})
			}},
			{"the certificate reloaded to one that expired an hour ago", false, func(t *testing.T, server *postgres, _ *board) {
				t.Helper()
				server.reloadCertificate(t, serverCertificate{notAfter: time.Now().Add(-time.Hour)})
			}},
			{"the login's sign-in rule made password", false, func(t *testing.T, server *postgres, created *board) {
				t.Helper()
				server.signInRule(t, created.login, "password")
			}},
			{"the login's password stored as md5 and its sign-in rule made md5", false, func(t *testing.T, server *postgres, created *board) {
				t.Helper()
				server.sql(t, superuser, "SET password_encryption = 'md5'; ALTER ROLE "+created.login+" PASSWORD "+quoteLiteral(created.password))
				server.signInRule(t, created.login, "md5")
			}},
			{"the login's sign-in rule made trust", true, func(t *testing.T, server *postgres, created *board) {
				t.Helper()
				server.signInRule(t, created.login, "trust")
			}},
			{"TLS turned off and the login's rule made one without TLS", false, func(t *testing.T, server *postgres, created *board) {
				t.Helper()
				server.addSettings(t, "ssl = off")
				server.signInRule(t, created.login, "scram-sha-256-any")
			}},
			{"TLS limited to 1.1 and the login's rule made one with or without TLS", false, func(t *testing.T, server *postgres, created *board) {
				t.Helper()
				server.addSettings(t, "ssl_min_protocol_version = 'TLSv1'", "ssl_max_protocol_version = 'TLSv1.1'", "ssl_ciphers = 'DEFAULT:@SECLEVEL=0'")
				server.signInRule(t, created.login, "scram-sha-256-any")
			}},
		}
		t.Run("the server stopped once every connection of the login ended, a listener that accepts and never answers in its place: EndLease tries it and returns within 1 s", func(t *testing.T) {
			t.Parallel()
			server := startPostgres(t, serverOptions{})
			created, lease, taken := takeBoard(t, server)
			endConnections(t, created)
			server.control(t, "stop", "-m", "immediate", "-w", "-t", "60")
			silent, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", net.JoinHostPort(databaseHost, strconv.Itoa(server.port)))
			if err != nil {
				t.Fatalf("cannot tell: the stopped server's port could not be taken for the silent listener: %v", err)
			}
			held := make(chan net.Conn, 16)
			go func() {
				for {
					connection, err := silent.Accept()
					if err != nil {
						close(held)
						return
					}
					held <- connection
				}
			}()
			t.Cleanup(func() {
				_ = silent.Close()
				for connection := range held {
					_ = connection.Close()
				}
			})
			expectBeforeRenewal(t, taken)
			called := time.Now()
			lease.EndLease()
			expectWithin(t, "EndLease's return", time.Now(), called, called.Add(endWait+timingMargin))
			select {
			case connection := <-held:
				held <- connection
			default:
				t.Fatalf("EndLease tried no new connection, so the row cannot tell its bound")
			}
		})
		t.Run("the server stopped once every connection of the login ended, a fake with a certificate from its authority in its place offering SCRAM-SHA-256 without channel binding: EndLease within 1 s tries it and does not answer the offer", func(t *testing.T) {
			t.Parallel()
			server := startPostgres(t, serverOptions{})
			created, lease, taken := takeBoard(t, server)
			endConnections(t, created)
			server.control(t, "stop", "-m", "immediate", "-w", "-t", "60")
			listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", net.JoinHostPort(databaseHost, strconv.Itoa(server.port)))
			if err != nil {
				t.Fatalf("cannot tell: the stopped server's port could not be taken for the fake: %v", err)
			}
			received := make(chan string, 1)
			startFakeOn(t, listener, server.authority, false, func(t *testing.T, connection *fakeConnection) {
				t.Helper()
				connection.send(t, 'R', saslBody("SCRAM-SHA-256"))
				kind, _, err := connection.readMessage(time.Now().Add(tryLimit))
				select {
				case received <- fmt.Sprintf("%q %v", kind, err):
				default:
				}
			})
			expectBeforeRenewal(t, taken)
			called := time.Now()
			lease.EndLease()
			expectWithin(t, "EndLease's return", time.Now(), called, called.Add(endWait+timingMargin))
			timer := time.NewTimer(tryLimit + timingMargin)
			defer timer.Stop()
			select {
			case got := <-received:
				if strings.HasPrefix(got, `'p'`) {
					t.Fatalf("EndLease answered the offer without channel binding: %s", got)
				}
			case <-timer.C:
				t.Fatalf("EndLease's new connection never reached the fake's offer, so the row cannot tell")
			}
		})
		for _, entry := range changes {
			t.Run(entry.name+", then every connection of the login ended: EndLease within 1 s tries the server, signs in nowhere, and writes nothing", func(t *testing.T) {
				t.Parallel()
				server := startPostgres(t, serverOptions{})
				created, lease, taken := takeBoard(t, server)
				entry.change(t, server, created)
				endConnections(t, created)
				expectBeforeRenewal(t, taken)
				// After the end: the test's own connections log their arrival too.
				since := time.Now()
				called := time.Now()
				lease.EndLease()
				expectWithin(t, "EndLease's return", time.Now(), called, called.Add(endWait+timingMargin))
				log, _ := server.logSince(since, created.login)
				if !strings.Contains(log, "connection received:") {
					t.Fatalf("the server's log since the connection ended shows no connection tried:\n%s", log)
				}
				if !entry.trusted && (strings.Contains(log, "connection authenticated: identity=\""+created.login+"\"") ||
					strings.Contains(log, "connection authorized: user="+created.login+" ")) {
					t.Fatalf("the server's log since the change shows %s signed in:\n%s", created.login, log)
				}
				if count := len(created.updates(t)); count != 1 {
					t.Fatalf("the row had %d updates, want the take alone", count)
				}
			})
		}
	})
}

// reloadCertificate gives the server a new certificate from its authority and has it read it.
func (server *postgres) reloadCertificate(t *testing.T, wanted serverCertificate) {
	t.Helper()
	if err := server.writeCertificate(wanted); err != nil {
		t.Fatalf("writing the new certificate: %v", err)
	}
	server.sql(t, superuser, "SELECT pg_reload_conf()")
}

// addSettings adds lines to the server's settings and writes them; the next reload reads them.
func (server *postgres) addSettings(t *testing.T, lines ...string) {
	t.Helper()
	server.mutex.Lock()
	server.settings = append(server.settings, lines...)
	err := server.writeSettings()
	server.mutex.Unlock()
	if err != nil {
		t.Fatalf("writing the settings: %v", err)
	}
}

// expectBeforeRenewal fails the row as one that cannot tell when its setup ran so long that the
// Lease's first renewal, which connects anew when its connection failed, may come before EndLease:
// the new connection would then be the renewal's.
func expectBeforeRenewal(t *testing.T, taken update) {
	t.Helper()
	if due := taken.transactionStart.Add(renewEvery - timingMargin); time.Now().After(due) {
		t.Fatalf("cannot tell: the setup ended %v after the first renewal could start", time.Since(due))
	}
}

// endConnections ends every connection the board's login holds, from the database's side, and
// waits until the server shows none.
func endConnections(t *testing.T, created *board) {
	t.Helper()
	// A connection is told by its process and its start time together: Windows hands an ended
	// process's ID to the next at once. The wait is for these connections alone, since a sound
	// Lease may connect again as soon as its connection drops.
	ended := created.server.sql(t, superuser, "SELECT pid || '@' || backend_start, pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = "+
		quoteLiteral(created.login))
	var keys []string
	for line := range strings.SplitSeq(ended, "\n") {
		if key, _, found := strings.Cut(line, "|"); found {
			keys = append(keys, quoteLiteral(key))
		}
	}
	if len(keys) == 0 {
		t.Fatalf("the login %s had no connection to end", created.login)
	}
	deadline := time.Now().Add(takeLimit)
	for created.server.sql(t, superuser, "SELECT count(*) FROM pg_stat_activity WHERE pid || '@' || backend_start IN ("+strings.Join(keys, ", ")+")") != "0" {
		if time.Now().After(deadline) {
			t.Fatalf("the login %s's ended connections were still there %v on", created.login, takeLimit)
		}
		pause(t, 20*time.Millisecond)
	}
}
