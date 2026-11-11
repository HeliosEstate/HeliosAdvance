// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The program's lines on its server's settings, driven from outside: which services it runs and on
// which ports, read from its row each time it takes the lease; a setting it cannot use; a service
// turned on without its key files; a server with every service off; and the lease ended at a stop
// after the database ended its connection, or at a refusal after the take. The settings are written
// with SQL as the board's owner, into the row's own columns; the lease is read from the tests'
// record of every update to the row.
package main_test

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// settingNames are the six columns, as the page names them.
var settingNames = []string{"telnet_on", "telnet_port", "ssh_on", "ssh_port", "telnets_on", "telnets_port"}

// portSettings are the three port columns and the range check each carries in the schema.
var portSettings = map[string]string{
	"telnet_port":  "telnet_port_range",
	"ssh_port":     "ssh_port_range",
	"telnets_port": "telnets_port_range",
}

// changeSettings writes the settings into the board's own row as its owner, with SQL, as a sysop's
// change made while the engine runs.
func (created *board) changeSettings(t *testing.T, settings services) {
	t.Helper()
	created.sqlAsOwner(t, fmt.Sprintf("UPDATE hadv.servers SET (%s) = (%s) WHERE id = %d", settingColumns, settings.values(), created.serverID))
}

// expectNamesSetting checks a refusal's reason names the column and none of the other five.
func expectNamesSetting(t *testing.T, reason, column string) {
	t.Helper()
	for _, name := range settingNames {
		if named := strings.Contains(reason, name); named != (name == column) {
			t.Fatalf("the reason %q names %s %v, want it to name %s alone of the six settings", reason, name, named, column)
		}
	}
}

// socketsOf returns the addresses a started line names, without their kinds, for a comparison with
// the program's own sockets.
func socketsOf(listeners []string) []string {
	var addresses []string
	for _, listener := range listeners {
		_, address, _ := strings.Cut(listener, "://")
		addresses = append(addresses, address)
	}
	return addresses
}

// expectSockets checks the program's own listening sockets, read from the system's table, are
// exactly the addresses given.
func expectSockets(t *testing.T, program *run, addresses []string) {
	t.Helper()
	sockets := listeningSockets(t, program.command.Process.Pid)
	if !slices.Equal(slices.Sorted(slices.Values(sockets)), slices.Sorted(slices.Values(addresses))) {
		t.Fatalf("the program listens at %q, want exactly %q", sockets, addresses)
	}
}

// endConnections ends every connection the board's login holds, from the database's side, and
// waits until the server shows none.
func (created *board) endConnections(t *testing.T) {
	t.Helper()
	// A connection is told by its process and its start time together: Windows hands an ended
	// process's ID to the next at once. The wait is for these connections alone, since a sound
	// engine may connect again as soon as its connection drops.
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
	deadline := time.Now().Add(testrun.Patient(testrun.HangBound))
	for created.server.sql(t, superuser, "SELECT count(*) FROM pg_stat_activity WHERE pid || '@' || backend_start IN ("+strings.Join(keys, ", ")+")") != "0" {
		if time.Now().After(deadline) {
			t.Fatalf("the login %s's ended connections were still there %v on", created.login, testrun.Patient(testrun.HangBound))
		}
		pause(t, 20*time.Millisecond)
	}
}

// expectEndedBy checks the run whose holder is given set the lease end before it exited: its last
// update is a later one than its take, sets the end to the database's time, keeps the holder, and
// was recorded before the exit. It returns that update.
func expectEndedBy(t *testing.T, created *board, holder string, exitedAt time.Time) update {
	t.Helper()
	var own []update
	for _, change := range created.updates(t) {
		if change.newHolder == holder {
			own = append(own, change)
		}
	}
	if len(own) < 2 || own[0].oldHolder == holder {
		t.Fatalf("the run holding %s made no update after its take: %+v", holder, own)
	}
	last := own[len(own)-1]
	if last.recorded.After(exitedAt) {
		t.Fatalf("the run's last update, %+v, was recorded after its exit at %v", last, exitedAt.Format(time.RFC3339Nano))
	}
	expectExactEnd(t, last, 0)
	return last
}

// heldSession is a psql session of the test's own that runs its statements and then sleeps,
// holding what they took, until release ends it.
type heldSession struct {
	command *exec.Cmd
	server  *postgres
	name    string
}

// startSession starts a session of the test's own in the database that runs the statements and
// then sleeps, and returns at once: its statements may wait on a lock.
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
	t.Cleanup(func() { session.release(t) })
	return session
}

// holdSession starts the session in the database and returns once its statements have run and it
// sleeps.
func (server *postgres) holdSession(t *testing.T, database, statements string) *heldSession {
	t.Helper()
	session := server.startSession(t, database, statements)
	server.awaitActivity(t, "application_name = "+quoteLiteral(session.name)+" AND wait_event = 'PgSleep'")
	return session
}

// awaitActivity waits, up to the hang bound, until the server's list of what its connections are
// doing shows one that meets the condition. The server announces no change in that list.
func (server *postgres) awaitActivity(t *testing.T, condition string) {
	t.Helper()
	deadline := time.Now().Add(testrun.Patient(testrun.HangBound))
	for server.sql(t, superuser, "SELECT count(*) > 0 FROM pg_stat_activity WHERE "+condition) != "t" {
		if time.Now().After(deadline) {
			t.Fatalf("no connection on the server met %q within %v", condition, testrun.Patient(testrun.HangBound))
		}
		pause(t, 20*time.Millisecond)
	}
}

// temporaryCause is one of the six refusals that pass on their own, made on the real database for
// a board of the row's own. stage makes it before the program starts; meet runs once the program
// has started and returns once the program has met it; fix removes it. A cause staged by a trigger
// that raises its code is planted: the real database gave the code, but not from a full disk or
// memory.
type temporaryCause struct {
	name   string
	reason string
	// logged is what the server logs for the take's error when the staging gave the code.
	logged string
	stage  func(t *testing.T) (created *board, meet, fix func(t *testing.T))
}

// expectLoginError waits, up to the hang bound, for the server's log to show an error of the
// login's holding the text: the staging gave the take the code it is there to give. A log without
// it cannot tell which code the engine met, so the row fails as one that cannot tell.
func (server *postgres) expectLoginError(t *testing.T, login, text string) {
	t.Helper()
	deadline := time.Now().Add(testrun.Patient(testrun.HangBound))
	for {
		for line := range strings.SplitSeq(server.serverLog(t), "\n") {
			match := tryPrefix.FindStringSubmatch(line)
			if match != nil && match[2] == login && match[3] == "ERROR" && strings.Contains(line, text) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("cannot tell: the server's log shows no error of %s's holding %q, so the staging may not have given its code:\n%s",
				login, text, server.serverLog(t))
		}
		pause(t, 100*time.Millisecond)
	}
}

// The four reasons the contract names, as the rows compare them: a row compares two waiting lines
// only when their causes are of different reasons.
const (
	reasonCancelled = "cancelled"
	reasonLock      = "lock not available"
	reasonClash     = "clash"
	reasonRanOut    = "ran out"
)

// raisingTrigger makes every update of the board's row raise the SQLSTATE, by a trigger run with
// its owner's rights that no one else may run, and returns a fix that drops it.
func (created *board) raisingTrigger(t *testing.T, code string) func(t *testing.T) {
	t.Helper()
	created.server.sql(t, created.database, `CREATE FUNCTION qa_audit.raise_code() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
			SET search_path = pg_catalog AS $$
		BEGIN
			RAISE EXCEPTION 'planted by the test: `+code+`' USING ERRCODE = '`+code+`';
		END $$`,
		"REVOKE EXECUTE ON FUNCTION qa_audit.raise_code() FROM PUBLIC",
		"CREATE TRIGGER qa_raise_code BEFORE UPDATE ON hadv.servers FOR EACH ROW EXECUTE FUNCTION qa_audit.raise_code()")
	return func(t *testing.T) {
		t.Helper()
		created.server.sql(t, created.database, "DROP TRIGGER qa_raise_code ON hadv.servers")
	}
}

// loginWaitsOnLock is the condition that the board's login has a connection waiting on a lock.
func (created *board) loginWaitsOnLock() string {
	return "usename = " + quoteLiteral(created.login) + " AND wait_event_type = 'Lock'"
}

// temporaryCauses are the six refusals, each staged as the QA probes found the real database gives
// it at a take.
func temporaryCauses() []temporaryCause {
	return []temporaryCause{
		{"a cancelled statement (57014), the take's write slowed 2 s by a trigger under a statement limit of 500 ms", reasonCancelled, "canceling statement due to statement timeout",
			func(t *testing.T) (*board, func(t *testing.T), func(t *testing.T)) {
				t.Helper()
				created := sharedServer(t).newBoard(t, telnetAt(0))
				created.server.sql(t, created.database, `CREATE FUNCTION qa_audit.slow() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
						SET search_path = pg_catalog AS $$
					BEGIN
						PERFORM pg_sleep(2);
						RETURN NEW;
					END $$`,
					"REVOKE EXECUTE ON FUNCTION qa_audit.slow() FROM PUBLIC",
					"CREATE TRIGGER qa_slow BEFORE UPDATE ON hadv.servers FOR EACH ROW EXECUTE FUNCTION qa_audit.slow()")
				created.server.sql(t, superuser, "ALTER ROLE "+created.login+" SET statement_timeout = '500ms'")
				return created, func(*testing.T) {}, func(t *testing.T) {
					t.Helper()
					// The limit goes with the trigger: left in place, any statement of a later
					// take that a loaded machine slows past 500 ms is cancelled too.
					created.server.sql(t, created.database, "DROP TRIGGER qa_slow ON hadv.servers")
					created.server.sql(t, superuser, "ALTER ROLE "+created.login+" RESET statement_timeout")
				}
			}},
		{"a lock not available (55P03), the row held under a lock limit of 100 ms", reasonLock, "canceling statement due to lock timeout",
			func(t *testing.T) (*board, func(t *testing.T), func(t *testing.T)) {
				t.Helper()
				created := sharedServer(t).newBoard(t, telnetAt(0))
				created.server.sql(t, superuser, "ALTER ROLE "+created.login+" SET lock_timeout = '100ms'")
				lock := created.lockRow(t)
				return created, func(*testing.T) {}, lock.release
			}},
		{"a clash (40001), the take at repeatable read meeting another transaction's update committed while it waits", reasonClash, "could not serialize access",
			func(t *testing.T) (*board, func(t *testing.T), func(t *testing.T)) {
				t.Helper()
				created := sharedServer(t).newBoard(t, telnetAt(0))
				created.server.sql(t, superuser, "ALTER ROLE "+created.login+" SET default_transaction_isolation = 'repeatable read'")
				key := strconv.FormatInt(nameCounter.Add(1), 10)
				gate := created.server.holdSession(t, created.database, "SELECT pg_advisory_lock("+key+")")
				other := created.server.startSession(t, created.database, fmt.Sprintf(
					"BEGIN; UPDATE hadv.servers SET lease_until = lease_until WHERE id = %d; SELECT pg_advisory_lock(%s); COMMIT", created.serverID, key))
				created.server.awaitActivity(t, "application_name = "+quoteLiteral(other.name)+" AND wait_event = 'advisory'")
				return created, func(t *testing.T) {
					t.Helper()
					created.server.awaitActivity(t, created.loginWaitsOnLock())
					gate.release(t)
				}, func(*testing.T) {}
			}},
		{"a clash (40P01), a deadlock the take's trigger closes, the login's deadlock check the sooner", reasonClash, "deadlock detected",
			func(t *testing.T) (*board, func(t *testing.T), func(t *testing.T)) {
				t.Helper()
				created := sharedServer(t).newBoard(t, telnetAt(0))
				first := strconv.FormatInt(nameCounter.Add(1), 10)
				second := strconv.FormatInt(nameCounter.Add(1), 10)
				created.server.sql(t, created.database, `CREATE FUNCTION qa_audit.two_locks() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
						SET search_path = pg_catalog AS $$
					BEGIN
						PERFORM pg_advisory_xact_lock(`+first+`);
						PERFORM pg_advisory_xact_lock(`+second+`);
						RETURN NEW;
					END $$`,
					"REVOKE EXECUTE ON FUNCTION qa_audit.two_locks() FROM PUBLIC",
					"CREATE TRIGGER qa_two_locks BEFORE UPDATE ON hadv.servers FOR EACH ROW EXECUTE FUNCTION qa_audit.two_locks()")
				created.server.sql(t, superuser, "ALTER ROLE "+created.login+" SET deadlock_timeout = '100ms'")
				gate := created.server.holdSession(t, created.database, "SELECT pg_advisory_lock("+first+")")
				return created, func(t *testing.T) {
						t.Helper()
						// The take's write holds the row and waits in the trigger on the first
						// lock.
						created.server.awaitActivity(t, created.loginWaitsOnLock())
						// The test's own transaction takes the second lock, then waits on the
						// row.
						other := created.server.startSession(t, created.database, fmt.Sprintf(
							"SET deadlock_timeout = '60s'; BEGIN; SELECT pg_advisory_xact_lock(%s); UPDATE hadv.servers SET lease_until = lease_until WHERE id = %d; COMMIT",
							second, created.serverID))
						created.server.awaitActivity(t, "application_name = "+quoteLiteral(other.name)+" AND wait_event_type = 'Lock'")
						// Freed, the first lock lets the trigger reach the second, which closes
						// the cycle; the login checks for a deadlock first.
						gate.release(t)
					}, func(t *testing.T) {
						t.Helper()
						created.server.sql(t, created.database, "DROP TRIGGER qa_two_locks ON hadv.servers")
					}
			}},
		{"disk full (53100), planted by a trigger that raises the code", reasonRanOut, "planted by the test: 53100",
			func(t *testing.T) (*board, func(t *testing.T), func(t *testing.T)) {
				t.Helper()
				created := sharedServer(t).newBoard(t, telnetAt(0))
				return created, func(*testing.T) {}, created.raisingTrigger(t, "53100")
			}},
		{"out of memory (53200), planted by a trigger that raises the code", reasonRanOut, "planted by the test: 53200",
			func(t *testing.T) (*board, func(t *testing.T), func(t *testing.T)) {
				t.Helper()
				created := sharedServer(t).newBoard(t, telnetAt(0))
				return created, func(*testing.T) {}, created.raisingTrigger(t, "53200")
			}},
	}
}

// release ends the session, freeing what it held.
func (session *heldSession) release(t *testing.T) {
	t.Helper()
	if session.command.Process == nil || session.command.ProcessState != nil {
		return
	}
	_, _ = session.server.trySQL(superuser, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = "+quoteLiteral(session.name))
	_ = session.command.Process.Kill()
	_ = session.command.Wait()
}

// blockEndWrites makes every update of the board's row that keeps its holder and sets a lease end
// no later than the database's time, an end write, wait on an advisory lock a session of the test's
// own holds, until the session is released: the database does not answer the end, while a take
// and a renewal, which write an end 30 seconds on, pass. The trigger runs with its owner's rights,
// and no one else may run its function.
func (created *board) blockEndWrites(t *testing.T) *heldSession {
	t.Helper()
	key := strconv.FormatInt(created.serverID+nameCounter.Add(1)*1000, 10)
	created.server.sql(t, created.database, `CREATE FUNCTION qa_audit.block_end() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
			SET search_path = pg_catalog AS $$
		BEGIN
			IF NEW.lease_holder IS NOT DISTINCT FROM OLD.lease_holder AND NEW.lease_until <= clock_timestamp() THEN
				PERFORM pg_advisory_xact_lock(`+key+`);
			END IF;
			RETURN NEW;
		END $$`,
		"REVOKE EXECUTE ON FUNCTION qa_audit.block_end() FROM PUBLIC",
		"CREATE TRIGGER qa_block_end BEFORE UPDATE ON hadv.servers FOR EACH ROW EXECUTE FUNCTION qa_audit.block_end()")
	return created.server.holdSession(t, created.database, "SELECT pg_advisory_lock("+key+")")
}

func TestSettingsProgram(t *testing.T) {
	t.Parallel()

	t.Run("When it takes its server's lease, the engine shall listen as its server's settings stand at that moment, until it next takes the lease.", func(t *testing.T) {
		t.Parallel()
		t.Run("Telnet on, SSH off; changed to SSH on at a port freed for it and Telnet off: after a renewal it still listens as at the take; the lease taken away and taken back: lease_lost, then a started line naming SSH alone at that port, its sockets exactly those", func(t *testing.T) {
			t.Parallel()
			key := makeKey(t, "ed25519", "")
			// A port freed for the program may be taken by a parallel row before the program
			// listens there, so a refusal naming the freed port as in use tries a fresh one.
			for try := range freedPortTries {
				created := sharedServer(t).newBoard(t, telnetAt(0))
				program := startWithFile(t, created.file().write(t), nil, hostKeyOption, key)
				first := program.listeners(t)
				telnetAlone(t, first)
				port, ipv4, ipv6 := heldPort(t)
				_ = ipv4.Close()
				_ = ipv6.Close()
				created.changeSettings(t, allOff().withSSH(portNumber(t, port)))
				changed := len(created.updates(t))
				created.waitForUpdates(t, changed+1, time.Now().Add(renewEvery+testrun.Patient(2*leaseMargin)))
				expectSockets(t, program, socketsOf(first))
				created.setRow(t, foreignHolder, "now()")
				program.expectLine(t, 1, "lease_lost", time.Now().Add(renewEvery+testrun.Patient(leaseMargin)))
				lineKey, value, _ := program.waitForLine(t, 2, time.Now().Add(retryEvery+tryLimit+testrun.Patient(leaseMargin)))
				if takenWhileFreed(lineKey+"="+value, port, []string{ipv4Loopback, ipv6Loopback}) && try < freedPortTries-1 {
					t.Logf("the freed port was taken before the program listened, %q: trying a fresh port", value)
					continue
				}
				if lineKey != "started" {
					t.Fatalf("the program's log's line 3 is %s=%s, want a started line", lineKey, value)
				}
				second := strings.Split(value, ",")
				telnet, ssh := kindsOf(t, second)
				if len(telnet) != 0 {
					t.Fatalf("the second started line names Telnet at %q, which the settings at that take turn off", telnet)
				}
				expectAddresses(t, ssh, net.JoinHostPort(ipv4Loopback, port), net.JoinHostPort(ipv6Loopback, port))
				expectSockets(t, program, socketsOf(second))
				for _, address := range ssh {
					expectSSHServed(t, address)
				}
				return
			}
		})
	})

	t.Run("If a setting it reads is empty, not of its kind, or a port outside 0 to 65535, then the engine shall write one `start_failed` line naming the setting, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		type badSetting struct {
			column string
			kind   string
			change string
		}
		var rows []badSetting
		for _, column := range settingNames {
			rows = append(rows, badSetting{column, "empty", "ALTER TABLE hadv.servers ALTER COLUMN " + column + " DROP NOT NULL; UPDATE hadv.servers SET " + column + " = NULL"})
		}
		for _, column := range []string{"telnet_on", "ssh_on", "telnets_on"} {
			rows = append(rows, badSetting{column, "text holding yes",
				"ALTER TABLE hadv.servers ALTER COLUMN " + column + " TYPE text USING " + column + "::text; UPDATE hadv.servers SET " + column + " = 'yes'"})
		}
		for column, check := range portSettings {
			rows = append(rows, badSetting{column, "text holding abc",
				"ALTER TABLE hadv.servers DROP CONSTRAINT " + check + "; ALTER TABLE hadv.servers ALTER COLUMN " + column + " TYPE text USING " + column + "::text; UPDATE hadv.servers SET " + column + " = 'abc'"})
			for _, value := range []string{"-1", "65536", "70000"} {
				rows = append(rows, badSetting{column, value,
					"ALTER TABLE hadv.servers DROP CONSTRAINT " + check + "; UPDATE hadv.servers SET " + column + " = " + value})
			}
		}
		for _, row := range rows {
			t.Run(row.column+" "+row.kind+", every service off: one start_failed line naming "+row.column+" alone of the six, and a non-zero exit", func(t *testing.T) {
				t.Parallel()
				created := sharedServer(t).newBoard(t, allOff())
				created.sqlAsOwner(t, row.change)
				expectNamesSetting(t, startOnBoard(t, created).expectRefusal(t), row.column)
			})
		}
		t.Run("the edges, every port 0 and then every port 65535, every service off: each starts", func(t *testing.T) {
			t.Parallel()
			for _, port := range []int{0, 65535} {
				settings := allOff()
				settings.telnetPort, settings.sshPort, settings.telnetsPort = port, port, port
				created := sharedServer(t).newBoard(t, settings)
				program := startOnBoard(t, created)
				value, _ := program.expectLine(t, 0, "started", time.Now().Add(startLimit))
				expectListensNowhere(t, value)
			}
		})
		t.Run("a bad setting met after a loss: started, telnet_port made 70000 and the lease taken away: lease_lost, then one start_failed line naming telnet_port, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t, telnetAt(0))
			program := startOnBoard(t, created)
			program.listening(t)
			created.sqlAsOwner(t, fmt.Sprintf("ALTER TABLE hadv.servers DROP CONSTRAINT telnet_port_range; UPDATE hadv.servers SET telnet_port = 70000 WHERE id = %d", created.serverID))
			created.setRow(t, foreignHolder, "now()")
			code, _ := program.exit(t, time.Now().Add(renewEvery+retryEvery+tryLimit+testrun.Patient(leaseMargin)))
			values := program.expectLog(t, "started", "lease_lost", startFailedKey)
			if code == 0 {
				t.Fatalf("the program refused to start again but exited with 0; its log:\n%s", program.text())
			}
			expectNamesSetting(t, values[2], "telnet_port")
		})
	})

	t.Run("If its server's `ssh_on` is true and the command line names no SSH host key file, or its `telnets_on` is true and the command line does not name both a TLS certificate file and its key file, then the engine shall write one `start_failed` line saying which, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("ssh_on with no host key, and telnets_on with no TLS files: two start_failed lines, two reasons; with the files given, each starts naming its kind", func(t *testing.T) {
			t.Parallel()
			noKey := startProgram(t, telnetAt(0).withSSH(0)).expectRefusal(t)
			noFiles := startProgram(t, telnetsOn()).expectRefusal(t)
			if noKey == noFiles {
				t.Fatalf("SSH without its key and Telnet over TLS without its files gave the same reason, %q", noKey)
			}
			expectSSHStarts(t)
			expectTLSStarts(t)
		})
	})

	t.Run("When it takes its server's lease and its server's settings turn no service on, the engine shall write one `started` line saying it listens nowhere.", func(t *testing.T) {
		t.Parallel()
		t.Run("the seeded row, every service off: one started line saying so, nothing listening; a stop: it exits, its log that line alone", func(t *testing.T) {
			t.Parallel()
			send := stopSignals()[0].prepare(t)
			program := startProgram(t, allOff())
			value, _ := program.expectLine(t, 0, "started", time.Now().Add(startLimit))
			expectListensNowhere(t, value)
			expectNotListening(t, program)
			_, sentBy := send(t, program)
			program.exit(t, sentBy.Add(endLeaseWait+testrun.Patient(margin)))
			program.expectLog(t, "started")
		})
	})

	t.Run("When it receives a stop signal while it holds its server's lease, after the database has ended the connection the lease was taken or last renewed over, the engine shall still set the lease end to the database's current time before it exits, unless the database does not answer.", func(t *testing.T) {
		t.Parallel()
		for _, signal := range stopSignals() {
			for _, renewals := range []int{0, 1} {
				t.Run(fmt.Sprintf("%s after %d renewals, the connection ended from the database's side: the lease end set to the database's time before the exit, over a new connection", signal.name, renewals), func(t *testing.T) {
					t.Parallel()
					send := signal.prepare(t)
					created := sharedServer(t).newBoard(t, telnetAt(0))
					program := startOnBoard(t, created)
					program.listening(t)
					changes := created.waitForUpdates(t, renewals+1, time.Now().Add(time.Duration(renewals)*renewEvery+testrun.Patient(2*leaseMargin)))
					last := changes[renewals]
					created.endConnections(t)
					// The stop must reach the engine before its next renewal could make a
					// connection of its own; a setup that ran past that cannot tell which made the
					// end.
					if due := last.transactionStart.Add(renewEvery - leaseMargin); time.Now().After(due) {
						t.Fatalf("cannot tell: the setup ended %v after the next renewal was due", time.Since(due))
					}
					_, sentBy := send(t, program)
					_, exitedAt := program.exit(t, sentBy.Add(endLeaseWait+testrun.Patient(margin)))
					after := created.updates(t)
					if len(after) != renewals+2 {
						t.Fatalf("the row had %d updates, want the take, %d renewals and the end: %+v", len(after), renewals, after)
					}
					end := expectEndedBy(t, created, last.newHolder, exitedAt)
					if end.backend == last.backend {
						t.Fatalf("the end was written over the connection the database ended, %s", end.backend)
					}
				})
			}
		}
		t.Run("the edge, the database stopped once the connection ended: the program exits within 1 s, the row as it was once the database is back", func(t *testing.T) {
			t.Parallel()
			send := stopSignals()[0].prepare(t)
			server := startPostgres(t, serverOptions{})
			created := server.newBoard(t, telnetAt(0))
			program := startOnBoard(t, created)
			program.listening(t)
			before := created.row(t)
			created.endConnections(t)
			server.control(t, "stop", "-m", "immediate", "-w", "-t", "60")
			from, sentBy := send(t, program)
			_, exitedAt := program.exit(t, sentBy.Add(endLeaseWait+testrun.Patient(leaseMargin)))
			expectWithin(t, "the exit", exitedAt, from, sentBy.Add(endLeaseWait+margin))
			server.control(t, "start", "-w", "-t", "60", "-l", server.logPath)
			if after := created.row(t); after.holder != before.holder || !after.until.Equal(before.until) {
				t.Fatalf("the row became %+v, want it as the run left it, %+v", after, before)
			}
		})
	})

	t.Run("If it writes a `start_failed` line after it has taken its server's lease, then the engine shall set the lease end to the database's current time before it exits, unless the database does not answer.", func(t *testing.T) {
		t.Parallel()
		refusals := []struct {
			name     string
			settings func(t *testing.T) (refused, control services)
			options  func(t *testing.T) []string
		}{
			{"ssh_on with no host key file", func(*testing.T) (services, services) {
				return telnetAt(0).withSSH(0), telnetAt(0).withSSH(0)
			}, nil},
			{"telnets_on with no TLS files", func(*testing.T) (services, services) {
				return telnetsOn(), telnetsOn()
			}, nil},
			{"Telnet on at a port the test holds at both addresses", func(t *testing.T) (services, services) {
				t.Helper()
				port, _, _ := heldPort(t)
				return telnetAt(portNumber(t, port)), telnetAt(0)
			}, func(*testing.T) []string { return nil }},
			{"Telnet on at a port the system picks and SSH at a port the test holds, so the refusal comes after Telnet listens", func(t *testing.T) (services, services) {
				t.Helper()
				port, _, _ := heldPort(t)
				return telnetAt(0).withSSH(portNumber(t, port)), telnetAt(0).withSSH(0)
			}, func(t *testing.T) []string { t.Helper(); return []string{hostKeyOption, makeKey(t, "ed25519", "")} }},
		}
		for _, refusal := range refusals {
			t.Run(refusal.name+": one start_failed line, a non-zero exit, and the lease end set to the database's time before it; with what the refusal lacked, it starts", func(t *testing.T) {
				t.Parallel()
				refused, control := refusal.settings(t)
				var options []string
				if refusal.options != nil {
					options = refusal.options(t)
				}
				created := sharedServer(t).newBoard(t, refused)
				program := startWithFile(t, created.file().write(t), nil, options...)
				code, exitedAt := program.exit(t, time.Now().Add(startLimit))
				program.expectLog(t, startFailedKey)
				if code == 0 {
					t.Fatalf("the program refused to start but exited with 0; its log:\n%s", program.text())
				}
				changes := created.updates(t)
				if len(changes) == 0 {
					t.Fatalf("the program refused without taking the lease, so the row cannot tell: its log:\n%s", program.text())
				}
				expectEndedBy(t, created, changes[0].newHolder, exitedAt)
				// The control, in the same row: what the refusal lacked, given.
				controlOptions := options
				switch {
				case control.sshOn && len(options) == 0:
					controlOptions = []string{hostKeyOption, makeKey(t, "ed25519", "")}
				case control.telnetsOn:
					controlOptions = goodTLSFiles(t, tlsP256).options()
				}
				listeners := startProgram(t, control, controlOptions...).listeners(t)
				kinds := map[string]int{}
				for _, listener := range listeners {
					scheme, _, _ := strings.Cut(listener, "://")
					kinds[scheme]++
				}
				for _, scheme := range []string{schemeTelnet, schemeSSH, schemeTelnets} {
					if control.turnsOn(scheme) && kinds[scheme] != 2 {
						t.Fatalf("with what the refusal lacked, the started line names %q, want %s at both addresses", listeners, scheme)
					}
				}
			})
		}
		t.Run("after a loss: started, telnet_port made a port the test holds and the lease taken away: lease_lost, then start_failed, and the lease end set by the second take's holder before the exit", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t, telnetAt(0))
			program := startOnBoard(t, created)
			program.listening(t)
			first := expectHolder(t, created.row(t))
			port, _, _ := heldPort(t)
			created.changeSettings(t, telnetAt(portNumber(t, port)))
			created.setRow(t, foreignHolder, "now()")
			code, exitedAt := program.exit(t, time.Now().Add(renewEvery+retryEvery+tryLimit+testrun.Patient(leaseMargin)))
			program.expectLog(t, "started", "lease_lost", startFailedKey)
			if code == 0 {
				t.Fatalf("the program refused to start again but exited with 0; its log:\n%s", program.text())
			}
			second := ""
			for _, change := range created.updates(t) {
				if change.newHolder != first && change.newHolder != foreignHolder {
					second = change.newHolder
					break
				}
			}
			if second == "" {
				t.Fatalf("no second take after the loss: %+v", created.updates(t))
			}
			expectEndedBy(t, created, second, exitedAt)
		})
		t.Run("the edge, the end not answered: ssh_on with no host key, the row's end writes held waiting: one start_failed line, a non-zero exit within 1 s of the take, and the row as the take left it; with a host key, it starts naming SSH", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t, telnetAt(0).withSSH(0))
			hold := created.blockEndWrites(t)
			program := startOnBoard(t, created)
			code, exitedAt := program.exit(t, time.Now().Add(startLimit))
			program.expectLog(t, startFailedKey)
			if code == 0 {
				t.Fatalf("the program refused to start but exited with 0; its log:\n%s", program.text())
			}
			changes := created.updates(t)
			if len(changes) != 1 {
				t.Fatalf("the row had %d updates, want the take alone, its end held: %+v", len(changes), changes)
			}
			expectWithin(t, "the exit", exitedAt, changes[0].recorded, changes[0].recorded.Add(endLeaseWait+leaseMargin))
			if row := created.row(t); row.holder != changes[0].newHolder || !row.until.Equal(changes[0].newUntil) {
				t.Fatalf("the row became %+v, want it as the take left it, %+v", row, changes[0])
			}
			hold.release(t)
			expectSSHStarts(t)
		})
	})
}
