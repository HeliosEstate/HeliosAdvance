// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The program and its database, driven from outside: the connection file on the command line,
// signing in, the checks made before it listens, waiting for the database or the lease, taking,
// renewing and losing the lease, and ending it at a stop. The program is the built one; the
// database is a real PostgreSQL the tests make; the lease is read from the tests' record of every
// update to the program's row.
package main_test

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// The page's numbers, written here so a changed constant in the engine cannot move a test with
// it.
const (
	retryEvery    = 10 * time.Second
	tryLimit      = 10 * time.Second
	renewEvery    = 10 * time.Second
	leaseLength   = 30 * time.Second
	lossAfter     = 25 * time.Second
	endLeaseWait  = time.Second
	waitLineLimit = 30 * time.Second
	holderPattern = `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
)

// leaseMargin is how late an event may come past its moment on every runner. To be measured at
// CI's own load on each runner before the summary; this is the draft.
const leaseMargin = 2 * time.Second

// foreignHolder is another run's lease holder, which the tests write into a row.
const foreignHolder = "11111111-2222-4333-8444-555555555555"

// noFileKey names, among the reasons a row compares, the one for no connection file at all.
const noFileKey = "no connection file"

// startWithFile starts the program with the connection file at path, the options given and
// PostgreSQL's own variables taken out of its environment, the extra entries added.
func startWithFile(t *testing.T, path string, extra []string, options ...string) *run {
	t.Helper()
	command := exec.CommandContext(t.Context(), programPath, append([]string{databaseOption, path}, options...)...)
	command.Env = cleanEnvironment(extra...)
	return startCommand(t, command)
}

// startOnBoard starts the program on the board's own row, at a Telnet port the system picks.
func startOnBoard(t *testing.T, created *board) *run {
	t.Helper()
	return startWithFile(t, created.file().write(t), nil, portOption, "0")
}

// freedPort finds a port free at 127.0.0.1 and ::1 and frees it again, for a program to be
// started on; while the program waits, nothing should listen there.
func freedPort(t *testing.T) string {
	t.Helper()
	port, ipv4, ipv6 := heldPort(t)
	_ = ipv4.Close()
	_ = ipv6.Close()
	return port
}

// expectNotListening checks nothing listens at the port at either address, and on Linux that
// the system's table shows the program holding no listening socket.
func expectNotListening(t *testing.T, program *run, port string) {
	t.Helper()
	expectRefused(t, net.JoinHostPort(ipv4Loopback, port))
	expectRefused(t, net.JoinHostPort(ipv6Loopback, port))
	if runtime.GOOS == "linux" {
		if sockets := listeningSockets(t, program.command.Process.Pid); len(sockets) != 0 {
			t.Fatalf("the program listens at %q while it may not", sockets)
		}
	}
}

// noFileReason is the start_failed reason the program gives when it is started with no
// connection file, a Telnet port the system picks and nothing else.
func noFileReason(t *testing.T) string {
	t.Helper()
	return startBare(t, portOption, "0").expectRefusal(t)
}

// expectDifferent checks the reasons are pairwise different, each naming its own case.
func expectDifferent(t *testing.T, reasons map[string]string) {
	t.Helper()
	seen := map[string]string{}
	for name, reason := range reasons {
		if other, found := seen[reason]; found {
			t.Fatalf("the reasons for %q and %q are both %q, where each must say which", name, other, reason)
		}
		seen[reason] = name
	}
}

// expectNoPassword checks the local log holds no part of any login's password.
func expectNoPassword(t *testing.T, program *run) {
	t.Helper()
	if strings.Contains(program.text(), passwordCanary) {
		t.Fatalf("the local log holds a login's password:\n%s", program.text())
	}
}

// expectHolder checks the row's holder is a UUID, and returns it.
func expectHolder(t *testing.T, found lease) string {
	t.Helper()
	if !regexp.MustCompile(holderPattern).MatchString(found.holder) {
		t.Fatalf("the row's holder is %q, not a UUID", found.holder)
	}
	return found.holder
}

// expectExactEnd checks an update wrote a lease end the given time after the database's: at
// least its transaction's start plus that, and at most the moment it was recorded plus that.
func expectExactEnd(t *testing.T, change update, after time.Duration) {
	t.Helper()
	if change.newUntil.Before(change.transactionStart.Add(after)) || change.newUntil.After(change.recorded.Add(after)) {
		t.Fatalf("the update wrote a lease end of %v, want %v after the database's time, between %v and %v",
			change.newUntil.Format(time.RFC3339Nano), after, change.transactionStart.Add(after).Format(time.RFC3339Nano),
			change.recorded.Add(after).Format(time.RFC3339Nano))
	}
}

// expectEngineWithin checks a moment came inside a window anchored on an earlier event of the
// engine's own, such as the try or the renewal before it. Under the race detector that earlier
// event may itself have come late while the engine's ticker brings the next one on time, so a
// short gap there is right: neither bound is judged, and the moment is only logged.
func expectEngineWithin(t *testing.T, what string, moment, notBefore, notAfter time.Time) {
	t.Helper()
	if testrun.Race {
		t.Logf("under the race detector, timing is not judged: %s came %v into its window of %v, which opens from an earlier event of the engine's",
			what, moment.Sub(notBefore), notAfter.Sub(notBefore))
		return
	}
	expectWithin(t, what, moment, notBefore, notAfter)
}

// waitingCaller dials the program, answers its negotiation and reads the greeting and prompt, so
// the call waits on its name for 60 seconds.
func waitingCaller(t *testing.T, address string) caller {
	t.Helper()
	call := expectServed(t, address)
	call.send(t, answers)
	call.readExactly(t, []byte(greeting+prompt), time.Now().Add(testrun.Patient(margin)))
	return call
}

// waitForStartedAgain waits for the program's started line at index, by the deadline, and
// returns when it came.
func waitForStarted(t *testing.T, program *run, index int, deadline time.Time) time.Time {
	t.Helper()
	_, read := program.expectLine(t, index, "started", deadline)
	return read
}

func TestDatabaseProgram(t *testing.T) {
	t.Parallel()

	t.Run("If it starts without a connection file on the command line, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("with -port 0 and no connection file: one start_failed line, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			noFileReason(t)
		})
		t.Run("with no option at all: one start_failed line saying the same, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			want := noFileReason(t)
			if reason := startBare(t).expectRefusal(t); reason != want {
				t.Fatalf("with no option the reason was %q, want the one for no connection file, %q", reason, want)
			}
		})
	})

	t.Run("If the connection file is missing, unreadable, over 64 KiB, not in the connection file's format, or missing a field or holding one the format does not name, then the engine shall write one `start_failed` line saying which, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("missing, unreadable, 70 KiB, not JSON, without port, with sslmode: six start_failed lines, six reasons, none the password", func(t *testing.T) {
			t.Parallel()
			valid := sharedBoard.file()
			text := func(change func(map[string]any)) string {
				fields := map[string]any{"server_id": valid.ServerID, "host": valid.Host, "port": valid.Port, "database": valid.Database,
					"login": valid.Login, "password": valid.Password, "ca_certificate": valid.CACertificate}
				change(fields)
				parts := []string{}
				for name, value := range fields {
					encoded, err := jsonValue(value)
					if err != nil {
						t.Fatalf("writing %s: %v", name, err)
					}
					parts = append(parts, strconv.Quote(name)+": "+encoded)
				}
				return "{" + strings.Join(parts, ", ") + "}"
			}
			unreadable := writeConnectionFile(t, text(func(map[string]any) {}))
			keepFromReading(t, unreadable)
			large := text(func(map[string]any) {})
			files := map[string]string{
				"missing":         unreadable + ".missing",
				"unreadable":      unreadable,
				"over 64 KiB":     writeConnectionFile(t, large[:len(large)-1]+strings.Repeat(" ", 70<<10)+"}"),
				"not JSON":        writeConnectionFile(t, "password="+valid.Password),
				"missing a field": writeConnectionFile(t, text(func(fields map[string]any) { delete(fields, "port") })),
				"an unknown field": writeConnectionFile(t, text(func(fields map[string]any) {
					fields["sslmode"] = "disable"
				})),
			}
			reasons := map[string]string{noFileKey: noFileReason(t)}
			for name, path := range files {
				program := startWithFile(t, path, nil, portOption, "0")
				reasons[name] = program.expectRefusal(t)
				expectNoPassword(t, program)
			}
			expectDifferent(t, reasons)
		})
	})

	t.Run("The engine shall take where it connects, its login and its password from the connection file alone.", func(t *testing.T) {
		t.Parallel()
		t.Run("PostgreSQL's variables, a password file and a service file naming a decoy board: it starts on the file's board, the decoy left alone", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			decoy := sharedServer(t).newBoard(t)
			program := startWithFile(t, created.file().write(t), decoyEnvironment(t, decoy), portOption, "0")
			program.listening(t)
			expectHolder(t, created.row(t))
			if changes := decoy.updates(t); len(changes) != 0 {
				t.Fatalf("the decoy board's row was updated: %+v", changes)
			}
			if strings.Contains(created.server.serverLog(t), "user="+decoy.login+" ") {
				t.Fatalf("the decoy login signed in")
			}
		})
	})

	t.Run("The engine shall not write the connection file's password to the local log.", func(t *testing.T) {
		t.Parallel()
		t.Run("a run that starts, loses its lease to another run, waits and starts again, then stops: the password nowhere in its log", func(t *testing.T) {
			t.Parallel()
			send := stopSignals()[0].prepare(t)
			created := sharedServer(t).newBoard(t)
			program := startOnBoard(t, created)
			program.listening(t)
			created.setRow(t, foreignHolder, "now() + interval '25 seconds'")
			program.expectLine(t, 1, "lease_lost", time.Now().Add(renewEvery+testrun.Patient(leaseMargin)))
			program.expectLine(t, 2, "waiting", time.Now().Add(testrun.Patient(waitLineLimit)))
			waitForStarted(t, program, 3, time.Now().Add(25*time.Second+retryEvery+tryLimit+testrun.Patient(leaseMargin)))
			_, sentBy := send(t, program)
			program.exit(t, sentBy.Add(endLeaseWait+testrun.Patient(margin)))
			program.expectLog(t, "started", "lease_lost", "waiting", "started")
			expectNoPassword(t, program)
		})
	})

	t.Run("The engine shall connect to the database only over TLS, and sign in only by SCRAM-SHA-256 with channel binding, under the login the connection file names.", func(t *testing.T) {
		t.Parallel()
		t.Run("started: the server's log shows the file's login signed in by SCRAM-SHA-256 over TLS", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			startOnBoard(t, created).listening(t)
			log := created.server.serverLog(t)
			if !strings.Contains(log, `connection authenticated: identity="`+created.login+`" method=scram-sha-256`) ||
				!regexp.MustCompile(`connection authorized: user=`+created.login+` database=`+created.database+`.*SSL enabled`).MatchString(log) {
				t.Fatalf("the server's log shows no SCRAM sign-in over TLS by %s:\n%s", created.login, log)
			}
		})
	})

	t.Run("If the database's certificate does not chain to the certificate authority in the connection file or does not name the file's host, the database asks for any other way of signing in, or it refuses the sign-in, then the engine shall write one `start_failed` line saying which, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("another authority, the sign-in rule password, a wrong password: three start_failed lines, three reasons", func(t *testing.T) {
			t.Parallel()
			wrongAuthority := sharedServer(t).newBoard(t)
			contents := wrongAuthority.file()
			other, err := makeAuthority()
			if err != nil {
				t.Fatalf("making another authority: %v", err)
			}
			contents.CACertificate = other.pemText
			method := sharedServer(t).newBoard(t)
			method.server.signInRule(t, method.login, "password")
			refused := sharedServer(t).newBoard(t)
			wrongPassword := refused.file()
			wrongPassword.Password = passwordCanary + "-wrong"
			reasons := map[string]string{noFileKey: noFileReason(t)}
			for name, path := range map[string]string{
				"certificate":               contents.write(t),
				"another way of signing in": method.file().write(t),
				"sign-in refused":           wrongPassword.write(t),
			} {
				program := startWithFile(t, path, nil, portOption, "0")
				reasons[name] = program.expectRefusal(t)
				expectNoPassword(t, program)
			}
			expectDifferent(t, reasons)
		})
	})

	t.Run("If its login holds any right on the database beyond those each part grants a server's login, or the power to take one, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		for _, change := range []string{"ALTER ROLE {login} CREATEDB", "GRANT INSERT ON hadv.servers TO {login}"} {
			t.Run(change+": one start_failed line, and a non-zero exit", func(t *testing.T) {
				t.Parallel()
				created := sharedServer(t).newBoard(t)
				created.server.sql(t, created.database, strings.ReplaceAll(change, "{login}", created.login))
				reasons := map[string]string{noFileKey: noFileReason(t)}
				reasons["too powerful"] = startOnBoard(t, created).expectRefusal(t)
				expectDifferent(t, reasons)
			})
		}
	})

	t.Run("If the database refuses for any other reason, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("a database that does not exist: one start_failed line, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			contents := sharedServer(t).newBoard(t).file()
			contents.Database = "nowhere_" + strconv.FormatInt(time.Now().UnixNano(), 10)
			reasons := map[string]string{noFileKey: noFileReason(t)}
			reasons["refused"] = startWithFile(t, contents.write(t), nil, portOption, "0").expectRefusal(t)
			expectDifferent(t, reasons)
		})
		t.Run("a database with TLS switched off: one start_failed line, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			server := startPostgres(t, serverOptions{settings: []string{"ssl = off"}})
			created := server.newBoard(t)
			reasons := map[string]string{noFileKey: noFileReason(t)}
			reasons["no TLS"] = startOnBoard(t, created).expectRefusal(t)
			expectDifferent(t, reasons)
		})
	})

	t.Run("If `hadv.schema_version` is missing or holds a version other than 1 or 2, then the engine shall write one `start_failed` line naming the version it found, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("version 7: one start_failed line naming 7, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			created.sqlAsOwner(t, "UPDATE hadv.schema_version SET version = 7")
			reason := startOnBoard(t, created).expectRefusal(t)
			if !regexp.MustCompile(`(^|[^0-9])7([^0-9]|$)`).MatchString(reason) {
				t.Fatalf("the reason %q does not name the version found, 7", reason)
			}
		})
		t.Run("the table dropped: one start_failed line, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			created.sqlAsOwner(t, "DROP TABLE hadv.schema_version")
			reasons := map[string]string{noFileKey: noFileReason(t)}
			reasons["missing"] = startOnBoard(t, created).expectRefusal(t)
			expectDifferent(t, reasons)
		})
		t.Run("version 2, the next: it starts", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			created.sqlAsOwner(t, "UPDATE hadv.schema_version SET version = 2")
			startOnBoard(t, created).listening(t)
		})
	})

	t.Run("If `hadv.servers` holds no row for the connection file's server ID, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("a server ID with no row: one start_failed line, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			contents := sharedServer(t).newBoard(t).file()
			contents.ServerID += 1000
			reasons := map[string]string{noFileKey: noFileReason(t)}
			reasons["no row"] = startWithFile(t, contents.write(t), nil, portOption, "0").expectRefusal(t)
			expectDifferent(t, reasons)
		})
	})

	t.Run("If the database does not answer, or answers that it is starting up, shutting down or recovering, that it has no connection free, or that it is read-only, then the engine shall write one `waiting` line saying which, listen nowhere, and try again every 10 seconds.", func(t *testing.T) {
		t.Parallel()
		t.Run("a database that closes each connection: one waiting line, nothing listening, tries 10 s apart, still one line after the third", func(t *testing.T) {
			t.Parallel()
			database := startAcceptor(t)
			contents := sharedBoard.file()
			contents.Port = database.port(t)
			port := freedPort(t)
			program := startWithFile(t, contents.write(t), nil, portOption, port)
			program.expectLine(t, 0, "waiting", time.Now().Add(testrun.Patient(waitLineLimit)))
			expectNotListening(t, program, port)
			for len(database.triesSoFar()) < 3 {
				if program.lineCount() > 1 {
					t.Fatalf("the program wrote more than one line while waiting:\n%s", program.text())
				}
				pause(t, 100*time.Millisecond)
			}
			tries := database.triesSoFar()
			for index := 1; index < 3; index++ {
				expectEngineWithin(t, "a try", tries[index], tries[index-1].Add(retryEvery-leaseMargin), tries[index-1].Add(retryEvery+leaseMargin))
			}
			expectNotListening(t, program, port)
			if program.lineCount() != 1 {
				t.Fatalf("the program wrote more than one line while waiting:\n%s", program.text())
			}
		})
		causes := []struct {
			name    string
			prepare func(t *testing.T) (*board, *postgres, func(t *testing.T))
		}{
			{"recovering, a standby with hot standby off, then promoted", func(t *testing.T) (*board, *postgres, func(t *testing.T)) {
				t.Helper()
				created, standby := startStandby(t)
				return created, standby, func(t *testing.T) {
					t.Helper()
					standby.control(t, "promote", "-w", "-t", "60")
				}
			}},
			{"no connection free, the login's limit 0, then lifted", func(t *testing.T) (*board, *postgres, func(t *testing.T)) {
				t.Helper()
				created := sharedServer(t).newBoard(t)
				created.server.sql(t, superuser, "ALTER ROLE "+created.login+" CONNECTION LIMIT 0")
				return created, created.server, func(t *testing.T) {
					t.Helper()
					created.server.sql(t, superuser, "ALTER ROLE "+created.login+" CONNECTION LIMIT -1")
				}
			}},
			{"read-only, the database's default, then reset", func(t *testing.T) (*board, *postgres, func(t *testing.T)) {
				t.Helper()
				created := sharedServer(t).newBoard(t)
				created.server.sql(t, superuser, "ALTER DATABASE "+created.database+" SET default_transaction_read_only = on")
				return created, created.server, func(t *testing.T) {
					t.Helper()
					created.server.sql(t, superuser, "ALTER DATABASE "+created.database+" RESET default_transaction_read_only")
				}
			}},
		}
		for _, cause := range causes {
			t.Run(cause.name+": one waiting line, nothing listening; once fixed, tried again within 10 s, then started", func(t *testing.T) {
				t.Parallel()
				created, database, fix := cause.prepare(t)
				contents := created.file()
				contents.Port = database.port
				port := freedPort(t)
				program := startWithFile(t, contents.write(t), nil, portOption, port)
				program.expectLine(t, 0, "waiting", time.Now().Add(testrun.Patient(waitLineLimit)))
				expectNotListening(t, program, port)
				fix(t)
				fixed := time.Now()
				// The line is about when the program tries, so the try is read from the server's
				// log; the take that follows is the database unit's, bounded by its own 10 s.
				tried := database.waitForTry(t, created.login, fixed, fixed.Add(retryEvery+testrun.Patient(2*leaseMargin)))
				expectWithin(t, "the first try after the fix", tried, fixed.Truncate(time.Millisecond), fixed.Add(retryEvery+leaseMargin))
				waitForStarted(t, program, 1, tried.Add(tryLimit+testrun.Patient(leaseMargin)))
			})
		}
		t.Run("not answering, recovering, no connection free, read-only and a lease held: five waiting lines, five reasons", func(t *testing.T) {
			t.Parallel()
			reasons := map[string]string{}
			database := startAcceptor(t)
			unanswered := sharedBoard.file()
			unanswered.Port = database.port(t)
			recovering, standby := startStandby(t)
			standbyFile := recovering.file()
			standbyFile.Port = standby.port
			full := sharedServer(t).newBoard(t)
			full.server.sql(t, superuser, "ALTER ROLE "+full.login+" CONNECTION LIMIT 0")
			readOnly := sharedServer(t).newBoard(t)
			readOnly.server.sql(t, superuser, "ALTER DATABASE "+readOnly.database+" SET default_transaction_read_only = on")
			held := sharedServer(t).newBoard(t)
			held.setRow(t, foreignHolder, "now() + interval '1 hour'")
			for name, contents := range map[string]connectionFile{
				"not answering": unanswered, "recovering": standbyFile, "no connection free": full.file(),
				"read-only": readOnly.file(), "lease held": held.file(),
			} {
				program := startWithFile(t, contents.write(t), nil, portOption, "0")
				reasons[name], _ = program.expectLine(t, 0, "waiting", time.Now().Add(testrun.Patient(waitLineLimit)))
			}
			expectDifferent(t, reasons)
		})
	})

	t.Run("If its server's lease has not ended and its lease holder is not this run's own, then the engine shall write one `waiting` line saying so, listen nowhere, and try again every 10 seconds.", func(t *testing.T) {
		t.Parallel()
		t.Run("another run's lease ending 15 s on: one waiting line, nothing listening, no update; tried again within 10 s of its end, then started", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			created.setRow(t, foreignHolder, "now() + interval '15 seconds'")
			ends := created.row(t).until
			port := freedPort(t)
			program := startWithFile(t, created.file().write(t), nil, portOption, port)
			program.expectLine(t, 0, "waiting", time.Now().Add(testrun.Patient(waitLineLimit)))
			expectNotListening(t, program, port)
			if changes := created.updates(t); len(changes) != 1 {
				t.Fatalf("the waiting program updated the row: %+v", changes)
			}
			tried := created.server.waitForTry(t, created.login, ends, ends.Add(retryEvery+testrun.Patient(2*leaseMargin)))
			expectWithin(t, "the first try after the lease's end", tried, ends.Truncate(time.Millisecond), ends.Add(retryEvery+leaseMargin))
			started := waitForStarted(t, program, 1, tried.Add(tryLimit+testrun.Patient(leaseMargin)))
			expectWithin(t, "the start", started, ends, tried.Add(tryLimit+leaseMargin))
		})
		t.Run("two programs on one row: the second waits while the first holds it", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			path := created.file().write(t)
			startWithFile(t, path, nil, portOption, "0").listening(t)
			second := startWithFile(t, path, nil, portOption, "0")
			second.expectLine(t, 0, "waiting", time.Now().Add(testrun.Patient(waitLineLimit)))
		})
	})

	t.Run("The engine shall listen for callers only while it holds its server's lease.", func(t *testing.T) {
		t.Parallel()
		t.Run("waiting on a held lease: nothing listens; the lease taken: it listens at the port; the lease lost: nothing listens", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			created.setRow(t, foreignHolder, "now() + interval '5 seconds'")
			port := freedPort(t)
			program := startWithFile(t, created.file().write(t), nil, portOption, port)
			program.expectLine(t, 0, "waiting", time.Now().Add(testrun.Patient(waitLineLimit)))
			expectNotListening(t, program, port)
			value, _ := program.expectLine(t, 1, "started", time.Now().Add(5*time.Second+retryEvery+tryLimit+testrun.Patient(leaseMargin)))
			for _, address := range strings.Split(value, ",") {
				expectServed(t, strings.TrimPrefix(address, "telnet://"))
			}
			created.setRow(t, foreignHolder, "now() + interval '1 hour'")
			program.expectLine(t, 2, "lease_lost", time.Now().Add(renewEvery+testrun.Patient(leaseMargin)))
			expectNotListening(t, program, port)
		})
	})

	t.Run("When it takes its server's lease, the engine shall write a new random lease holder and a lease end 30 seconds after the database's current time to its server's row, only if that row's lease has ended or its lease holder is this run's own.", func(t *testing.T) {
		t.Parallel()
		t.Run("started: the row has a new holder, its end 30 s after the take's own database time", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			startOnBoard(t, created).listening(t)
			holder := expectHolder(t, created.row(t))
			changes := created.updates(t)
			if len(changes) < 1 || changes[0].oldHolder != "" || changes[0].newHolder != holder {
				t.Fatalf("the take's update was %+v, want one writing the holder %s", changes, holder)
			}
			expectExactEnd(t, changes[0], leaseLength)
		})
		t.Run("two programs, one after the other, on one row: two different holders", func(t *testing.T) {
			t.Parallel()
			send := stopSignals()[0].prepare(t)
			created := sharedServer(t).newBoard(t)
			path := created.file().write(t)
			first := startWithFile(t, path, nil, portOption, "0")
			first.listening(t)
			firstHolder := expectHolder(t, created.row(t))
			_, sentBy := send(t, first)
			first.exit(t, sentBy.Add(endLeaseWait+testrun.Patient(margin)))
			startWithFile(t, path, nil, portOption, "0").listening(t)
			if secondHolder := expectHolder(t, created.row(t)); secondHolder == firstHolder {
				t.Fatalf("both runs wrote the holder %s", firstHolder)
			}
		})
	})

	t.Run("While it holds its server's lease, the engine shall renew it every 10 seconds, writing a lease end 30 seconds after the database's current time, only while the row's lease holder is its own.", func(t *testing.T) {
		t.Parallel()
		t.Run("two renewals, each 10 s after the one before, each 30 s after the database's time, the holder kept", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			startOnBoard(t, created).listening(t)
			taken := created.waitForUpdates(t, 1, time.Now().Add(testrun.Patient(leaseMargin)))[0]
			changes := created.waitForUpdates(t, 3, taken.transactionStart.Add(2*renewEvery+testrun.Patient(2*leaseMargin)))
			for index := 1; index < 3; index++ {
				expectEngineWithin(t, "a renewal", changes[index].transactionStart,
					changes[index-1].transactionStart.Add(renewEvery-leaseMargin), changes[index-1].transactionStart.Add(renewEvery+leaseMargin))
				expectExactEnd(t, changes[index], leaseLength)
				if changes[index].newHolder != taken.newHolder {
					t.Fatalf("a renewal wrote the holder %s, want the take's %s", changes[index].newHolder, taken.newHolder)
				}
			}
		})
		t.Run("another run's holder written after the take: the row left as that run wrote it", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			program := startOnBoard(t, created)
			program.listening(t)
			created.setRow(t, foreignHolder, "now() + interval '1 hour'")
			written := created.row(t)
			program.expectLine(t, 1, "lease_lost", time.Now().Add(renewEvery+testrun.Patient(leaseMargin)))
			if after := created.row(t); after.holder != foreignHolder || !after.until.Equal(written.until) {
				t.Fatalf("the row became %+v, want the other run's %+v", after, written)
			}
		})
	})

	t.Run("If 25 seconds pass after it sent its last take or renewal that succeeded, or a renewal finds the lease holder is not its own, then the engine shall close every open connection and every listener, write one `lease_lost` line, and try to take the lease again every 10 seconds.", func(t *testing.T) {
		t.Parallel()
		t.Run("the row locked after a renewal: lease_lost 25 s after it, the caller's connection and every listener closed; the row freed: started again", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			program := startOnBoard(t, created)
			addresses := program.listening(t)
			renewed := created.waitForUpdates(t, 2, time.Now().Add(renewEvery+testrun.Patient(2*leaseMargin)))[1].transactionStart
			lock := created.lockRow(t)
			pause(t, time.Until(renewed.Add(lossAfter-5*time.Second)))
			call := waitingCaller(t, addresses[0])
			_, lost := program.expectLine(t, 1, "lease_lost", renewed.Add(lossAfter+testrun.Patient(2*leaseMargin)))
			expectEngineWithin(t, "lease_lost", lost, renewed.Add(lossAfter-leaseMargin), renewed.Add(lossAfter+leaseMargin))
			call.expectEnd(t, lost.Add(-leaseMargin), lost.Add(testrun.Patient(margin)))
			for _, address := range addresses {
				expectRefused(t, address)
			}
			lock.release(t)
			waitForStarted(t, program, 2, time.Now().Add(retryEvery+tryLimit+testrun.Patient(leaseMargin)))
		})
		t.Run("another run's holder written: lease_lost by the next renewal, then waiting; that lease ended: started again", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			program := startOnBoard(t, created)
			program.listening(t)
			changed := time.Now()
			created.setRow(t, foreignHolder, "now() + interval '25 seconds'")
			ends := created.row(t).until
			_, lost := program.expectLine(t, 1, "lease_lost", changed.Add(renewEvery+testrun.Patient(leaseMargin)))
			expectWithin(t, "lease_lost", lost, changed, changed.Add(renewEvery+leaseMargin))
			program.expectLine(t, 2, "waiting", lost.Add(retryEvery+tryLimit+testrun.Patient(leaseMargin)))
			started := waitForStarted(t, program, 3, ends.Add(retryEvery+tryLimit+testrun.Patient(leaseMargin)))
			expectWithin(t, "the start", started, ends, ends.Add(retryEvery+tryLimit+leaseMargin))
		})
	})

	t.Run("When it receives a stop signal while it holds its server's lease, the engine shall set the lease end to the database's current time before it exits, unless the database does not answer.", func(t *testing.T) {
		t.Parallel()
		for _, signal := range stopSignals() {
			t.Run(signal.name+": the lease's end set to the database's time, before the exit", func(t *testing.T) {
				t.Parallel()
				send := signal.prepare(t)
				created := sharedServer(t).newBoard(t)
				program := startOnBoard(t, created)
				program.listening(t)
				holder := expectHolder(t, created.row(t))
				_, sentBy := send(t, program)
				_, exitedAt := program.exit(t, sentBy.Add(endLeaseWait+testrun.Patient(margin)))
				changes := created.updates(t)
				last := changes[len(changes)-1]
				if last.newHolder != holder || last.recorded.After(exitedAt) {
					t.Fatalf("no update ending the lease came before the exit: %+v", changes)
				}
				expectExactEnd(t, last, 0)
			})
		}
		t.Run("the row locked: the program exits within 1 s, the row left as it was", func(t *testing.T) {
			t.Parallel()
			send := stopSignals()[0].prepare(t)
			created := sharedServer(t).newBoard(t)
			program := startOnBoard(t, created)
			program.listening(t)
			before := created.row(t)
			lock := created.lockRow(t)
			from, sentBy := send(t, program)
			_, exitedAt := program.exit(t, sentBy.Add(endLeaseWait+testrun.Patient(leaseMargin)))
			expectWithin(t, "the exit", exitedAt, from, sentBy.Add(endLeaseWait+margin))
			lock.release(t)
			if after := created.row(t); after.holder != before.holder {
				t.Fatalf("the row's holder changed from %s to %s", before.holder, after.holder)
			}
		})
	})

	t.Run("The engine shall write no line to the local log other than `started`, `start_failed`, `waiting` and `lease_lost`.", func(t *testing.T) {
		t.Parallel()
		t.Run("a lease held, taken, lost and taken again, then a stop: started, waiting, lease_lost and nothing else", func(t *testing.T) {
			t.Parallel()
			send := stopSignals()[0].prepare(t)
			created := sharedServer(t).newBoard(t)
			// Each hold lasts until the program has written its waiting line, then the test ends
			// it: a hold that runs out on a clock can end before a loaded machine's first try.
			created.setRow(t, foreignHolder, "now() + interval '1 hour'")
			program := startOnBoard(t, created)
			program.expectLine(t, 0, "waiting", time.Now().Add(testrun.Patient(waitLineLimit)))
			created.setRow(t, foreignHolder, "now()")
			waitForStarted(t, program, 1, time.Now().Add(retryEvery+tryLimit+testrun.Patient(leaseMargin)))
			created.setRow(t, foreignHolder, "now() + interval '1 hour'")
			program.expectLine(t, 2, "lease_lost", time.Now().Add(renewEvery+testrun.Patient(leaseMargin)))
			program.expectLine(t, 3, "waiting", time.Now().Add(testrun.Patient(waitLineLimit)))
			created.setRow(t, foreignHolder, "now()")
			waitForStarted(t, program, 4, time.Now().Add(retryEvery+tryLimit+testrun.Patient(leaseMargin)))
			_, sentBy := send(t, program)
			program.exit(t, sentBy.Add(endLeaseWait+testrun.Patient(margin)))
			program.expectLog(t, "waiting", "started", "lease_lost", "waiting", "started")
		})
	})

	t.Run("When it receives a stop signal, the engine shall close every open connection at once and exit.", func(t *testing.T) {
		t.Parallel()
		for _, signal := range stopSignals() {
			t.Run(signal.name+" while it waits for the database: it exits at once, its log the waiting line alone", func(t *testing.T) {
				t.Parallel()
				send := signal.prepare(t)
				database := startAcceptor(t)
				contents := sharedBoard.file()
				contents.Port = database.port(t)
				program := startWithFile(t, contents.write(t), nil, portOption, "0")
				program.expectLine(t, 0, "waiting", time.Now().Add(testrun.Patient(waitLineLimit)))
				from, sentBy := send(t, program)
				_, exitedAt := program.exit(t, sentBy.Add(testrun.Patient(margin)))
				expectWithin(t, "the exit", exitedAt, from, sentBy.Add(margin))
				program.expectLog(t, "waiting")
			})
		}
	})
}

// TestLinuxDatabaseProgram is Linux's alone: the line checks the file's mode on Linux only.
func TestLinuxDatabaseProgram(t *testing.T) {
	t.Parallel()
	t.Run("If, on Linux, the connection file's mode lets its group or others read it, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("mode 0644: one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			path := created.file().write(t)
			setMode(t, path, 0o644)
			reasons := map[string]string{noFileKey: noFileReason(t)}
			reasons["mode"] = startWithFile(t, path, nil, portOption, "0").expectRefusal(t)
			reasons["missing"] = startWithFile(t, path+".missing", nil, portOption, "0").expectRefusal(t)
			expectDifferent(t, reasons)
		})
	})
}

// decoyEnvironment is every one of PostgreSQL's variables the library reads, pointing at the
// decoy board or at a setting that would break the file's sign-in.
func decoyEnvironment(t *testing.T, decoy *board) []string {
	t.Helper()
	directory := t.TempDir()
	serviceFile := directory + string(os.PathSeparator) + "pg_service.conf"
	passwordFile := directory + string(os.PathSeparator) + "pgpass"
	service := fmt.Sprintf("[decoy]\nhost=%s\nport=%d\ndbname=%s\nuser=%s\npassword=%s\nsslmode=disable\noptions=-c default_transaction_read_only=on\n",
		databaseHost, decoy.server.port, decoy.database, decoy.login, decoy.password)
	for path, text := range map[string]string{serviceFile: service, passwordFile: "*:*:*:*:" + passwordCanary + "-wrong\n"} {
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
	}
	environment := []string{
		"PGHOST=" + databaseHost, "PGHOSTADDR=" + databaseHost, "PGPORT=" + strconv.Itoa(decoy.server.port),
		"PGDATABASE=" + decoy.database, "PGUSER=" + decoy.login, "PGPASSWORD=" + decoy.password,
		"PGPASSFILE=" + passwordFile, "PGSERVICEFILE=" + serviceFile, "PGSERVICE=decoy", "PGSSLMODE=disable",
		"PGOPTIONS=-c default_transaction_read_only=on", "PGAPPNAME=decoy", "PGCONNECT_TIMEOUT=1",
		"PGTARGETSESSIONATTRS=standby", "PGREQUIREAUTH=password", "PGCHANNELBINDING=disable",
	}
	return slices.Clip(environment)
}

// jsonValue writes one of the connection file's values as JSON.
func jsonValue(value any) (string, error) {
	switch typed := value.(type) {
	case string:
		return strconv.Quote(typed), nil
	case int64:
		return strconv.FormatInt(typed, 10), nil
	case int:
		return strconv.Itoa(typed), nil
	}
	return "", fmt.Errorf("a value of type %T", value)
}
