// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Taking the lease: connecting over TLS, signing in, each failure Take may return and the order
// they are made in, and the take itself, against real servers the tests make and, for what no
// real server sends, the fake.
package database_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/database"
)

// The limits as the lines state them, written here so a changed constant in the package cannot
// move a test with it.
const (
	tryLimit       = 10 * time.Second
	leaseLength    = 30 * time.Second
	lossAfter      = 25 * time.Second
	renewEvery     = 10 * time.Second
	endWait        = time.Second
	replyMostBytes = 1048576
	versionMadeFor = 1
	waitForNoDial  = time.Second
	// foreignHolder is another run's lease holder, which the tests write into a row.
	foreignHolder  = "11111111-2222-4333-8444-555555555555"
	takeLimit      = 2 * tryLimit
	versionPattern = `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
)

// timingMargin is how late an event may come past its moment on every runner. To be measured at
// CI's own load on each runner before the summary; this is the draft.
const timingMargin = 2 * time.Second

// takeErrors are every error Take may return but the context's and a *SchemaVersionError.
var takeErrors = []error{database.ErrUnreachable, database.ErrNotReady, database.ErrNoConnectionFree,
	database.ErrReadOnly, database.ErrRefused, database.ErrLeaseHeld, database.ErrCertificate,
	database.ErrSignInMethod, database.ErrSignInRefused, database.ErrTooPowerful, database.ErrNoServerRow,
	database.ErrSchemaVersion}

var holderPattern = regexp.MustCompile(versionPattern)

// serverDatabase reads the contents as a connection file and makes a ServerDatabase from it.
func serverDatabase(t *testing.T, contents connectionFile) *database.ServerDatabase {
	t.Helper()
	file, err := database.ReadConnectionFile(writeFile(t, contents.text(t)))
	if err != nil {
		t.Fatalf("the test's connection file was refused: %v", err)
	}
	return database.NewServerDatabase(file)
}

// take makes a ServerDatabase from the contents and takes the lease once, bounded by takeLimit.
// A lease taken is ended when the row ends.
func take(t *testing.T, contents connectionFile) (*database.Lease, error) {
	t.Helper()
	return takeWith(t, serverDatabase(t, contents))
}

func takeWith(t *testing.T, server *database.ServerDatabase) (*database.Lease, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), takeLimit)
	defer cancel()
	lease, err := server.Take(ctx)
	if lease != nil {
		t.Cleanup(lease.EndLease)
	}
	return lease, err
}

// expectTakeError checks Take failed with want and nothing else, returned no Lease, and that the
// error's text holds neither the password nor the canary.
func expectTakeError(t *testing.T, lease *database.Lease, err, want error, password string) {
	t.Helper()
	if lease != nil {
		t.Fatalf("Take returned a Lease with the error %v", err)
	}
	expectOnly(t, err, want, takeErrors)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the error %v matches the context's", err)
	}
	if strings.Contains(err.Error(), password) || strings.Contains(err.Error(), canary) {
		t.Fatalf("the error's text holds the password or text the database sent: %q", err.Error())
	}
}

// expectTaken checks Take returned a Lease that is not lost, and the row's new holder.
func expectTaken(t *testing.T, lease *database.Lease, err error, created *board) lease {
	t.Helper()
	if err != nil {
		t.Fatalf("Take failed: %v", err)
	}
	if lease == nil {
		t.Fatalf("Take returned no Lease and no error")
	}
	select {
	case <-lease.Lost():
		t.Fatalf("the Lease Take returned is already lost")
	default:
	}
	found := created.row(t)
	if !holderPattern.MatchString(found.holder) {
		t.Fatalf("the row's holder is %q, not a UUID", found.holder)
	}
	return found
}

// expectNoSignIn checks the server's log shows no sign-in by the login.
func expectNoSignIn(t *testing.T, server *postgres, login string) {
	t.Helper()
	if server.signedIn(t, login) {
		t.Fatalf("the server's log shows %s signed in:\n%s", login, server.log(t))
	}
}

// logOnFailure shows, if the row fails, what the server logged for the login's connections: a
// refusal the server logged but the engine reported as a dead connection is told apart from one
// the server never sent. Windows CI met that once, with no log to read.
func logOnFailure(t *testing.T, server *postgres, login string) {
	t.Helper()
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("the server's log for the connections of %s:\n%s", login, server.connectionLog(login))
		}
	})
}

// backendID is the server process an entry of the server's log came from.
var backendID = regexp.MustCompile(`^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3} UTC \[(\d+)\] `)

// connectionLog is every entry of the server's log from a server process whose entries name the
// login, so a connection's whole story shows, from its arrival, before the login is known, to its
// end. An entry runs from its prefix to the next, since an entry may span lines.
func (server *postgres) connectionLog(login string) string {
	names := regexp.MustCompile(`\b` + regexp.QuoteMeta(login) + `\b`)
	type entry struct {
		process string
		text    strings.Builder
	}
	var entries []*entry
	for line := range strings.SplitSeq(readText(server.logPath), "\n") {
		if match := backendID.FindStringSubmatch(line); match != nil || len(entries) == 0 {
			process := ""
			if match != nil {
				process = match[1]
			}
			entries = append(entries, &entry{process: process})
		}
		last := entries[len(entries)-1]
		last.text.WriteString(line)
		last.text.WriteString("\n")
	}
	named := map[string]bool{}
	for _, each := range entries {
		if each.process != "" && names.MatchString(each.text.String()) {
			named[each.process] = true
		}
	}
	var shown strings.Builder
	for _, each := range entries {
		if named[each.process] {
			shown.WriteString(each.text.String())
		}
	}
	if shown.Len() == 0 {
		return "(no entry names it)"
	}
	return shown.String()
}

// expectExactEnd checks an update wrote a lease end LeaseSeconds after the database's time: at
// least its transaction's start plus 30 s, and at most the moment it was recorded plus 30 s.
func expectExactEnd(t *testing.T, change update, after time.Duration) {
	t.Helper()
	if change.newUntil.Before(change.transactionStart.Add(after)) || change.newUntil.After(change.recorded.Add(after)) {
		t.Fatalf("the update wrote a lease end of %v, want %v after the database's time, between %v and %v",
			change.newUntil.Format(time.RFC3339Nano), after, change.transactionStart.Add(after).Format(time.RFC3339Nano),
			change.recorded.Add(after).Format(time.RFC3339Nano))
	}
}

func TestNewServerDatabase(t *testing.T) {
	t.Parallel()
	t.Run("NewServerDatabase shall connect to nothing.", func(t *testing.T) {
		t.Parallel()
		t.Run("made from a file naming a listening fake: no dial within a second, then Take dials it", func(t *testing.T) {
			t.Parallel()
			server := startFake(t, true, nil)
			made := serverDatabase(t, server.file())
			pause(t, waitForNoDial)
			if count := server.dialCount(); count != 0 {
				t.Fatalf("NewServerDatabase dialed the database %d times", count)
			}
			lease, err := takeWith(t, made)
			expectTakeError(t, lease, err, database.ErrUnreachable, "password-"+canary)
			if server.dialCount() == 0 {
				t.Fatalf("Take did not dial the database the file names")
			}
		})
	})
}

func TestTake(t *testing.T) {
	t.Parallel()

	t.Run("Take shall connect to the ConnectionFile's host and port over TLS 1.2 or 1.3 only, and accept the database's certificate only when it chains to the ConnectionFile's certificate authority and names its host.", func(t *testing.T) {
		t.Parallel()
		t.Run("a certificate from the file's authority naming 127.0.0.1: taken, the server's log shows the sign-in over TLS", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			lease, err := take(t, created.file())
			expectTaken(t, lease, err, created)
			if !regexp.MustCompile(`connection authorized: user=` + created.login + ` database=` + created.database + `.*SSL enabled \(protocol=TLSv1\.[23]`).MatchString(created.server.log(t)) {
				t.Fatalf("the server's log shows no sign-in by %s to %s over TLS 1.2 or 1.3:\n%s", created.login, created.database, created.server.log(t))
			}
		})
		t.Run("a server limited to TLS 1.2: taken over TLS 1.2", func(t *testing.T) {
			t.Parallel()
			server := startPostgres(t, serverOptions{settings: []string{"ssl_max_protocol_version = 'TLSv1.2'"}})
			created := server.newBoard(t)
			lease, err := take(t, created.file())
			expectTaken(t, lease, err, created)
			if !regexp.MustCompile(`connection authorized: user=` + created.login + ` .*SSL enabled \(protocol=TLSv1\.2`).MatchString(server.log(t)) {
				t.Fatalf("the server's log shows no sign-in by %s over TLS 1.2:\n%s", created.login, server.log(t))
			}
		})
	})

	t.Run("Take shall sign in as the ConnectionFile's login, to its database, only by SCRAM-SHA-256 with channel binding.", func(t *testing.T) {
		t.Parallel()
		t.Run("the server's log shows the file's login authenticated by SCRAM-SHA-256", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			lease, err := take(t, created.file())
			expectTaken(t, lease, err, created)
			if !strings.Contains(created.server.log(t), `connection authenticated: identity="`+created.login+`" method=scram-sha-256`) {
				t.Fatalf("the server's log shows no SCRAM sign-in by %s:\n%s", created.login, created.server.log(t))
			}
		})
		t.Run("offered both, the fake is answered with SCRAM-SHA-256-PLUS and tls-server-end-point binding", func(t *testing.T) {
			t.Parallel()
			mechanism := make(chan string, 1)
			server := startFake(t, false, func(t *testing.T, connection *fakeConnection) {
				t.Helper()
				connection.send(t, 'R', saslBody("SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"))
				kind, body, err := connection.readMessage(time.Now().Add(tryLimit))
				if err != nil || kind != 'p' {
					mechanism <- fmt.Sprintf("no SASL response (%q, %v)", kind, err)
					return
				}
				name, rest, _ := strings.Cut(string(body), "\x00")
				if len(rest) < 4 {
					mechanism <- "a SASL response with no data"
					return
				}
				mechanism <- name + " " + rest[4:]
				connection.send(t, 'E', errorBody("28P01", "refused"))
			})
			lease, err := take(t, server.file())
			expectTakeError(t, lease, err, database.ErrSignInRefused, "password-"+canary)
			got := <-mechanism
			if !strings.HasPrefix(got, "SCRAM-SHA-256-PLUS p=tls-server-end-point,") {
				t.Fatalf("the client answered %q, want SCRAM-SHA-256-PLUS with tls-server-end-point binding", got)
			}
		})
	})

	t.Run("If the database does not answer within TrySeconds, refuses the connection, or the connection fails after it is made, then Take shall return ErrUnreachable.", func(t *testing.T) {
		t.Parallel()
		t.Run("nothing listens at the port: ErrUnreachable", func(t *testing.T) {
			t.Parallel()
			contents := sharedServer(t).newBoard(t).file()
			port, err := freePort()
			if err != nil {
				t.Fatalf("finding a free port: %v", err)
			}
			contents.Port = port
			lease, err := take(t, contents)
			expectTakeError(t, lease, err, database.ErrUnreachable, contents.Password)
		})
		t.Run("a fake that closes each connection at once: ErrUnreachable", func(t *testing.T) {
			t.Parallel()
			server := startFake(t, true, nil)
			lease, err := take(t, server.file())
			expectTakeError(t, lease, err, database.ErrUnreachable, "password-"+canary)
		})
		t.Run("a fake that makes TLS, reads the startup and never answers: ErrUnreachable at 10 s", func(t *testing.T) {
			t.Parallel()
			server := startFake(t, false, func(_ *testing.T, connection *fakeConnection) {
				connection.awaitEnd(time.Now().Add(takeLimit))
			})
			called := time.Now()
			lease, err := take(t, server.file())
			returned := time.Now()
			expectTakeError(t, lease, err, database.ErrUnreachable, "password-"+canary)
			expectWithin(t, "Take's return", returned, called.Add(tryLimit), called.Add(tryLimit+timingMargin))
		})
		t.Run("a fake that makes TLS, reads the startup and closes the connection: ErrUnreachable", func(t *testing.T) {
			t.Parallel()
			server := startFake(t, false, func(*testing.T, *fakeConnection) {})
			lease, err := take(t, server.file())
			expectTakeError(t, lease, err, database.ErrUnreachable, "password-"+canary)
		})
		t.Run("the server stopped: ErrUnreachable", func(t *testing.T) {
			t.Parallel()
			server := startPostgres(t, serverOptions{})
			created := server.newBoard(t)
			server.control(t, "stop", "-m", "fast", "-w", "-t", "60")
			lease, err := take(t, created.file())
			expectTakeError(t, lease, err, database.ErrUnreachable, created.password)
		})
	})

	t.Run("If the database answers that it is starting up, shutting down or recovering, then Take shall return ErrNotReady.", func(t *testing.T) {
		t.Parallel()
		t.Run("shutting down, a session holding it open: ErrNotReady", func(t *testing.T) {
			t.Parallel()
			server := startPostgres(t, serverOptions{})
			created := server.newBoard(t)
			created.lockRow(t)
			server.control(t, "stop", "-m", "smart", "-W")
			waitForLog(t, server, "received smart shutdown request")
			lease, err := take(t, created.file())
			expectTakeError(t, lease, err, database.ErrNotReady, created.password)
		})
		t.Run("a standby in recovery with hot standby off: ErrNotReady", func(t *testing.T) {
			t.Parallel()
			created, standby := startStandby(t, false)
			contents := created.file()
			contents.Port = standby.port
			lease, err := take(t, contents)
			expectTakeError(t, lease, err, database.ErrNotReady, created.password)
		})
	})

	t.Run("If the database answers that it has no connection free, then Take shall return ErrNoConnectionFree.", func(t *testing.T) {
		t.Parallel()
		t.Run("the login's connection limit 0: ErrNoConnectionFree", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			created.server.sql(t, superuser, "ALTER ROLE "+created.login+" CONNECTION LIMIT 0")
			lease, err := take(t, created.file())
			expectTakeError(t, lease, err, database.ErrNoConnectionFree, created.password)
		})
	})

	t.Run("If the database will not use TLS 1.2 or 1.3, then Take shall return ErrRefused without sending the password.", func(t *testing.T) {
		t.Parallel()
		for _, entry := range []struct {
			name     string
			settings []string
		}{
			{"TLS off", []string{"ssl = off"}},
			{"TLS 1.1 alone", []string{"ssl_min_protocol_version = 'TLSv1'", "ssl_max_protocol_version = 'TLSv1.1'", "ssl_ciphers = 'DEFAULT:@SECLEVEL=0'"}},
		} {
			t.Run(entry.name+", the login allowed with or without TLS: ErrRefused, and no sign-in in the server's log", func(t *testing.T) {
				t.Parallel()
				server := startPostgres(t, serverOptions{settings: entry.settings})
				created := server.newBoard(t)
				server.signInRule(t, created.login, "scram-sha-256-any")
				lease, err := take(t, created.file())
				expectTakeError(t, lease, err, database.ErrRefused, created.password)
				expectNoSignIn(t, server, created.login)
			})
		}
	})

	t.Run("If the database's certificate fails its check, or cannot be used for channel binding, then Take shall return ErrCertificate without sending the password.", func(t *testing.T) {
		t.Parallel()
		t.Run("the file names another authority: ErrCertificate, and no sign-in in the server's log", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			contents := created.file()
			contents.CACertificate = newAuthority(t).pemText
			lease, err := take(t, contents)
			expectTakeError(t, lease, err, database.ErrCertificate, created.password)
			expectNoSignIn(t, created.server, created.login)
		})
		for _, entry := range []struct {
			name    string
			options serverOptions
		}{
			{"a certificate naming db.invalid alone", serverOptions{certificate: serverCertificate{names: []string{"db.invalid"}}}},
			{"a certificate naming 127.0.0.2 alone", serverOptions{certificate: serverCertificate{addresses: []net.IP{net.ParseIP("127.0.0.2")}}}},
			{"a certificate that expired an hour ago", serverOptions{certificate: serverCertificate{notAfter: time.Now().Add(-time.Hour)}}},
			{"an Ed25519-signed certificate, which channel binding cannot hash", serverOptions{edwards: true}},
		} {
			t.Run(entry.name+": ErrCertificate, and no sign-in in the server's log", func(t *testing.T) {
				t.Parallel()
				server := startPostgres(t, entry.options)
				created := server.newBoard(t)
				lease, err := take(t, created.file())
				expectTakeError(t, lease, err, database.ErrCertificate, created.password)
				expectNoSignIn(t, server, created.login)
			})
		}
	})

	t.Run("If the database asks for any other way of signing in, then Take shall return ErrSignInMethod without sending the password.", func(t *testing.T) {
		t.Parallel()
		for _, method := range []string{"password", "md5", "trust"} {
			t.Run("the sign-in rule "+method+": ErrSignInMethod, and no sign-in in the server's log", func(t *testing.T) {
				t.Parallel()
				created := sharedServer(t).newBoard(t)
				if method == "md5" {
					created.server.sql(t, superuser, "SET password_encryption = 'md5'; ALTER ROLE "+created.login+" PASSWORD "+quoteLiteral(created.password))
				}
				created.server.signInRule(t, created.login, method)
				lease, err := take(t, created.file())
				expectTakeError(t, lease, err, database.ErrSignInMethod, created.password)
				if method != "trust" {
					expectNoSignIn(t, created.server, created.login)
				}
			})
		}
		t.Run("a fake offering SCRAM-SHA-256 without channel binding: ErrSignInMethod, and nothing sent back", func(t *testing.T) {
			t.Parallel()
			received := make(chan string, 1)
			server := startFake(t, false, func(t *testing.T, connection *fakeConnection) {
				t.Helper()
				connection.send(t, 'R', saslBody("SCRAM-SHA-256"))
				kind, _, err := connection.readMessage(time.Now().Add(tryLimit))
				received <- fmt.Sprintf("%q %v", kind, err)
			})
			lease, err := take(t, server.file())
			expectTakeError(t, lease, err, database.ErrSignInMethod, "password-"+canary)
			if got := <-received; strings.HasPrefix(got, `'p'`) {
				t.Fatalf("the client answered the offer without channel binding: %s", got)
			}
		})
	})

	t.Run("If the database refuses the sign-in, then Take shall return ErrSignInRefused.", func(t *testing.T) {
		t.Parallel()
		cases := map[string]func(t *testing.T, created *board, contents *connectionFile){
			"a wrong password": func(_ *testing.T, _ *board, contents *connectionFile) {
				contents.Password = "wrong-" + canary
			},
			"the sign-in rule reject": func(t *testing.T, created *board, _ *connectionFile) {
				t.Helper()
				created.server.signInRule(t, created.login, "reject")
			},
			"the login not allowed to log in": func(t *testing.T, created *board, _ *connectionFile) {
				t.Helper()
				created.server.sql(t, superuser, "ALTER ROLE "+created.login+" NOLOGIN")
			},
			"a login that does not exist": func(_ *testing.T, _ *board, contents *connectionFile) {
				contents.Login = "nobody_" + strconv.FormatInt(time.Now().UnixNano(), 10)
			},
		}
		for name, change := range cases {
			t.Run(name+": ErrSignInRefused", func(t *testing.T) {
				t.Parallel()
				created := sharedServer(t).newBoard(t)
				contents := created.file()
				change(t, created, &contents)
				logOnFailure(t, created.server, contents.Login)
				lease, err := take(t, contents)
				expectTakeError(t, lease, err, database.ErrSignInRefused, created.password)
			})
		}
		t.Run("a fake refusing with a message holding the canary: ErrSignInRefused, its text without the message", func(t *testing.T) {
			t.Parallel()
			server := startFake(t, false, func(t *testing.T, connection *fakeConnection) {
				t.Helper()
				connection.send(t, 'E', errorBody("28P01", "password authentication failed "+canary))
				connection.awaitEnd(time.Now().Add(tryLimit))
			})
			lease, err := take(t, server.file())
			expectTakeError(t, lease, err, database.ErrSignInRefused, "password-"+canary)
		})
	})

	t.Run("If the login holds any role attribute but LOGIN and INHERIT (SUPERUSER, CREATEROLE, CREATEDB, REPLICATION and BYPASSRLS among them), is a member of any role but hadv_server, may grant hadv_server to another role, owns anything in the database, or holds, itself or through PUBLIC, a right on the database or on any schema or object in it that schema.sql does not grant hadv_server; or if hadv_server holds any role attribute but INHERIT; then Take shall return ErrTooPowerful. Connecting to the database; USAGE on a language, on a data type and on the schema public, which PostgreSQL gives every login by default; and the rights PostgreSQL gives every login by default on its own catalogs, are not counted; a right granted beyond those defaults on a catalog object, such as EXECUTE on pg_read_file, is.", func(t *testing.T) {
		t.Parallel()
		// Each change is made as the superuser in the board's database, its names filled in.
		cases := []struct {
			name   string
			change string
		}{
			{"SUPERUSER", "ALTER ROLE {login} SUPERUSER"},
			{"CREATEROLE", "ALTER ROLE {login} CREATEROLE"},
			{"CREATEDB", "ALTER ROLE {login} CREATEDB"},
			{"REPLICATION", "ALTER ROLE {login} REPLICATION"},
			{"BYPASSRLS", "ALTER ROLE {login} BYPASSRLS"},
			{"a member of pg_read_all_data", "GRANT pg_read_all_data TO {login}"},
			{"a member of a role with no rights", "CREATE ROLE {login}_extra NOLOGIN; GRANT {login}_extra TO {login}"},
			{"a member of a SUPERUSER role that cannot log in", "CREATE ROLE {login}_admin SUPERUSER NOLOGIN; GRANT {login}_admin TO {login}"},
			{"able to grant hadv_server to another role", "GRANT hadv_server TO {login} WITH ADMIN OPTION"},
			// A default role makes the session run as hadv_server from the sign-in on; the rights
			// counted are still the login's own, read through each way a right can come.
			{"SUPERUSER, the login's default role hadv_server", "ALTER ROLE {login} SUPERUSER; ALTER ROLE {login} SET role = hadv_server"},
			{"a member of pg_read_all_data, the login's default role hadv_server", "GRANT pg_read_all_data TO {login}; ALTER ROLE {login} SET role = hadv_server"},
			{"INSERT on hadv.servers, the login's default role hadv_server", "GRANT INSERT ON hadv.servers TO {login}; ALTER ROLE {login} SET role = hadv_server"},
			{"the owner of a table in public", "CREATE TABLE public.{login}_owned (value integer); ALTER TABLE public.{login}_owned OWNER TO {login}"},
			{"the owner of the database", "ALTER DATABASE {database} OWNER TO {login}"},
			{"CREATE on the database", "GRANT CREATE ON DATABASE {database} TO {login}"},
			{"TEMPORARY on the database", "GRANT TEMPORARY ON DATABASE {database} TO {login}"},
			{"TEMPORARY on the database to PUBLIC", "GRANT TEMPORARY ON DATABASE {database} TO PUBLIC"},
			{"CREATE on hadv", "GRANT CREATE ON SCHEMA hadv TO {login}"},
			{"CREATE on public", "GRANT CREATE ON SCHEMA public TO {login}"},
			{"USAGE on a new schema", "CREATE SCHEMA {login}_more; GRANT USAGE ON SCHEMA {login}_more TO {login}"},
			{"INSERT on hadv.servers", "GRANT INSERT ON hadv.servers TO {login}"},
			{"DELETE on hadv.servers", "GRANT DELETE ON hadv.servers TO {login}"},
			{"TRUNCATE on hadv.servers", "GRANT TRUNCATE ON hadv.servers TO {login}"},
			{"TRIGGER on hadv.servers", "GRANT TRIGGER ON hadv.servers TO {login}"},
			{"REFERENCES on hadv.servers", "GRANT REFERENCES ON hadv.servers TO {login}"},
			{"UPDATE on all of hadv.servers", "GRANT UPDATE ON hadv.servers TO {login}"},
			{"UPDATE on hadv.servers' id", "GRANT UPDATE (id) ON hadv.servers TO {login}"},
			{"UPDATE on hadv.schema_version", "GRANT UPDATE ON hadv.schema_version TO {login}"},
			{"SELECT on a new table in hadv", "CREATE TABLE hadv.{login}_more (value integer); GRANT SELECT ON hadv.{login}_more TO {login}"},
			{"INSERT on hadv.servers to PUBLIC", "GRANT INSERT ON hadv.servers TO PUBLIC"},
			{"INSERT on hadv.servers to hadv_server", "GRANT INSERT ON hadv.servers TO hadv_server"},
			{"USAGE on hadv.servers' ID sequence", "GRANT USAGE ON SEQUENCE hadv.servers_id_seq TO {login}"},
			{"EXECUTE on a new function", "CREATE FUNCTION public.{login}_more() RETURNS integer LANGUAGE sql AS 'SELECT 1'; REVOKE EXECUTE ON FUNCTION public.{login}_more() FROM PUBLIC; GRANT EXECUTE ON FUNCTION public.{login}_more() TO {login}"},
			{"EXECUTE on a new function, PostgreSQL's default to PUBLIC", "CREATE FUNCTION public.{login}_more() RETURNS integer LANGUAGE sql AS 'SELECT 1'"},
			{"EXECUTE on pg_read_file(text)", "GRANT EXECUTE ON FUNCTION pg_read_file(text) TO {login}"},
			{"SELECT on pg_authid", "GRANT SELECT ON pg_authid TO {login}"},
			{"SET on a parameter", "GRANT SET ON PARAMETER log_statement TO {login}"},
		}
		for _, entry := range cases {
			t.Run(entry.name+": ErrTooPowerful", func(t *testing.T) {
				t.Parallel()
				created := sharedServer(t).newBoard(t)
				created.server.sql(t, created.database, created.fill(entry.change))
				lease, err := take(t, created.file())
				expectTakeError(t, lease, err, database.ErrTooPowerful, created.password)
			})
		}
		t.Run("hadv_server a member of pg_read_all_data, so the login is too: ErrTooPowerful", func(t *testing.T) {
			t.Parallel()
			server := startPostgres(t, serverOptions{})
			created := server.newBoard(t)
			server.sql(t, superuser, "GRANT pg_read_all_data TO hadv_server")
			lease, err := take(t, created.file())
			expectTakeError(t, lease, err, database.ErrTooPowerful, created.password)
		})
		// hadv_server is one role for the whole server, so each attribute is given and taken back
		// in turn, on a server of this row's own, with a new board for each; the log names the
		// attribute a failure comes under.
		t.Run("hadv_server holding SUPERUSER, CREATEROLE, CREATEDB, REPLICATION, BYPASSRLS or LOGIN, each in turn: ErrTooPowerful", func(t *testing.T) {
			t.Parallel()
			server := startPostgres(t, serverOptions{})
			for _, attribute := range []string{"SUPERUSER", "CREATEROLE", "CREATEDB", "REPLICATION", "BYPASSRLS", "LOGIN"} {
				t.Logf("hadv_server given %s", attribute)
				created := server.newBoard(t)
				server.sql(t, superuser, "ALTER ROLE hadv_server "+attribute)
				lease, err := take(t, created.file())
				expectTakeError(t, lease, err, database.ErrTooPowerful, created.password)
				server.sql(t, superuser, "ALTER ROLE hadv_server NO"+attribute)
			}
		})
		t.Run("a login made as schema.sql says, holding PostgreSQL's defaults alone: taken", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			lease, err := take(t, created.file())
			expectTaken(t, lease, err, created)
		})
		t.Run("a login made as schema.sql says, its default role hadv_server: taken", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			created.server.sql(t, created.database, created.fill("ALTER ROLE {login} SET role = hadv_server"))
			lease, err := take(t, created.file())
			expectTaken(t, lease, err, created)
		})
	})

	t.Run("If the database answers that it is read-only, then Take shall return ErrReadOnly.", func(t *testing.T) {
		t.Parallel()
		t.Run("the database read-only by default: ErrReadOnly, the row unchanged", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			created.server.sql(t, superuser, "ALTER DATABASE "+created.database+" SET default_transaction_read_only = on")
			before := created.row(t)
			lease, err := take(t, created.file())
			expectTakeError(t, lease, err, database.ErrReadOnly, created.password)
			if after := created.row(t); after.holder != before.holder || !after.until.Equal(before.until) {
				t.Fatalf("the row changed from %+v to %+v", before, after)
			}
		})
		t.Run("a standby in recovery with hot standby on: ErrReadOnly", func(t *testing.T) {
			t.Parallel()
			created, standby := startStandby(t, true)
			contents := created.file()
			contents.Port = standby.port
			lease, err := take(t, contents)
			expectTakeError(t, lease, err, database.ErrReadOnly, created.password)
		})
	})

	t.Run("If hadv.schema_version is missing, holds no row, holds anything but one integer, or holds a version other than SchemaVersionMadeFor and the next, then Take shall return a *SchemaVersionError naming the version found, or Missing.", func(t *testing.T) {
		t.Parallel()
		missing := map[string]string{
			"the table dropped":              "DROP TABLE hadv.schema_version",
			"its row deleted":                "DELETE FROM hadv.schema_version",
			"the version NULL":               "ALTER TABLE hadv.schema_version ALTER COLUMN version DROP NOT NULL; UPDATE hadv.schema_version SET version = NULL",
			"two rows":                       "DROP INDEX hadv.schema_version_one_row; INSERT INTO hadv.schema_version VALUES (1)",
			"the version a text holding abc": "ALTER TABLE hadv.schema_version ALTER COLUMN version TYPE text; UPDATE hadv.schema_version SET version = 'abc'",
			"the version column dropped":     "ALTER TABLE hadv.schema_version DROP COLUMN version",
		}
		for name, change := range missing {
			t.Run(name+": a *SchemaVersionError, Missing", func(t *testing.T) {
				t.Parallel()
				created := sharedServer(t).newBoard(t)
				created.sqlAsOwner(t, change)
				lease, err := take(t, created.file())
				expectTakeError(t, lease, err, database.ErrSchemaVersion, created.password)
				var found *database.SchemaVersionError
				if !errors.As(err, &found) || !found.Missing {
					t.Fatalf("the error is %#v, want a *SchemaVersionError with Missing set", err)
				}
			})
		}
		for _, version := range []int32{0, 3, 7, -1} {
			t.Run(fmt.Sprintf("version %d: a *SchemaVersionError naming %d", version, version), func(t *testing.T) {
				t.Parallel()
				created := sharedServer(t).newBoard(t)
				created.sqlAsOwner(t, fmt.Sprintf("UPDATE hadv.schema_version SET version = %d", version))
				lease, err := take(t, created.file())
				expectTakeError(t, lease, err, database.ErrSchemaVersion, created.password)
				var found *database.SchemaVersionError
				if !errors.As(err, &found) || found.Missing || found.Found != version {
					t.Fatalf("the error is %#v, want a *SchemaVersionError naming %d", err, version)
				}
			})
		}
		for _, version := range []int{versionMadeFor, versionMadeFor + 1} {
			t.Run(fmt.Sprintf("version %d: taken", version), func(t *testing.T) {
				t.Parallel()
				created := sharedServer(t).newBoard(t)
				created.sqlAsOwner(t, fmt.Sprintf("UPDATE hadv.schema_version SET version = %d", version))
				lease, err := take(t, created.file())
				expectTaken(t, lease, err, created)
			})
		}
	})

	t.Run("If hadv.servers holds no row for the ConnectionFile's server ID, then Take shall return ErrNoServerRow.", func(t *testing.T) {
		t.Parallel()
		t.Run("a server ID with no row: ErrNoServerRow", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			contents := created.file()
			contents.ServerID = created.serverID + 1000
			lease, err := take(t, contents)
			expectTakeError(t, lease, err, database.ErrNoServerRow, created.password)
		})
	})

	t.Run("When the server's row's lease has ended, or its lease holder is the one this ServerDatabase last sent, Take shall write a new random lease holder and a lease end LeaseSeconds after the database's current time to that row, and return the Lease.", func(t *testing.T) {
		t.Parallel()
		t.Run("a lease never held: a new holder, its end 30 s after the database's time", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			lease, err := take(t, created.file())
			found := expectTaken(t, lease, err, created)
			changes := created.updates(t)
			if len(changes) != 1 || changes[0].oldHolder != "" || changes[0].newHolder != found.holder {
				t.Fatalf("the take's updates were %+v, want one writing the holder %s", changes, found.holder)
			}
			expectExactEnd(t, changes[0], leaseLength)
		})
		t.Run("a lease another run held that ended a second ago: taken, a new holder", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			foreign := foreignHolder
			created.setRow(t, foreign, "now() - interval '1 second'")
			lease, err := take(t, created.file())
			if found := expectTaken(t, lease, err, created); found.holder == foreign {
				t.Fatalf("the take kept the other run's holder")
			}
		})
		t.Run("taken, ended, taken again by the same ServerDatabase: two different holders", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			made := serverDatabase(t, created.file())
			first, err := takeWith(t, made)
			firstHolder := expectTaken(t, first, err, created).holder
			first.EndLease()
			second, err := takeWith(t, made)
			if secondHolder := expectTaken(t, second, err, created).holder; secondHolder == firstHolder {
				t.Fatalf("both takes wrote the holder %s", firstHolder)
			}
		})
	})

	t.Run("If the lease has not ended and its holder is not the one this ServerDatabase last sent, then Take shall return ErrLeaseHeld and change nothing.", func(t *testing.T) {
		t.Parallel()
		t.Run("another run's holder, its end an hour on: ErrLeaseHeld, the row unchanged, no update", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			created.setRow(t, foreignHolder, "now() + interval '1 hour'")
			before := created.row(t)
			updatesBefore := len(created.updates(t))
			lease, err := take(t, created.file())
			expectTakeError(t, lease, err, database.ErrLeaseHeld, created.password)
			after := created.row(t)
			if after.holder != before.holder || !after.until.Equal(before.until) || len(created.updates(t)) != updatesBefore {
				t.Fatalf("the row changed from %+v to %+v", before, after)
			}
		})
		t.Run("a lease taken by one ServerDatabase, then Take by a second made from the same file: ErrLeaseHeld", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			lease, err := take(t, created.file())
			held := expectTaken(t, lease, err, created)
			second, err := take(t, created.file())
			expectTakeError(t, second, err, database.ErrLeaseHeld, created.password)
			if after := created.row(t); after.holder != held.holder {
				t.Fatalf("the second Take changed the holder from %s to %s", held.holder, after.holder)
			}
		})
	})

	t.Run("If the database refuses for any reason the lines above do not name, then Take shall return ErrRefused.", func(t *testing.T) {
		t.Parallel()
		t.Run("a database that does not exist: ErrRefused", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			contents := created.file()
			contents.Database = "nowhere_" + strconv.FormatInt(time.Now().UnixNano(), 10)
			lease, err := take(t, contents)
			expectTakeError(t, lease, err, database.ErrRefused, created.password)
		})
		t.Run("the right to connect taken away: ErrRefused", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			created.server.sql(t, superuser, "REVOKE CONNECT ON DATABASE "+created.database+" FROM PUBLIC")
			lease, err := take(t, created.file())
			expectTakeError(t, lease, err, database.ErrRefused, created.password)
		})
		t.Run("the right to read hadv.schema_version taken away: ErrRefused, not a *SchemaVersionError", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			created.sqlAsOwner(t, "REVOKE SELECT ON hadv.schema_version FROM hadv_server")
			lease, err := take(t, created.file())
			expectTakeError(t, lease, err, database.ErrRefused, created.password)
		})
		t.Run("a fake refusing with an internal error holding the canary: ErrRefused, its text without the message", func(t *testing.T) {
			t.Parallel()
			server := startFake(t, false, func(t *testing.T, connection *fakeConnection) {
				t.Helper()
				connection.send(t, 'E', errorBody("XX000", "internal error "+canary))
				connection.awaitEnd(time.Now().Add(tryLimit))
			})
			lease, err := take(t, server.file())
			expectTakeError(t, lease, err, database.ErrRefused, "password-"+canary)
		})
	})

	t.Run("Take shall make the checks in the order of the lines below, and return the first failure; until it has signed in, the first failure is the one the connection meets first.", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name   string
			change string
			wrong  bool
			want   error
		}{
			{"too powerful and read-only: ErrTooPowerful", "ALTER ROLE {login} CREATEDB; ALTER DATABASE {database} SET default_transaction_read_only = on", false, database.ErrTooPowerful},
			{"read-only and version 7: ErrReadOnly", "UPDATE hadv.schema_version SET version = 7; ALTER DATABASE {database} SET default_transaction_read_only = on", false, database.ErrReadOnly},
			{"version 7 and no row: a *SchemaVersionError", "UPDATE hadv.schema_version SET version = 7", true, database.ErrSchemaVersion},
			{"no row, its lease held by another run on the row there is: ErrNoServerRow", "UPDATE hadv.servers SET lease_holder = '" + foreignHolder + "', lease_until = now() + interval '1 hour'", true, database.ErrNoServerRow},
		}
		for _, entry := range cases {
			t.Run(entry.name, func(t *testing.T) {
				t.Parallel()
				created := sharedServer(t).newBoard(t)
				created.server.sql(t, created.database, created.fill(entry.change))
				contents := created.file()
				if entry.wrong {
					contents.ServerID = created.serverID + 1000
				}
				lease, err := take(t, contents)
				expectTakeError(t, lease, err, entry.want, created.password)
			})
		}
	})

	t.Run("If the context has ended when Take is called, or ends while it waits, then Take shall return the context's error, wrapped.", func(t *testing.T) {
		t.Parallel()
		t.Run("ended before the call: the context's error, and nothing dialed", func(t *testing.T) {
			t.Parallel()
			server := startFake(t, true, nil)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			lease, err := serverDatabase(t, server.file()).Take(ctx)
			expectContextError(t, lease, err, context.Canceled)
			pause(t, waitForNoDial)
			if count := server.dialCount(); count != 0 {
				t.Fatalf("Take dialed %d times with its context ended", count)
			}
		})
		t.Run("cancelled half a second into a fake that never answers: the context's error, at once", func(t *testing.T) {
			t.Parallel()
			server := startFake(t, false, func(_ *testing.T, connection *fakeConnection) {
				connection.awaitEnd(time.Now().Add(takeLimit))
			})
			ctx, cancel := context.WithCancel(t.Context())
			cancelled := time.Now().Add(500 * time.Millisecond)
			timer := time.AfterFunc(time.Until(cancelled), cancel)
			defer timer.Stop()
			lease, err := serverDatabase(t, server.file()).Take(ctx)
			expectWithin(t, "Take's return", time.Now(), cancelled, cancelled.Add(timingMargin))
			expectContextError(t, lease, err, context.Canceled)
		})
		t.Run("a deadline of a second into a fake that never answers: the context's error, at the deadline", func(t *testing.T) {
			t.Parallel()
			server := startFake(t, false, func(_ *testing.T, connection *fakeConnection) {
				connection.awaitEnd(time.Now().Add(takeLimit))
			})
			deadline := time.Now().Add(time.Second)
			ctx, cancel := context.WithDeadline(t.Context(), deadline)
			defer cancel()
			lease, err := serverDatabase(t, server.file()).Take(ctx)
			expectWithin(t, "Take's return", time.Now(), deadline, deadline.Add(timingMargin))
			expectContextError(t, lease, err, context.DeadlineExceeded)
		})
	})
}

// expectContextError checks Take returned no Lease and the context's error, matching none of
// Take's own.
func expectContextError(t *testing.T, lease *database.Lease, err, want error) {
	t.Helper()
	if lease != nil {
		lease.EndLease()
		t.Fatalf("Take returned a Lease with its context ended")
	}
	if !errors.Is(err, want) {
		t.Fatalf("Take returned %v, want the context's error %v", err, want)
	}
	for _, other := range takeErrors {
		if errors.Is(err, other) {
			t.Fatalf("the error %v matches %v as well as the context's", err, other)
		}
	}
}

// waitForLog waits until the server's log holds text.
func waitForLog(t *testing.T, server *postgres, text string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(server.log(t), text) {
		if time.Now().After(deadline) {
			t.Fatalf("the server's log did not show %q within 30 s:\n%s", text, server.log(t))
		}
		pause(t, 50*time.Millisecond)
	}
}
