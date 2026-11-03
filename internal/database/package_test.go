// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The package's own lines: the bound on each reply from the database, what an error's text may
// hold, and that the connection file alone says where to connect and as whom, whatever
// PostgreSQL's own environment variables, password file and service file say.
package database_test

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/database"
)

func TestPackage(t *testing.T) {
	t.Parallel()

	t.Run("If a message from the database is longer than ReplyMostBytes, then the database package shall treat the connection as failed, ErrUnreachable at a take, without reading the rest.", func(t *testing.T) {
		t.Parallel()
		t.Run("an error whose length says 2 MiB, 64 KiB of it sent and the rest held: ErrUnreachable at once, and the client closes", func(t *testing.T) {
			t.Parallel()
			sent := make(chan time.Time, 1)
			closed := make(chan time.Time, 1)
			server := startFake(t, false, func(t *testing.T, connection *fakeConnection) {
				t.Helper()
				header := []byte{'E', 0, 0, 0, 0}
				binary.BigEndian.PutUint32(header[1:], 2*replyMostBytes)
				body := errorBody("28P01", strings.Repeat("x", 64<<10))
				// The window opens as the write begins: a client that reads the header and closes
				// at once can return before the write does.
				began := time.Now()
				if _, err := connection.connection.Write(append(header, body...)); err != nil {
					t.Logf("the fake's write failed: %v", err)
				}
				sent <- began
				closed <- connection.awaitEnd(time.Now().Add(takeLimit))
			})
			lease, err := take(t, server.file())
			returned := time.Now()
			expectTakeError(t, lease, err, database.ErrUnreachable, "password-"+canary)
			sentAt := <-sent
			expectWithin(t, "Take's return", returned, sentAt, sentAt.Add(timingMargin))
			if end := <-closed; end.IsZero() {
				t.Fatalf("the client kept the connection open")
			} else {
				expectWithin(t, "the client's close", end, sentAt, sentAt.Add(timingMargin))
			}
		})
		t.Run("a refusal of 1 MiB less 64 bytes, inside the bound: read, ErrSignInRefused", func(t *testing.T) {
			t.Parallel()
			server := startFake(t, false, func(t *testing.T, connection *fakeConnection) {
				t.Helper()
				padding := replyMostBytes - 64 - 5 - len(errorBody("28P01", ""))
				connection.send(t, 'E', errorBody("28P01", strings.Repeat("x", padding)))
				connection.awaitEnd(time.Now().Add(tryLimit))
			})
			lease, err := take(t, server.file())
			expectTakeError(t, lease, err, database.ErrSignInRefused, "password-"+canary)
		})
		// A message's length may be read as its body, its length field (the body and 4) or the
		// whole (the body and 5); these two rows are past or inside the bound by every reading.
		t.Run("a refusal whose body is 1 MiB and 1 byte, sent whole, past the bound however a message is counted: ErrUnreachable at once", func(t *testing.T) {
			t.Parallel()
			sent := make(chan time.Time, 1)
			server := startFake(t, false, func(t *testing.T, connection *fakeConnection) {
				t.Helper()
				padding := replyMostBytes + 1 - len(errorBody("28P01", ""))
				sent <- time.Now()
				connection.send(t, 'E', errorBody("28P01", strings.Repeat("x", padding)))
				connection.awaitEnd(time.Now().Add(tryLimit))
			})
			lease, err := take(t, server.file())
			returned := time.Now()
			expectTakeError(t, lease, err, database.ErrUnreachable, "password-"+canary)
			sentAt := <-sent
			expectWithin(t, "Take's return", returned, sentAt, sentAt.Add(timingMargin))
		})
		t.Run("a refusal of exactly 1 MiB with its type and length, inside the bound however a message is counted: read, ErrSignInRefused", func(t *testing.T) {
			t.Parallel()
			server := startFake(t, false, func(t *testing.T, connection *fakeConnection) {
				t.Helper()
				padding := replyMostBytes - 5 - len(errorBody("28P01", ""))
				connection.send(t, 'E', errorBody("28P01", strings.Repeat("x", padding)))
				connection.awaitEnd(time.Now().Add(tryLimit))
			})
			lease, err := take(t, server.file())
			expectTakeError(t, lease, err, database.ErrSignInRefused, "password-"+canary)
		})
	})

	t.Run("No error the database package returns shall hold, in its text, the connection file's password or any text the database sent.", func(t *testing.T) {
		t.Parallel()
		for _, entry := range []struct {
			code string
			want error
		}{
			{"28P01", database.ErrSignInRefused},
			{"57P03", database.ErrNotReady},
			{"53300", database.ErrNoConnectionFree},
			{"XX000", database.ErrRefused},
		} {
			t.Run("a fake refusing with "+entry.code+", its message holding the canary: the error's text holds neither it nor the password", func(t *testing.T) {
				t.Parallel()
				server := startFake(t, false, func(t *testing.T, connection *fakeConnection) {
					t.Helper()
					connection.send(t, 'E', errorBody(entry.code, "the database says "+canary))
					connection.awaitEnd(time.Now().Add(tryLimit))
				})
				lease, err := take(t, server.file())
				expectTakeError(t, lease, err, entry.want, "password-"+canary)
			})
		}
		t.Run("a real refusal of the sign-in, the password holding the canary: the error's text holds neither", func(t *testing.T) {
			t.Parallel()
			created := sharedServer(t).newBoard(t)
			contents := created.file()
			contents.Password = "wrong-" + canary
			started := time.Now()
			// Windows lost the server's refusal on this row once: a failure shows the log.
			defer func() { showLogIfFailed(t, created.server, &contents.Login, started) }()
			lease, err := take(t, contents)
			expectTakeError(t, lease, err, database.ErrSignInRefused, contents.Password)
		})
	})
}

// TestFileAlone sets PostgreSQL's own environment variables in this process, which no test may do
// while another runs, so it and its rows run before the parallel tests resume.
func TestFileAlone(t *testing.T) {
	t.Run("The database package shall take where it connects, its login and its password from the ConnectionFile alone, whatever PostgreSQL's environment variables, password file or service file give.", func(t *testing.T) {
		t.Run("every variable, a password file and a service file naming a decoy board: the file's board is taken, the decoy left alone", func(t *testing.T) { //nolint:paralleltest // it sets the process's environment, through setDecoyEnvironment
			created := sharedServer(t).newBoard(t)
			decoy := sharedServer(t).newBoard(t)
			setDecoyEnvironment(t, decoy)
			lease, err := take(t, created.file())
			expectTaken(t, lease, err, created)
			if changes := decoy.updates(t); len(changes) != 0 {
				t.Fatalf("the decoy board's row was updated: %+v", changes)
			}
			if decoy.server.signedIn(t, decoy.login) {
				t.Fatalf("the decoy login signed in")
			}
		})
		t.Run("a service and a client certificate that cannot be found: the file's board is taken", func(t *testing.T) {
			created := sharedServer(t).newBoard(t)
			missing := filepath.Join(t.TempDir(), "missing")
			t.Setenv("PGSERVICEFILE", missing)
			t.Setenv("PGSERVICE", "nowhere")
			t.Setenv("PGSSLCERT", missing+".crt")
			t.Setenv("PGSSLKEY", missing+".key")
			lease, err := take(t, created.file())
			expectTaken(t, lease, err, created)
		})
	})
}

// setDecoyEnvironment points every one of PostgreSQL's variables the library reads at the decoy
// board, or at a setting that would break the file's sign-in, for the rest of the row.
func setDecoyEnvironment(t *testing.T, decoy *board) {
	t.Helper()
	directory := t.TempDir()
	serviceFile := filepath.Join(directory, "pg_service.conf")
	service := "[decoy]\nhost=" + databaseHost + "\nport=" + strconv.Itoa(decoy.server.port) + "\ndbname=" + decoy.database +
		"\nuser=" + decoy.login + "\npassword=" + decoy.password + "\nsslmode=disable\noptions=-c default_transaction_read_only=on\n"
	passwordFile := filepath.Join(directory, "pgpass")
	passwords := "*:*:*:*:wrong-" + canary + "\n"
	rootFile := filepath.Join(directory, "root.crt")
	for path, text := range map[string]string{serviceFile: service, passwordFile: passwords, rootFile: newAuthority(t).pemText} {
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
	}
	for name, value := range map[string]string{
		"PGHOST":               databaseHost,
		"PGHOSTADDR":           databaseHost,
		"PGPORT":               strconv.Itoa(decoy.server.port),
		"PGDATABASE":           decoy.database,
		"PGUSER":               decoy.login,
		"PGPASSWORD":           decoy.password,
		"PGPASSFILE":           passwordFile,
		"PGSERVICEFILE":        serviceFile,
		"PGSERVICE":            "decoy",
		"PGSSLMODE":            "disable",
		"PGSSLROOTCERT":        rootFile,
		"PGOPTIONS":            "-c default_transaction_read_only=on",
		"PGAPPNAME":            "decoy-" + canary,
		"PGCONNECT_TIMEOUT":    "1",
		"PGTARGETSESSIONATTRS": "standby",
		"PGREQUIREAUTH":        "password",
		"PGCHANNELBINDING":     "disable",
		"PGTZ":                 "Pacific/Chatham",
	} {
		t.Setenv(name, value)
	}
}
