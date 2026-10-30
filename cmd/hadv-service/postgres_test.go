// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The program's database: a real PostgreSQL, made by the tests themselves from its own programs
// (initdb, pg_ctl, psql and pg_basebackup) in temporary folders, as the ordinary user running
// them. Each server listens at 127.0.0.1 alone, with TLS on and a certificate signed by a
// certificate authority the test makes, ECDSA P-256 with SHA-256. A board is made on a server as
// hadv-setup will make one: an owner, its database, schema.sql run as the owner, a server's
// login that is a member of hadv_server alone, a row per run of the program and its connection
// file. Every run of the program that is not about the database gets a row of its own on one
// board the package shares. The tests read and change the server as its superuser through psql.
package main_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The option that names the connection file, the superuser the tests set a server up as, and
// the one address every server listens at.
const (
	databaseOption = "-database"
	superuser      = "postgres"
	databaseHost   = "127.0.0.1"
)

// toolLimit bounds each run of one of PostgreSQL's programs, so a hung one fails its row. It is
// not the test's context, which has ended by the time a cleanup stops a server.
const toolLimit = 2 * time.Minute

// The template cluster, made by initdb once in TestMain: each server is a copy of it. shared is
// the server rows share when they change nothing beyond their own board and login, and
// sharedBoard the board on it whose rows the program's other rows run on.
var (
	templateDirectory string
	templatePassword  string
	shared            *postgres
	sharedBoard       *board
	oracleFailure     error
)

// prepareOracle makes the template cluster, the shared server and the shared board.
func prepareOracle() error {
	directory, err := os.MkdirTemp("", "hadv-postgres-template-")
	if err != nil {
		return err
	}
	templateDirectory = directory
	templatePassword, err = randomText(16)
	if err != nil {
		return err
	}
	passwordFile := filepath.Join(directory, "password")
	if err := os.WriteFile(passwordFile, []byte(templatePassword+"\n"), 0o600); err != nil {
		return err
	}
	output, err := runTool(cleanEnvironment(), "initdb", "-D", filepath.Join(directory, "data"), "-U", superuser,
		"--pwfile="+passwordFile, "--auth=scram-sha-256", "-E", "UTF8", "--locale=C", "--no-sync")
	if err != nil {
		return fmt.Errorf("initdb: %w: %s", err, output)
	}
	sharedDirectory, err := os.MkdirTemp("", "hadv-postgres-shared-")
	if err != nil {
		return err
	}
	shared, err = launchPostgres(sharedDirectory, serverOptions{})
	if err != nil {
		return err
	}
	sharedBoard, err = shared.makeBoard()
	return err
}

// removeOracle stops the shared server and removes it and the template.
func removeOracle() {
	if shared != nil {
		_, _ = shared.pgctl("stop", "-m", "immediate", "-w", "-t", "60")
		_ = os.RemoveAll(shared.directory)
	}
	if templateDirectory != "" {
		_ = os.RemoveAll(templateDirectory)
	}
}

// cleanEnvironment is this process's environment without any of PostgreSQL's own variables, so a
// program the tests start is told everything on its command line. Windows runners set PGDATA and
// others.
func cleanEnvironment(extra ...string) []string {
	var environment []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(entry), "PG") {
			environment = append(environment, entry)
		}
	}
	return append(environment, extra...)
}

// runTool runs one of PostgreSQL's programs and returns what it printed. Its output goes to a
// file, not a pipe: the server pg_ctl starts inherits its handles, and would hold a pipe open.
func runTool(environment []string, name string, arguments ...string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("PostgreSQL's %s is not on the PATH, so the oracle cannot run: %w", name, err)
	}
	suffix, err := randomText(8)
	if err != nil {
		return "", err
	}
	outputPath := filepath.Join(os.TempDir(), "hadv-postgres-output-"+suffix)
	output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = output.Close()
		_ = os.Remove(outputPath)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), toolLimit)
	defer cancel()
	command := exec.CommandContext(ctx, path, arguments...)
	command.Env = environment
	command.Stdout = output
	command.Stderr = output
	runErr := command.Run()
	text, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		return "", readErr
	}
	return strings.TrimSpace(strings.ReplaceAll(string(text), "\r\n", "\n")), runErr
}

func randomText(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// nameCounter makes the names of roles and databases unique across a run.
var nameCounter atomic.Int64

func uniqueName(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, nameCounter.Add(1))
}

// authority is a certificate authority the tests make, which signs the database's certificate.
type authority struct {
	certificate *x509.Certificate
	key         crypto.Signer
	pemText     string
}

// makeAuthority makes a certificate authority signing with ECDSA P-256 and SHA-256.
func makeAuthority() (*authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	name, err := randomText(4)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "Helios test authority " + name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &authority{certificate: certificate, key: key,
		pemText: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}, nil
}

// issue signs a certificate for the database naming 127.0.0.1, and returns it and its key, as
// PEM.
func (signer *authority) issue() (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "Helios test database"},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP(databaseHost)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer.certificate, key.Public(), signer.key)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), nil
}

// postgres is one server.
type postgres struct {
	directory string
	data      string
	port      int
	password  string
	authority *authority
	logPath   string
	// mutex keeps rows that change the sign-in rules or the settings from writing at once.
	mutex    sync.Mutex
	hbaExtra []string
	settings []string
}

// serverOptions are settings added to a server's postgresql.conf.
type serverOptions struct {
	settings []string
}

// startPostgres makes a server of the row's own and starts it, stopped when the row ends.
func startPostgres(t *testing.T, options serverOptions) *postgres {
	t.Helper()
	if oracleFailure != nil {
		t.Fatalf("the oracle could not be prepared: %v", oracleFailure)
	}
	server, err := launchPostgres(t.TempDir(), options)
	if server != nil {
		t.Cleanup(func() {
			_, _ = server.pgctl("stop", "-m", "immediate", "-w", "-t", "60")
		})
	}
	if err != nil {
		t.Fatalf("starting PostgreSQL: %v", err)
	}
	return server
}

// sharedServer is the server rows share.
func sharedServer(t *testing.T) *postgres {
	t.Helper()
	if oracleFailure != nil {
		t.Fatalf("the oracle could not be prepared: %v", oracleFailure)
	}
	return shared
}

// launchPostgres copies the template into directory, gives it a certificate, its settings and
// sign-in rules, starts it on a free port, and makes the role hadv_server, which schema.sql needs.
func launchPostgres(directory string, options serverOptions) (*postgres, error) {
	data := filepath.Join(directory, "data")
	// PostgreSQL refuses a data folder others may read; the copy keeps the folder's own mode.
	if err := os.Mkdir(data, 0o700); err != nil {
		return nil, err
	}
	if err := os.CopyFS(data, os.DirFS(filepath.Join(templateDirectory, "data"))); err != nil {
		return nil, err
	}
	signer, err := makeAuthority()
	if err != nil {
		return nil, err
	}
	server := &postgres{directory: directory, data: data, password: templatePassword, authority: signer,
		logPath: filepath.Join(directory, "server.log")}
	certificate, key, err := signer.issue()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(data, "server.crt"), []byte(certificate), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(data, "server.key"), []byte(key), 0o600); err != nil {
		return nil, err
	}
	if err := server.writeHBA(); err != nil {
		return nil, err
	}
	for try := 0; ; try++ {
		port, err := freePort()
		if err != nil {
			return nil, err
		}
		server.port = port
		server.settings = append([]string{
			"listen_addresses = '" + databaseHost + "'",
			"port = " + strconv.Itoa(port),
			"unix_socket_directories = ''",
			"ssl = on",
			"ssl_cert_file = 'server.crt'",
			"ssl_key_file = 'server.key'",
			"log_connections = on",
			"log_disconnections = on",
			"log_line_prefix = '%m [%p] %u@%d '",
			"log_timezone = 'UTC'",
			"fsync = off",
			"max_connections = 300",
		}, options.settings...)
		if err := server.writeSettings(); err != nil {
			return nil, err
		}
		output, err := server.pgctl("start", "-w", "-t", "60", "-l", server.logPath)
		if err == nil {
			break
		}
		log := readText(server.logPath)
		if try < 5 && strings.Contains(log, "could not bind") {
			continue
		}
		return server, fmt.Errorf("pg_ctl start: %w: %s\n%s", err, output, log)
	}
	if output, err := server.trySQL(superuser, "CREATE ROLE hadv_server NOLOGIN"); err != nil {
		return server, fmt.Errorf("making hadv_server: %w: %s", err, output)
	}
	return server, nil
}

// startStandby makes a primary with a board on it, then a standby copied from the primary by
// pg_basebackup and following it, in recovery with hot standby off, so it answers that it is
// recovering. It returns the board and the standby, both stopped when the row ends. The copy asks
// for its checkpoint at once: the default spreads it out, which can outlast the tools' limit on a
// busy machine.
func startStandby(t *testing.T) (*board, *postgres) {
	t.Helper()
	primary := startPostgres(t, serverOptions{settings: []string{"wal_level = replica", "max_wal_senders = 4"}})
	created := primary.newBoard(t)
	directory := t.TempDir()
	standby := &postgres{directory: directory, data: filepath.Join(directory, "data"), password: primary.password,
		authority: primary.authority, logPath: filepath.Join(directory, "server.log")}
	if output, err := runTool(primary.superuserEnvironment(), "pg_basebackup", "-h", databaseHost,
		"-p", strconv.Itoa(primary.port), "-U", superuser, "-D", standby.data, "-R", "-X", "stream", "--checkpoint=fast", "--no-sync"); err != nil {
		t.Fatalf("pg_basebackup: %v: %s", err, output)
	}
	t.Cleanup(func() {
		_, _ = standby.pgctl("stop", "-m", "immediate", "-w", "-t", "60")
	})
	for try := 0; try < 5; try++ {
		port, err := freePort()
		if err != nil {
			t.Fatalf("finding a free port: %v", err)
		}
		standby.port = port
		standby.settings = append(append([]string{}, primary.settings...), "port = "+strconv.Itoa(port), "hot_standby = off")
		if err := standby.writeSettings(); err != nil {
			t.Fatalf("writing the standby's settings: %v", err)
		}
		// With hot standby off the server accepts no connection, so pg_ctl cannot wait for it;
		// the standby's log shows when it has started.
		if output, err := standby.pgctl("start", "-W", "-l", standby.logPath); err != nil {
			t.Fatalf("starting the standby: %v: %s", err, output)
		}
		deadline := time.Now().Add(60 * time.Second)
		for {
			text := readText(standby.logPath)
			if strings.Contains(text, "started streaming WAL") {
				return created, standby
			}
			if strings.Contains(text, "could not bind") {
				_, _ = standby.pgctl("stop", "-m", "immediate", "-w", "-t", "60")
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the standby did not start streaming within 60 s:\n%s", text)
			}
			pause(t, 100*time.Millisecond)
		}
	}
	t.Fatalf("the standby found no free port in 5 tries")
	return nil, nil
}

// freePort finds a port nothing listens on at 127.0.0.1.
func freePort() (int, error) {
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", databaseHost+":0")
	if err != nil {
		return 0, err
	}
	address, isTCP := listener.Addr().(*net.TCPAddr)
	_ = listener.Close()
	if !isTCP {
		return 0, fmt.Errorf("the listener's address is a %T", listener.Addr())
	}
	return address.Port, nil
}

// readText reads a file a row only shows, such as a server's log, or says why it could not.
func readText(path string) string {
	text, err := os.ReadFile(path)
	if err != nil {
		return "(" + path + " could not be read: " + err.Error() + ")"
	}
	return string(text)
}

func (server *postgres) pgctl(arguments ...string) (string, error) {
	return runTool(cleanEnvironment(), "pg_ctl", append(arguments, "-D", server.data)...)
}

// control runs pg_ctl for a row, failing it when pg_ctl fails.
func (server *postgres) control(t *testing.T, arguments ...string) {
	t.Helper()
	if output, err := server.pgctl(arguments...); err != nil {
		t.Fatalf("pg_ctl %s: %v: %s", strings.Join(arguments, " "), err, output)
	}
}

// writeSettings writes the tests' settings at the end of postgresql.conf.
func (server *postgres) writeSettings() error {
	path := filepath.Join(server.data, "postgresql.conf")
	text, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	base, _, _ := strings.Cut(string(text), "# The tests' settings\n")
	return os.WriteFile(path, []byte(base+"# The tests' settings\n"+strings.Join(server.settings, "\n")+"\n"), 0o600)
}

// writeHBA writes the sign-in rules: the superuser by SCRAM with or without TLS, and replication
// for it, then the rows' own rules, then every other login by SCRAM over TLS alone.
func (server *postgres) writeHBA() error {
	lines := []string{
		"host all " + superuser + " " + databaseHost + "/32 scram-sha-256",
		"host replication " + superuser + " " + databaseHost + "/32 scram-sha-256",
	}
	lines = append(lines, server.hbaExtra...)
	lines = append(lines, "hostssl all all "+databaseHost+"/32 scram-sha-256")
	return replaceFile(filepath.Join(server.data, "pg_hba.conf"), []byte(strings.Join(lines, "\n")+"\n"))
}

// replaceFile puts the new contents in place whole. On Windows each new connection reads
// pg_hba.conf again, and one that reads it while it is written in place is refused with "could not
// load pg_hba.conf"; a rename gives it the old file or the new one. The rename is tried again for a
// while, since Windows refused one now and then while connections were being made.
func replaceFile(path string, contents []byte) error {
	temporary := path + ".new"
	if err := os.WriteFile(temporary, contents, 0o600); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := os.Rename(temporary, path)
		if err == nil || time.Now().After(deadline) {
			return err
		}
		timer := time.NewTimer(20 * time.Millisecond)
		<-timer.C
	}
}

// signInRule puts a sign-in rule for one login ahead of the others, reloads the server, and waits
// until the server has read it.
func (server *postgres) signInRule(t *testing.T, login, method string) {
	t.Helper()
	server.mutex.Lock()
	server.hbaExtra = append(server.hbaExtra, "hostssl all "+login+" "+databaseHost+"/32 "+method)
	err := server.writeHBA()
	server.mutex.Unlock()
	if err != nil {
		t.Fatalf("writing pg_hba.conf: %v", err)
	}
	server.sql(t, superuser, "SELECT pg_reload_conf()")
	deadline := time.Now().Add(30 * time.Second)
	for server.sql(t, superuser, "SELECT count(*) FROM pg_hba_file_rules WHERE "+quoteLiteral(login)+" = ANY(user_name)") != "1" {
		if time.Now().After(deadline) {
			t.Fatalf("the server did not read the sign-in rule for %s", login)
		}
		pause(t, 50*time.Millisecond)
	}
}

// sql runs statements as the superuser in a database, one psql call, and returns what psql
// printed: unaligned, without headers, a row a line, fields split by |.
func (server *postgres) sql(t *testing.T, database string, statements ...string) string {
	t.Helper()
	output, err := server.trySQL(database, statements...)
	if err != nil {
		t.Fatalf("psql: %v: %s", err, output)
	}
	return output
}

func (server *postgres) trySQL(database string, statements ...string) (string, error) {
	arguments := []string{"-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-h", databaseHost,
		"-p", strconv.Itoa(server.port), "-U", superuser, "-d", database}
	for _, statement := range statements {
		arguments = append(arguments, "-c", statement)
	}
	return runTool(server.superuserEnvironment(), "psql", arguments...)
}

func (server *postgres) superuserEnvironment() []string {
	return cleanEnvironment("PGPASSWORD="+server.password, "PGSSLMODE=disable", "PGCONNECT_TIMEOUT=10")
}

// serverLog returns what the server has logged so far.
func (server *postgres) serverLog(t *testing.T) string {
	t.Helper()
	text, err := os.ReadFile(server.logPath)
	if err != nil {
		t.Fatalf("reading the server's log: %v", err)
	}
	return string(text)
}

// tryPrefix is how a log entry of one login's begins: its time, its process, the login and the
// database, as the settings' log_line_prefix writes them.
var tryPrefix = regexp.MustCompile(`^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}) UTC \[\d+\] (\S*)@\S* (\S+):`)

// triesBy returns when each of the login's tries to sign in ended, as the server logged it: its
// sign-in authorized, or refused with a FATAL error.
func (server *postgres) triesBy(t *testing.T, login string) []time.Time {
	t.Helper()
	var tries []time.Time
	for line := range strings.SplitSeq(server.serverLog(t), "\n") {
		match := tryPrefix.FindStringSubmatch(line)
		if match == nil || match[2] != login || (match[3] != "FATAL" && !strings.Contains(line, "connection authorized")) {
			continue
		}
		logged, err := time.Parse("2006-01-02 15:04:05.000", match[1])
		if err != nil {
			t.Fatalf("a time in the server's log read as %q", match[1])
		}
		tries = append(tries, logged.UTC())
	}
	return tries
}

// waitForTry waits, by the deadline, for the login's first try at or after the moment given, and
// returns when the server logged it. The log's times are to the millisecond.
func (server *postgres) waitForTry(t *testing.T, login string, since, deadline time.Time) time.Time {
	t.Helper()
	for {
		for _, tried := range server.triesBy(t, login) {
			if !tried.Before(since.Truncate(time.Millisecond)) {
				return tried
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the server logged no try by %s from %v to %v:\n%s", login, since.Format(time.RFC3339Nano),
				deadline.Format(time.RFC3339Nano), server.serverLog(t))
		}
		pause(t, 100*time.Millisecond)
	}
}

// quoteLiteral writes a string as an SQL literal.
func quoteLiteral(text string) string {
	return "'" + strings.ReplaceAll(text, "'", "''") + "'"
}

// board is a board's database made on a server as hadv-setup will make it, with one row, the
// board's own; rowFile adds more.
type board struct {
	server   *postgres
	database string
	owner    string
	login    string
	password string
	serverID int64
}

// passwordCanary marks every login's password, so the local log can be searched for it.
const passwordCanary = "helios-password-canary-4417"

// schemaText is the database unit's schema.sql, read as hadv-setup will read it.
func schemaText() (string, error) {
	text, err := os.ReadFile(filepath.Join("..", "..", "internal", "database", "schema.sql"))
	return string(text), err
}

// newBoard makes a board of the row's own on the server.
func (server *postgres) newBoard(t *testing.T) *board {
	t.Helper()
	created, err := server.makeBoard()
	if err != nil {
		t.Fatalf("making a board: %v", err)
	}
	return created
}

// makeBoard makes an owner, a database it owns, the schema run as the owner, a login that is a
// member of hadv_server alone, and a row, its lease ended an hour ago and never held. It adds the
// tests' record of every update to hadv.servers: a trigger run with its owner's rights, writing
// into a schema the login has no right on, so the login holds nothing it would not hold without
// it but USAGE on the record's row type, which the contract does not count.
func (server *postgres) makeBoard() (*board, error) {
	suffix, err := randomText(12)
	if err != nil {
		return nil, err
	}
	created := &board{server: server, database: uniqueName("board"), owner: uniqueName("owner"),
		login: uniqueName("server"), password: passwordCanary + "-" + suffix}
	schema, err := schemaText()
	if err != nil {
		return nil, err
	}
	steps := [][]string{
		{superuser, "CREATE ROLE " + created.owner + " NOLOGIN",
			"CREATE DATABASE " + created.database + " OWNER " + created.owner,
			"CREATE ROLE " + created.login + " LOGIN PASSWORD " + quoteLiteral(created.password) + " IN ROLE hadv_server"},
		{created.database, "SET ROLE " + created.owner + ";\n" + schema},
		{created.database, "CREATE SCHEMA qa_audit",
			`CREATE TABLE qa_audit.updates (
				recorded timestamptz NOT NULL DEFAULT clock_timestamp(),
				transaction_start timestamptz NOT NULL DEFAULT now(),
				backend text NOT NULL,
				id bigint, old_holder uuid, new_holder uuid, old_until timestamptz, new_until timestamptz)`,
			`CREATE FUNCTION qa_audit.record() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
				SET search_path = pg_catalog AS $$
			BEGIN
				INSERT INTO qa_audit.updates (backend, id, old_holder, new_holder, old_until, new_until)
					VALUES ((SELECT pid || ' started ' || backend_start FROM pg_stat_activity WHERE pid = pg_backend_pid()),
						NEW.id, OLD.lease_holder, NEW.lease_holder, OLD.lease_until, NEW.lease_until);
				RETURN NEW;
			END $$`,
			"REVOKE EXECUTE ON FUNCTION qa_audit.record() FROM PUBLIC",
			"CREATE TRIGGER qa_audit AFTER UPDATE ON hadv.servers FOR EACH ROW EXECUTE FUNCTION qa_audit.record()"},
	}
	for _, step := range steps {
		if output, err := server.trySQL(step[0], step[1:]...); err != nil {
			return nil, fmt.Errorf("%w: %s", err, output)
		}
	}
	created.serverID, err = created.addRow()
	return created, err
}

// addRow adds a row to the board, its lease ended an hour ago and never held, and returns its ID.
func (created *board) addRow() (int64, error) {
	output, err := created.server.trySQL(created.database,
		"SET ROLE "+created.owner+"; INSERT INTO hadv.servers (lease_until) VALUES (now() - interval '1 hour') RETURNING id")
	if err != nil {
		return 0, fmt.Errorf("%w: %s", err, output)
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	return strconv.ParseInt(strings.TrimSpace(lines[len(lines)-1]), 10, 64)
}

// sqlAsOwner runs statements in the board's database as its owner.
func (created *board) sqlAsOwner(t *testing.T, statements string) string {
	t.Helper()
	return created.server.sql(t, created.database, "SET ROLE "+created.owner+";\n"+statements)
}

// connectionFile is the connection file's contents, as the tests write it.
type connectionFile struct {
	ServerID      int64
	Host          string
	Port          int
	Database      string
	Login         string
	Password      string
	CACertificate string
}

// file is the board's connection file's contents, for its own row.
func (created *board) file() connectionFile {
	return connectionFile{ServerID: created.serverID, Host: databaseHost, Port: created.server.port,
		Database: created.database, Login: created.login, Password: created.password,
		CACertificate: created.server.authority.pemText}
}

// write writes the contents as a connection file only its owner may read, and returns its path.
func (contents connectionFile) write(t *testing.T) string {
	t.Helper()
	text, err := json.Marshal(map[string]any{
		"server_id": contents.ServerID, "host": contents.Host, "port": contents.Port, "database": contents.Database,
		"login": contents.Login, "password": contents.Password, "ca_certificate": contents.CACertificate,
	})
	if err != nil {
		t.Fatalf("writing the connection file's JSON: %v", err)
	}
	return writeConnectionFile(t, string(text))
}

// writeConnectionFile writes text as a connection file only its owner may read, and returns its
// path.
func writeConnectionFile(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "connection.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("writing the connection file: %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatalf("protecting the connection file: %v", err)
		}
	}
	return path
}

// sharedRowFile adds a row to the shared board for one run of the program, and returns the path
// of a connection file naming it.
func sharedRowFile(t *testing.T) string {
	t.Helper()
	if oracleFailure != nil {
		t.Fatalf("the oracle could not be prepared: %v", oracleFailure)
	}
	identifier, err := sharedBoard.addRow()
	if err != nil {
		t.Fatalf("adding a row to the shared board: %v", err)
	}
	contents := sharedBoard.file()
	contents.ServerID = identifier
	return contents.write(t)
}

// lease is the board's row as the database holds it.
type lease struct {
	holder string
	until  time.Time
}

// row reads the board's own row.
func (created *board) row(t *testing.T) lease {
	t.Helper()
	output := created.server.sql(t, created.database, fmt.Sprintf(
		"SELECT coalesce(lease_holder::text, ''), %s FROM hadv.servers WHERE id = %d", epoch("lease_until"), created.serverID))
	fields := strings.Split(output, "|")
	if len(fields) != 2 {
		t.Fatalf("the row for server %d read as %q", created.serverID, output)
	}
	return lease{holder: fields[0], until: parseEpoch(t, fields[1])}
}

// setRow writes the board's row as the owner: the holder (empty for none) and the lease's end as
// an SQL expression.
func (created *board) setRow(t *testing.T, holder, until string) {
	t.Helper()
	value := "NULL"
	if holder != "" {
		value = quoteLiteral(holder) + "::uuid"
	}
	created.sqlAsOwner(t, fmt.Sprintf("UPDATE hadv.servers SET lease_holder = %s, lease_until = %s WHERE id = %d",
		value, until, created.serverID))
}

// update is one update to the board's row, as the tests' trigger recorded it.
type update struct {
	recorded         time.Time
	transactionStart time.Time
	backend          string
	oldHolder        string
	newHolder        string
	newUntil         time.Time
}

// updates reads every update to the board's own row so far, oldest first.
func (created *board) updates(t *testing.T) []update {
	t.Helper()
	output := created.server.sql(t, created.database, fmt.Sprintf(
		"SELECT %s, %s, backend, coalesce(old_holder::text, ''), coalesce(new_holder::text, ''), %s"+
			" FROM qa_audit.updates WHERE id = %d ORDER BY recorded",
		epoch("recorded"), epoch("transaction_start"), epoch("new_until"), created.serverID))
	var found []update
	for line := range strings.SplitSeq(output, "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) != 6 {
			t.Fatalf("an update read as %q", line)
		}
		found = append(found, update{recorded: parseEpoch(t, fields[0]), transactionStart: parseEpoch(t, fields[1]),
			backend: fields[2], oldHolder: fields[3], newHolder: fields[4], newUntil: parseEpoch(t, fields[5])})
	}
	return found
}

// waitForUpdates waits until the board's row has had at least count updates, by the deadline,
// and returns them.
func (created *board) waitForUpdates(t *testing.T, count int, deadline time.Time) []update {
	t.Helper()
	for {
		found := created.updates(t)
		if len(found) >= count {
			return found
		}
		if time.Now().After(deadline) {
			t.Fatalf("the row had %d updates by the deadline, want %d: %+v", len(found), count, found)
		}
		pause(t, 100*time.Millisecond)
	}
}

// rowLock holds the board's row locked from a psql session of the test's own, so the program's
// updates of it wait. release ends that session, freeing the row.
type rowLock struct {
	command *exec.Cmd
	created *board
	name    string
}

// lockRow locks the board's own row and returns once the lock is held.
func (created *board) lockRow(t *testing.T) *rowLock {
	t.Helper()
	name := uniqueName("qa_lock")
	path, err := exec.LookPath("psql")
	if err != nil {
		t.Fatalf("PostgreSQL's psql is not on the PATH, so the oracle cannot run: %v", err)
	}
	command := exec.CommandContext(context.WithoutCancel(t.Context()), path, "-X", "-q", "-h", databaseHost,
		"-p", strconv.Itoa(created.server.port), "-U", superuser, "-d", created.database,
		"-c", fmt.Sprintf("BEGIN; SELECT 1 FROM hadv.servers WHERE id = %d FOR UPDATE; SELECT pg_sleep(600); COMMIT;", created.serverID))
	command.Env = append(created.server.superuserEnvironment(), "PGAPPNAME="+name)
	if err := command.Start(); err != nil {
		t.Fatalf("starting the psql that locks the row: %v", err)
	}
	lock := &rowLock{command: command, created: created, name: name}
	t.Cleanup(func() { lock.release(t) })
	deadline := time.Now().Add(30 * time.Second)
	for created.server.sql(t, superuser, "SELECT count(*) FROM pg_stat_activity WHERE application_name = "+quoteLiteral(name)+" AND query LIKE '%pg_sleep%' AND state = 'active'") != "1" {
		if time.Now().After(deadline) {
			t.Fatalf("the psql that locks the row did not hold it within 30 s")
		}
		pause(t, 20*time.Millisecond)
	}
	return lock
}

// release ends the locking session and waits until the server has let the row go.
func (lock *rowLock) release(t *testing.T) {
	t.Helper()
	if lock.command.Process == nil || lock.command.ProcessState != nil {
		return
	}
	_, _ = lock.created.server.trySQL(superuser, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = "+quoteLiteral(lock.name))
	_ = lock.command.Process.Kill()
	_ = lock.command.Wait()
}

// epoch writes a timestamp as seconds and microseconds since 1970, so it reads back exactly.
func epoch(expression string) string {
	return "to_char(extract(epoch FROM " + expression + "), 'FM9999999999.000000')"
}

func parseEpoch(t *testing.T, text string) time.Time {
	t.Helper()
	whole, fraction, found := strings.Cut(text, ".")
	seconds, err := strconv.ParseInt(whole, 10, 64)
	micro, fractionErr := strconv.ParseInt(fraction, 10, 64)
	if !found || err != nil || fractionErr != nil || len(fraction) != 6 {
		t.Fatalf("a time from the database read as %q", text)
	}
	return time.Unix(seconds, micro*1000)
}

// acceptor is a listener of the test's own at 127.0.0.1 that accepts each connection and closes
// it at once: a database that does not answer, which counts each time the program tries it.
type acceptor struct {
	listener net.Listener
	mutex    sync.Mutex
	tries    []time.Time
	done     sync.WaitGroup
}

func startAcceptor(t *testing.T) *acceptor {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", databaseHost+":0")
	if err != nil {
		t.Fatalf("listening for the program's tries: %v", err)
	}
	server := &acceptor{listener: listener}
	server.done.Go(func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			server.mutex.Lock()
			server.tries = append(server.tries, time.Now())
			server.mutex.Unlock()
			_ = connection.Close()
		}
	})
	t.Cleanup(func() {
		_ = listener.Close()
		server.done.Wait()
	})
	return server
}

func (server *acceptor) port(t *testing.T) int {
	t.Helper()
	address, isTCP := server.listener.Addr().(*net.TCPAddr)
	if !isTCP {
		t.Fatalf("the listener's address is a %T", server.listener.Addr())
	}
	return address.Port
}

// triesSoFar returns when each try came.
func (server *acceptor) triesSoFar() []time.Time {
	server.mutex.Lock()
	defer server.mutex.Unlock()
	return append([]time.Time{}, server.tries...)
}
