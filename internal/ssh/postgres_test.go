// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The database the built program needs before it listens: a real PostgreSQL, made by the tests
// from its own programs (initdb, pg_ctl and psql) in temporary folders, as the ordinary user
// running them, listening at 127.0.0.1 alone with TLS on and a certificate signed by a
// certificate authority the test makes, ECDSA P-256 with SHA-256. One board is made on it as
// hadv-setup will make one, and each run of the program gets a row of its own and a connection
// file naming it. These rows are about SSH, not the database: the program's database rows are
// cmd/hadv-service's.
package ssh_test

import (
	"context"
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
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The option that names the connection file, the superuser the tests set the server up as, and
// the one address it listens at.
const (
	databaseOption = "-database"
	superuser      = "postgres"
	databaseHost   = "127.0.0.1"
)

// toolLimit bounds each run of one of PostgreSQL's programs, so a hung one fails its row.
const toolLimit = 2 * time.Minute

// passwordField is the connection file's field that holds the login's password.
const passwordField = "password"

// The template cluster and the one server and board every run of the program shares, made in
// TestMain.
var (
	templateDirectory string
	shared            *postgres
	sharedBoard       *board
	oracleFailure     error
)

// prepareOracle makes the template cluster, the server and the board.
func prepareOracle() error {
	directory, err := os.MkdirTemp("", "hadv-postgres-template-")
	if err != nil {
		return err
	}
	templateDirectory = directory
	password, err := randomText(16)
	if err != nil {
		return err
	}
	passwordFile := filepath.Join(directory, "password")
	if err := os.WriteFile(passwordFile, []byte(password+"\n"), 0o600); err != nil {
		return err
	}
	output, err := runTool(cleanEnvironment(), "initdb", "-D", filepath.Join(directory, "data"), "-U", superuser,
		"--pwfile="+passwordFile, "--auth=scram-sha-256", "-E", "UTF8", "--locale=C", "--no-sync")
	if err != nil {
		return fmt.Errorf("initdb: %w: %s", err, output)
	}
	shared, err = launchPostgres(filepath.Join(directory, "shared"), password)
	if err != nil {
		return err
	}
	sharedBoard, err = shared.makeBoard()
	return err
}

// stopOracle stops the server; its folder and the template's go with the run's own.
func stopOracle() {
	if shared != nil {
		_, _ = shared.pgctl("stop", "-m", "immediate", "-w", "-t", "60")
	}
}

// cleanEnvironment is this process's environment without any of PostgreSQL's own variables, so a
// program the tests start is told everything on its command line.
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

// postgres is the server.
type postgres struct {
	data     string
	port     int
	password string
	// authorityPEM is the certificate authority, as PEM, that signed the server's certificate.
	authorityPEM string
}

// launchPostgres copies the template into directory, gives it a certificate signed by an
// authority of its own, its settings and sign-in rules, starts it on a free port, and makes the
// role hadv_server, which schema.sql needs.
func launchPostgres(directory, password string) (*postgres, error) {
	data := filepath.Join(directory, "data")
	// PostgreSQL refuses a data folder others may read; the copy keeps the folder's own mode.
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	if err := os.Mkdir(data, 0o700); err != nil {
		return nil, err
	}
	if err := os.CopyFS(data, os.DirFS(filepath.Join(templateDirectory, "data"))); err != nil {
		return nil, err
	}
	authorityPEM, certificate, key, err := makeCertificates()
	if err != nil {
		return nil, err
	}
	server := &postgres{data: data, password: password, authorityPEM: authorityPEM}
	for name, text := range map[string]string{
		"server.crt": certificate, "server.key": key,
		"pg_hba.conf": "host all " + superuser + " " + databaseHost + "/32 scram-sha-256\nhostssl all all " + databaseHost + "/32 scram-sha-256\n",
	} {
		if err := os.WriteFile(filepath.Join(data, name), []byte(text), 0o600); err != nil {
			return nil, err
		}
	}
	for try := 0; ; try++ {
		port, err := databasePort()
		if err != nil {
			return nil, err
		}
		server.port = port
		settings := []string{
			"listen_addresses = '" + databaseHost + "'", "port = " + strconv.Itoa(port), "unix_socket_directories = ''",
			"ssl = on", "ssl_cert_file = 'server.crt'", "ssl_key_file = 'server.key'", "fsync = off", "max_connections = 300",
		}
		configuration := filepath.Join(data, "postgresql.conf")
		text, err := os.ReadFile(configuration)
		if err != nil {
			return nil, err
		}
		base, _, _ := strings.Cut(string(text), "# The tests' settings\n")
		if err := os.WriteFile(configuration, []byte(base+"# The tests' settings\n"+strings.Join(settings, "\n")+"\n"), 0o600); err != nil {
			return nil, err
		}
		logPath := filepath.Join(directory, "server.log")
		output, err := server.pgctl("start", "-w", "-t", "60", "-l", logPath)
		if err == nil {
			break
		}
		log, readErr := os.ReadFile(logPath)
		if readErr != nil {
			log = []byte("(the server's log could not be read: " + readErr.Error() + ")")
		}
		if try < 5 && strings.Contains(string(log), "could not bind") {
			continue
		}
		return server, fmt.Errorf("pg_ctl start: %w: %s\n%s", err, output, log)
	}
	if output, err := server.trySQL(superuser, "CREATE ROLE hadv_server NOLOGIN"); err != nil {
		return server, fmt.Errorf("making hadv_server: %w: %s", err, output)
	}
	return server, nil
}

// makeCertificates makes a certificate authority signing with ECDSA P-256 and SHA-256, and a
// certificate for the database naming 127.0.0.1, and returns the authority, the certificate and
// its key, as PEM.
func makeCertificates() (string, string, string, error) {
	authorityKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", err
	}
	authorityTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "Helios test authority"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true,
	}
	authorityDER, err := x509.CreateCertificate(rand.Reader, authorityTemplate, authorityTemplate, authorityKey.Public(), authorityKey)
	if err != nil {
		return "", "", "", err
	}
	authority, err := x509.ParseCertificate(authorityDER)
	if err != nil {
		return "", "", "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "Helios test database"},
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP(databaseHost)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, authority, key.Public(), authorityKey)
	if err != nil {
		return "", "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authorityDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), nil
}

// databasePort finds a port nothing listens on at 127.0.0.1.
func databasePort() (int, error) {
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

func (server *postgres) pgctl(arguments ...string) (string, error) {
	return runTool(cleanEnvironment(), "pg_ctl", append(arguments, "-D", server.data)...)
}

// trySQL runs statements as the superuser in a database, one psql call.
func (server *postgres) trySQL(database string, statements ...string) (string, error) {
	arguments := []string{"-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-h", databaseHost,
		"-p", strconv.Itoa(server.port), "-U", superuser, "-d", database}
	for _, statement := range statements {
		arguments = append(arguments, "-c", statement)
	}
	return runTool(cleanEnvironment("PGPASSWORD="+server.password, "PGSSLMODE=disable", "PGCONNECT_TIMEOUT=10"), "psql", arguments...)
}

// quoteLiteral writes a string as an SQL literal.
func quoteLiteral(text string) string {
	return "'" + strings.ReplaceAll(text, "'", "''") + "'"
}

// board is a board's database made as hadv-setup will make it.
type board struct {
	server   *postgres
	database string
	owner    string
	login    string
	password string
}

// makeBoard makes an owner, a database it owns, the schema run as the owner, and a login that is
// a member of hadv_server alone.
func (server *postgres) makeBoard() (*board, error) {
	suffix, err := randomText(12)
	if err != nil {
		return nil, err
	}
	created := &board{server: server, database: uniqueName("board"), owner: uniqueName("owner"),
		login: uniqueName("server"), password: "password-" + suffix}
	schema, err := os.ReadFile(filepath.Join("..", "database", "schema.sql"))
	if err != nil {
		return nil, err
	}
	steps := [][]string{
		{superuser, "CREATE ROLE " + created.owner + " NOLOGIN",
			"CREATE DATABASE " + created.database + " OWNER " + created.owner,
			"CREATE ROLE " + created.login + " LOGIN PASSWORD " + quoteLiteral(created.password) + " IN ROLE hadv_server"},
		{created.database, "SET ROLE " + created.owner + ";\n" + string(schema)},
	}
	for _, step := range steps {
		if output, err := server.trySQL(step[0], step[1:]...); err != nil {
			return nil, fmt.Errorf("%w: %s", err, output)
		}
	}
	return created, nil
}

// sharedRowFile adds a row to the board for one run of the program, its lease ended an hour ago
// and never held, and returns the path of a connection file naming it, which only its owner may
// read.
func sharedRowFile(t *testing.T) string {
	t.Helper()
	if oracleFailure != nil {
		t.Fatalf("the program's database could not be prepared: %v", oracleFailure)
	}
	output, err := shared.trySQL(sharedBoard.database,
		"SET ROLE "+sharedBoard.owner+"; INSERT INTO hadv.servers (lease_until) VALUES (now() - interval '1 hour') RETURNING id")
	if err != nil {
		t.Fatalf("adding a row to the board: %v: %s", err, output)
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	identifier, err := strconv.ParseInt(strings.TrimSpace(lines[len(lines)-1]), 10, 64)
	if err != nil {
		t.Fatalf("the new row's ID read as %q: %v", output, err)
	}
	text, err := json.Marshal(map[string]any{
		"server_id": identifier, "host": databaseHost, "port": shared.port, "database": sharedBoard.database,
		"login": sharedBoard.login, passwordField: sharedBoard.password, "ca_certificate": shared.authorityPEM,
	})
	if err != nil {
		t.Fatalf("writing the connection file's JSON: %v", err)
	}
	path := filepath.Join(t.TempDir(), "connection.json")
	if err := os.WriteFile(path, text, 0o600); err != nil {
		t.Fatalf("writing the connection file: %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatalf("protecting the connection file: %v", err)
		}
	}
	return path
}
