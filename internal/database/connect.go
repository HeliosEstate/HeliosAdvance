// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package database

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

// errLocalSettings is a fault on the engine's own machine: the temporary file the settings are
// parsed with could not be made. The contract names no error for it, so the program stops with
// this one's text.
var errLocalSettings = errors.New("database: the engine could not prepare its database settings, " +
	"since it could not write a file in the system's temporary folder")

// fixedSettings gives every setting PostgreSQL's environment variables could otherwise give, a
// fixed value, so no variable can fail the parse or reach the settings. The file's own values
// replace the placeholders afterwards. The service is empty and its file is the package's own:
// the library reads PGSERVICE's file and fails when it is missing, whatever else is given.
const fixedSettings = "host=localhost port=5432 user=u dbname=d password=p sslmode=disable " +
	"connect_timeout=10 target_session_attrs=any channel_binding=require require_auth=scram-sha-256 " +
	"min_protocol_version=3.0 max_protocol_version=3.0 service=''"

// settings parses once, at the first Take, since parsing writes and removes a file.
func (server *ServerDatabase) settings() (*pgx.ConnConfig, error) {
	state := &server.state
	if state.config != nil {
		return state.config, nil
	}
	serviceFile, err := os.CreateTemp("", "hadv-service-*")
	if err != nil {
		return nil, errLocalSettings
	}
	path := serviceFile.Name()
	_, writeErr := serviceFile.WriteString("[]\n")
	closeErr := serviceFile.Close()
	var config *pgx.ConnConfig
	var parseErr error
	if writeErr == nil && closeErr == nil {
		// Forward slashes: the library's connection string drops a backslash.
		config, parseErr = pgx.ParseConfig(fixedSettings + " servicefile='" + filepath.ToSlash(path) + "'")
	}
	removeErr := os.Remove(path)
	if writeErr != nil || closeErr != nil || parseErr != nil || removeErr != nil {
		return nil, errLocalSettings
	}
	file := state.file
	config.Host, config.Port, config.Database = file.Host, file.Port, file.Database
	config.User, config.Password = file.Login, file.Password
	config.TLSConfig, config.Fallbacks, config.RuntimeParams = nil, nil, map[string]string{}
	config.ValidateConnect, config.AfterConnect, config.AfterNetConnect = nil, nil, nil
	config.KerberosSrvName, config.KerberosSpn, config.OAuthTokenProvider = "", "", nil
	config.MinProtocolVersion, config.MaxProtocolVersion = "3.0", "3.0"
	config.ChannelBinding, config.RequireAuth = "require", "scram-sha-256"
	config.ConnectTimeout = 0
	config.MaxProtocolMessageBodyLen = ReplyMostBytes - 4
	config.LookupFunc = func(_ context.Context, host string) ([]string, error) { return []string{host}, nil }
	// One message per statement, with nothing prepared or cached: the engine runs a handful of
	// statements, and their values are an integer and a UUID the engine made.
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(file.CACertificate))
	state.config, state.roots = config, roots
	return config, nil
}

// socket is the raw connection under TLS. It keeps the first failure of a read or write that the
// engine did not cause by closing it: that failure is what tells a database that stopped
// answering from one that refused.
type socket struct {
	net.Conn
	closed atomic.Bool
	failed atomic.Bool
}

func (raw *socket) Read(buffer []byte) (int, error) {
	count, err := raw.Conn.Read(buffer)
	if err != nil && !raw.closed.Load() {
		raw.failed.Store(true)
	}
	return count, err
}

func (raw *socket) Write(buffer []byte) (int, error) {
	count, err := raw.Conn.Write(buffer)
	if err != nil && !raw.closed.Load() {
		raw.failed.Store(true)
	}
	return count, err
}

// abandon ends the socket's reads and writes at once, by a deadline in the past. A socket whose
// deadline cannot be set is failing.
func (raw *socket) abandon() {
	if err := raw.SetDeadline(time.Unix(1, 0)); err != nil {
		raw.failed.Store(true)
	}
}

func (raw *socket) Close() error {
	raw.closed.Store(true)
	return raw.Conn.Close()
}

// attempt carries the socket the connection was made on to the classification of an error, which
// cannot see it through the library. Only the first socket is kept: the library dials again for a
// cancel request after a failed read, and that fresh socket would hide the failure.
type attempt struct {
	socket atomic.Pointer[socket]
}

func (made *attempt) socketFailed() bool {
	raw := made.socket.Load()
	return raw != nil && raw.failed.Load()
}

// sslRequest is what PostgreSQL's protocol needs sent, and answered with S, before any TLS: the
// library's own TLS is off, so the package sends it, a length of 8 and the code 80877103.
var sslRequest = []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}

// bindable is the signature algorithms the library can hash for channel binding, so a
// certificate outside them is refused before anything is sent (RFC 5929).
var bindable = map[x509.SignatureAlgorithm]bool{
	x509.MD5WithRSA: true, x509.SHA1WithRSA: true, x509.ECDSAWithSHA1: true,
	x509.SHA256WithRSA: true, x509.SHA256WithRSAPSS: true, x509.ECDSAWithSHA256: true,
	x509.SHA384WithRSA: true, x509.SHA384WithRSAPSS: true, x509.ECDSAWithSHA384: true,
	x509.SHA512WithRSA: true, x509.SHA512WithRSAPSS: true, x509.ECDSAWithSHA512: true,
}

func verifyBindable(state tls.ConnectionState) error {
	if len(state.PeerCertificates) == 0 || !bindable[state.PeerCertificates[0].SignatureAlgorithm] {
		return ErrCertificate
	}
	return nil
}

// dial makes the TLS connection itself, so nothing but the handshake reaches the database before
// its certificate is checked, and SCRAM's channel binding sees this connection. The error is one
// of the three sentinels, by the stage it came at.
func (server *ServerDatabase) dial(made *attempt) pgconn.DialFunc {
	file := server.state.file
	roots := server.state.roots
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(file.Host, strconv.Itoa(int(file.Port))))
		if err != nil {
			return nil, ErrUnreachable
		}
		wrapped := &socket{Conn: raw}
		made.socket.CompareAndSwap(nil, wrapped)
		// A context that ends mid-handshake closes the socket, which fails the handshake's read.
		stop := context.AfterFunc(ctx, func() { wrapped.abandon() })
		defer stop()

		secured, err := secure(ctx, wrapped, file.Host, roots)
		if err != nil {
			return nil, errors.Join(err, wrapped.Close())
		}
		if !stop() {
			return nil, errors.Join(ErrUnreachable, wrapped.Close())
		}
		return secured, nil
	}
}

func secure(ctx context.Context, wrapped *socket, host string, roots *x509.CertPool) (*tls.Conn, error) {
	if _, err := wrapped.Write(sslRequest); err != nil {
		return nil, ErrUnreachable
	}
	answer := make([]byte, 1)
	if _, err := wrapped.Read(answer); err != nil {
		return nil, ErrUnreachable
	}
	if answer[0] != 'S' {
		return nil, ErrRefused
	}
	secured := tls.Client(wrapped, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: host,
		VerifyConnection: verifyBindable})
	if err := secured.HandshakeContext(ctx); err != nil {
		var unverified *tls.CertificateVerificationError
		switch {
		case errors.As(err, &unverified) || errors.Is(err, ErrCertificate):
			return nil, ErrCertificate
		case wrapped.failed.Load():
			return nil, ErrUnreachable
		}
		return nil, ErrRefused
	}
	return secured, nil
}

// connect copies the settings for each connection, since the dial function is each connection's
// own and the library keeps what it is given.
func (server *ServerDatabase) connect(ctx context.Context) (*pgx.Conn, *attempt, error) {
	config, err := server.settings()
	if err != nil {
		return nil, nil, err
	}
	made := &attempt{}
	copied := config.Copy()
	copied.DialFunc = server.dial(made)
	connection, err := pgx.ConnectConfig(ctx, copied)
	return connection, made, err
}

// classify turns an error from connecting or querying into the package's own, and never holds
// the library's text or the database's. signingIn is true while the connection is made: the
// library gives no type to a refusal of the way of signing in, so what is left of it is that.
func classify(callerContext, tryContext context.Context, made *attempt, err error, signingIn bool) error {
	if callerContext.Err() != nil {
		return fmt.Errorf("database: take: %w", callerContext.Err())
	}
	// What the database answered stands even when the try's time has run out by now: the close
	// before this call can take a second. A query cut off by the deadline is a context error, so
	// it is none of these.
	var badVersion *SchemaVersionError
	if errors.As(err, &badVersion) {
		return badVersion
	}
	var refusal *pgconn.PgError
	if errors.As(err, &refusal) {
		return bySQLState(refusal.Code)
	}
	for _, answered := range []error{ErrTooPowerful, ErrReadOnly, ErrNoServerRow, ErrLeaseHeld} {
		if errors.Is(err, answered) {
			return answered
		}
	}
	if tryContext.Err() != nil {
		return ErrUnreachable
	}
	for _, own := range []error{ErrUnreachable, ErrCertificate, ErrRefused} {
		if errors.Is(err, own) {
			return own
		}
	}
	var tooLong *pgproto3.ExceededMaxBodyLenErr
	if made != nil && made.socketFailed() || errors.As(err, &tooLong) {
		return ErrUnreachable
	}
	if signingIn {
		return ErrSignInMethod
	}
	return ErrRefused
}

func bySQLState(code string) error {
	switch code {
	case "57P01", "57P02", "57P03":
		return ErrNotReady
	case "53300":
		return ErrNoConnectionFree
	case "28P01", "28000":
		return ErrSignInRefused
	case "25006":
		return ErrReadOnly
	}
	if len(code) >= 2 && code[:2] == "08" {
		return ErrUnreachable
	}
	return ErrRefused
}
