// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// A server written in the test, from the standard library, for what no real PostgreSQL sends: a
// reply longer than the engine reads, SCRAM offered without channel binding, a refusal carrying
// text of the test's choosing, and a database that accepts and never answers. It speaks TLS with
// a certificate from the test's own authority, then PostgreSQL's framing by hand: a type byte, a
// 32-bit big-endian length that counts itself, and the body.
package database_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// The request codes a client may open with, from PostgreSQL's protocol documentation.
const (
	sslRequestCode    = 80877103
	gssencRequestCode = 80877104
	protocolVersion3  = 196608
)

// fakeScript is what the fake does with one connection once TLS is up and the startup message
// read.
type fakeScript func(t *testing.T, connection *fakeConnection)

// fake is a server written in the test, listening at 127.0.0.1.
type fake struct {
	listener  net.Listener
	port      int
	authority *authority
	config    *tls.Config
	// closeAtOnce makes the fake close each connection as soon as it accepts it.
	closeAtOnce bool
	script      fakeScript
	mutex       sync.Mutex
	dials       []time.Time
	done        sync.WaitGroup
}

// fakeConnection is one client's connection to the fake, after TLS.
type fakeConnection struct {
	connection *tls.Conn
	reader     *bufio.Reader
	startup    map[string]string
}

// startFake listens at 127.0.0.1 and serves each connection with script, until the row ends.
func startFake(t *testing.T, closeAtOnce bool, script fakeScript) *fake {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", databaseHost+":0")
	if err != nil {
		t.Fatalf("the fake's listen: %v", err)
	}
	signer := newAuthority(t)
	certificatePEM, keyPEM, err := signer.issue(serverCertificate{})
	if err != nil {
		t.Fatalf("the fake's certificate: %v", err)
	}
	pair, err := tls.X509KeyPair([]byte(certificatePEM), []byte(keyPEM))
	if err != nil {
		t.Fatalf("the fake's certificate: %v", err)
	}
	address, isTCP := listener.Addr().(*net.TCPAddr)
	if !isTCP {
		t.Fatalf("the fake's address is a %T", listener.Addr())
	}
	server := &fake{listener: listener, port: address.Port, authority: signer,
		config: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, closeAtOnce: closeAtOnce, script: script}
	server.done.Go(func() { server.serve(t) })
	t.Cleanup(func() {
		_ = listener.Close()
		server.done.Wait()
	})
	return server
}

func (server *fake) serve(t *testing.T) {
	t.Helper()
	for {
		connection, err := server.listener.Accept()
		if err != nil {
			return
		}
		server.mutex.Lock()
		server.dials = append(server.dials, time.Now())
		server.mutex.Unlock()
		if server.closeAtOnce {
			_ = connection.Close()
			continue
		}
		server.done.Go(func() {
			defer func() { _ = connection.Close() }()
			ended := context.AfterFunc(t.Context(), func() { _ = connection.Close() })
			defer ended()
			client, err := server.open(t.Context(), connection)
			if err != nil {
				return
			}
			server.script(t, client)
		})
	}
}

// open answers the client's request for TLS, or its direct TLS, makes the handshake, and reads
// the startup message.
func (server *fake) open(ctx context.Context, raw net.Conn) (*fakeConnection, error) {
	buffered := bufio.NewReader(raw)
	first, err := buffered.Peek(1)
	if err != nil {
		return nil, err
	}
	if first[0] != 0x16 {
		for {
			request := make([]byte, 8)
			if _, err := io.ReadFull(buffered, request); err != nil {
				return nil, err
			}
			code := binary.BigEndian.Uint32(request[4:])
			if code == gssencRequestCode {
				if _, err := raw.Write([]byte{'N'}); err != nil {
					return nil, err
				}
				continue
			}
			if code != sslRequestCode {
				return nil, errors.New("the client did not ask for TLS")
			}
			if _, err := raw.Write([]byte{'S'}); err != nil {
				return nil, err
			}
			break
		}
	}
	connection := tls.Server(&bufferedConnection{Conn: raw, reader: buffered}, server.config)
	if err := connection.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(connection)
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header)
	if length < 8 || length > 10000 {
		return nil, errors.New("the startup message's length is out of bounds")
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint32(body) != protocolVersion3 {
		return nil, errors.New("the startup message is not protocol 3.0")
	}
	startup := map[string]string{}
	fields := strings.Split(string(body[4:]), "\x00")
	for index := 0; index+1 < len(fields); index += 2 {
		if fields[index] == "" {
			break
		}
		startup[fields[index]] = fields[index+1]
	}
	return &fakeConnection{connection: connection, reader: reader, startup: startup}, nil
}

// bufferedConnection hands TLS the bytes the fake peeked at before them.
type bufferedConnection struct {
	net.Conn
	reader *bufio.Reader
}

func (connection *bufferedConnection) Read(buffer []byte) (int, error) {
	return connection.reader.Read(buffer)
}

// dialCount is how many connections the fake has accepted.
func (server *fake) dialCount() int {
	server.mutex.Lock()
	defer server.mutex.Unlock()
	return len(server.dials)
}

// send writes one message: its type, its length and its body.
func (connection *fakeConnection) send(t *testing.T, kind byte, body []byte) {
	t.Helper()
	length := 4 + len(body)
	if length < 4 || length > math.MaxUint32 {
		t.Fatalf("a message of %d bytes is longer than its length can say", length)
		return
	}
	message := make([]byte, 5, 5+len(body))
	message[0] = kind
	binary.BigEndian.PutUint32(message[1:], uint32(length))
	if _, err := connection.connection.Write(append(message, body...)); err != nil {
		t.Logf("the fake's write failed: %v", err)
	}
}

// errorBody is an ErrorResponse's body: a FATAL error with the code and message given.
func errorBody(code, message string) []byte {
	var body []byte
	for _, field := range []struct {
		kind  byte
		value string
	}{{'S', "FATAL"}, {'V', "FATAL"}, {'C', code}, {'M', message}} {
		body = append(append(append(body, field.kind), field.value...), 0)
	}
	return append(body, 0)
}

// saslBody is an AuthenticationSASL's body, offering the mechanisms given.
func saslBody(mechanisms ...string) []byte {
	body := binary.BigEndian.AppendUint32(nil, 10)
	for _, mechanism := range mechanisms {
		body = append(append(body, mechanism...), 0)
	}
	return append(body, 0)
}

// readMessage reads one message from the client, by the deadline: its type and body.
func (connection *fakeConnection) readMessage(deadline time.Time) (byte, []byte, error) {
	_ = connection.connection.SetReadDeadline(deadline)
	header := make([]byte, 5)
	if _, err := io.ReadFull(connection.reader, header); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(header[1:])
	if length < 4 || length > 1<<20 {
		return 0, nil, errors.New("a client message's length is out of bounds")
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(connection.reader, body); err != nil {
		return 0, nil, err
	}
	return header[0], body, nil
}

// awaitEnd reads until the client closes the connection or the deadline passes, and returns
// when the close came, or the zero time if it did not.
func (connection *fakeConnection) awaitEnd(deadline time.Time) time.Time {
	_ = connection.connection.SetReadDeadline(deadline)
	buffer := make([]byte, 4096)
	for {
		if _, err := connection.reader.Read(buffer); err != nil {
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				return time.Time{}
			}
			return time.Now()
		}
	}
}

// fakeFile is a connection file for the fake.
func (server *fake) file() connectionFile {
	return connectionFile{ServerID: 1, Host: databaseHost, Port: server.port, Database: "board",
		Login: "server", Password: "password-" + canary, CACertificate: server.authority.pemText}
}
