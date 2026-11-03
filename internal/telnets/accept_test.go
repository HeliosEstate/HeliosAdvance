// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package telnets_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/telnet"
	"github.com/heliosestate/heliosadvance/internal/telnets"
	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// versions are the two the TLS table offers, as QA's caller asks for each.
var versions = []struct {
	name string
	id   uint16
}{{"TLS 1.3", tls.VersionTLS13}, {"TLS 1.2", tls.VersionTLS12}}

// helloCatcher takes a crypto/tls client's first flight and fails every read, so the client
// stops after its ClientHello.
type helloCatcher struct {
	net.Conn
	written []byte
}

func (catcher *helloCatcher) Write(buffer []byte) (int, error) {
	catcher.written = append(catcher.written, buffer...)
	return len(buffer), nil
}

func (*helloCatcher) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// clientHello is the ClientHello a crypto/tls client offering TLS 1.2 up to the version given
// sends first.
func clientHello(t *testing.T, maximum uint16) []byte {
	t.Helper()
	catcher := &helloCatcher{}
	config := &tls.Config{ServerName: "localhost", MinVersion: tls.VersionTLS12, MaxVersion: maximum}
	_ = tls.Client(catcher, config).HandshakeContext(t.Context())
	if len(catcher.written) < 11 || catcher.written[0] != handshakeRecord {
		t.Fatalf("a fault in the test: the client's first flight is % x", catcher.written)
	}
	return catcher.written
}

// tls11Hello is the TLS 1.1 ClientHello s_client sends, caught on a listener of the test's own: a
// crypto/tls client puts supported_versions in every hello, so no hello of its own is TLS 1.1.
// s_client ends once the caught connection closes.
func tls11Hello(t *testing.T) []byte {
	t.Helper()
	listening, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on loopback: %v", err)
	}
	defer func() { _ = listening.Close() }()
	startSClient(t, listening.Addr().String(), "-tls1_1", "-cipher", "DEFAULT:@SECLEVEL=0")
	accepted, err := listening.Accept()
	if err != nil {
		t.Fatalf("accepting s_client: %v", err)
	}
	defer func() { _ = accepted.Close() }()
	_ = accepted.SetReadDeadline(time.Now().Add(testrun.Patient(testrun.HangBound)))
	header := make([]byte, 5)
	if _, err := io.ReadFull(accepted, header); err != nil || header[0] != handshakeRecord {
		t.Fatalf("a fault in the test: s_client's first record began % x (%v)", header, err)
	}
	body := make([]byte, int(header[3])<<8|int(header[4]))
	if _, err := io.ReadFull(accepted, body); err != nil || len(body) < 6 || body[4] != 3 || body[5] != 2 {
		t.Fatalf("a fault in the test: s_client's ClientHello is not TLS 1.1: % x (%v)", body, err)
	}
	return append(header, body...)
}

// lateDeadline is a context whose deadline has passed while it does not report it yet: only the
// clock can tell it has ended.
type lateDeadline struct {
	context.Context
	deadline time.Time
}

func (ctx lateDeadline) Deadline() (time.Time, bool) { return ctx.deadline, true }

func endsLate(t *testing.T, deadline time.Time) context.Context {
	t.Helper()
	ctx, cancel := context.WithDeadline(t.Context(), deadline.Add(testrun.Patient(testrun.HangBound)))
	t.Cleanup(cancel)
	return lateDeadline{Context: ctx, deadline: deadline}
}

// expectUntouched checks nothing was written to the caller within the quiet time, and that a
// byte still passes both ways: the connection was neither written to nor closed.
func expectUntouched(t *testing.T, connection pair) {
	t.Helper()
	_ = connection.client.SetReadDeadline(time.Now().Add(quiet))
	buffer := make([]byte, 64)
	if got, err := connection.client.Read(buffer); got > 0 || !isDeadline(err) {
		t.Fatalf("the caller read % x and %v, want nothing", buffer[:got], err)
	}
	_ = connection.client.SetWriteDeadline(time.Now().Add(testrun.Patient(testrun.HangBound)))
	if _, err := connection.client.Write([]byte("y")); err != nil {
		t.Fatalf("the caller's write failed: %v", err)
	}
	_ = connection.server.SetReadDeadline(time.Now().Add(testrun.Patient(margin)))
	if got, err := connection.server.Read(buffer); err != nil || !bytes.Equal(buffer[:got], []byte("y")) {
		t.Fatalf("the server's end read % x and %v, want y", buffer[:got], err)
	}
	expectNotClosed(t, connection)
}

// expectAtMostAlert reads what reached the caller until the quiet time passes after Accept
// returned, which must be at most one whole alert record: no Telnet byte, and nothing else.
func expectAtMostAlert(t *testing.T, client *net.TCPConn) {
	t.Helper()
	received, err := rawToEnd(client, time.Now().Add(quiet))
	if !isDeadline(err) && !isEnd(err) {
		t.Fatalf("the caller's read failed: %v", err)
	}
	types, trailing := recordTypes(received)
	if trailing != 0 || len(types) > 1 || (len(types) == 1 && types[0] != alertRecord) {
		t.Fatalf("the caller received % x, want at most one alert record", received)
	}
}

// failedHandshake is a handshake made to fail one way: the bytes the caller sends, and whether
// Accept's context has a deadline 1 second away or is cancelled half a second in, either of
// which Accept's return is judged against.
type failedHandshake struct {
	name             string
	send             func(t *testing.T, connection pair)
	deadline, cancel bool
	want             []error
}

// stalledHello sends the first bytes of a ClientHello, never finished.
func stalledHello(t *testing.T, connection pair) {
	t.Helper()
	send(t, connection.client, clientHello(t, tls.VersionTLS13)[:10])
}

func send(t *testing.T, client *net.TCPConn, data []byte) {
	t.Helper()
	_ = client.SetWriteDeadline(time.Now().Add(testrun.Patient(testrun.HangBound)))
	if _, err := client.Write(data); err != nil {
		t.Fatalf("the caller's write failed: %v", err)
	}
}

var failedHandshakes = []failedHandshake{
	{name: "plain Telnet bytes sent first", send: func(t *testing.T, connection pair) {
		t.Helper()
		send(t, connection.client, append(append([]byte{}, answers...), "Caller\r"...))
	}, want: []error{telnets.ErrHandshakeFailed}},
	{name: "a TLS 1.1 ClientHello", send: func(t *testing.T, connection pair) {
		t.Helper()
		send(t, connection.client, tls11Hello(t))
	}, want: []error{telnets.ErrHandshakeFailed}},
	{name: "garbage text", send: func(t *testing.T, connection pair) {
		t.Helper()
		send(t, connection.client, []byte(canary+" is not TLS\r\n"))
	}, want: []error{telnets.ErrHandshakeFailed}},
	{name: "a handshake stalled after part of a ClientHello, its context's deadline 1 second away", send: stalledHello,
		deadline: true, want: []error{telnet.ErrDeadlineEnded, context.DeadlineExceeded}},
	{name: "a handshake stalled after part of a ClientHello, its context cancelled", send: stalledHello,
		cancel: true, want: []error{telnet.ErrDeadlineEnded, context.Canceled}},
}

// runFailedHandshake makes the handshake fail as the case says and checks Accept's return: no
// Line, the error the case gives, and, where the context ends, at the moment it ends.
func runFailedHandshake(t *testing.T, failure failedHandshake) pair {
	t.Helper()
	connection := connect(t)
	certificate := readCertificate(t, goodFiles(t, ecdsaP256))
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	var ended time.Time
	if failure.deadline {
		ended = time.Now().Add(time.Second)
		var cancelDeadline context.CancelFunc
		ctx, cancelDeadline = context.WithDeadline(ctx, ended)
		t.Cleanup(cancelDeadline)
	}
	done := acceptOn(ctx, connection.server, certificate)
	failure.send(t, connection)
	if failure.cancel {
		wait(t.Context(), time.Now().Add(500*time.Millisecond))
		ended = time.Now()
		cancel()
	}
	got := waitAccepted(t, done, time.Now().Add(testrun.Patient(testrun.HangBound)))
	if got.line != nil {
		t.Fatalf("Accept gave a Line for a failed handshake")
	}
	for _, want := range failure.want {
		if !errors.Is(got.err, want) {
			t.Fatalf("Accept gave %v, want %v", got.err, failure.want)
		}
	}
	if !ended.IsZero() {
		expectWithin(t, "Accept's return", got.returned, ended, ended.Add(margin))
	}
	return connection
}

func TestAccept(t *testing.T) {
	t.Parallel()

	t.Run("If connection is nil, or certificate was not made by ReadCertificate or is nil, then Accept shall return telnet.ErrConnectionFailed and a nil Line without touching the connection, whether or not the context has ended.", func(t *testing.T) {
		t.Parallel()
		contexts := []struct {
			name string
			make func(t *testing.T) context.Context
		}{
			{"a live context", func(t *testing.T) context.Context { t.Helper(); return t.Context() }},
			{"a cancelled context", func(t *testing.T) context.Context {
				t.Helper()
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				return ctx
			}},
		}
		for _, made := range contexts {
			t.Run("a nil connection, "+made.name+": ErrConnectionFailed and no Line", func(t *testing.T) {
				t.Parallel()
				line, err := telnets.Accept(made.make(t), nil, readCertificate(t, goodFiles(t, ecdsaP256)))
				if line != nil || !errors.Is(err, telnet.ErrConnectionFailed) {
					t.Fatalf("Accept gave %v and %v, want no Line and ErrConnectionFailed", line, err)
				}
			})
			for _, certificate := range []struct {
				name  string
				value *telnets.Certificate
			}{{"a nil Certificate", nil}, {"a zero Certificate", &telnets.Certificate{}}} {
				t.Run(certificate.name+", "+made.name+": ErrConnectionFailed, no Line, and a byte still passes both ways", func(t *testing.T) {
					t.Parallel()
					connection := connect(t)
					got := waitAccepted(t, acceptOn(made.make(t), connection.server, certificate.value), time.Now().Add(testrun.Patient(margin)))
					if got.line != nil || !errors.Is(got.err, telnet.ErrConnectionFailed) {
						t.Fatalf("Accept gave %v and %v, want no Line and ErrConnectionFailed", got.line, got.err)
					}
					expectUntouched(t, connection)
				})
			}
		}
	})

	t.Run("If the context has ended when Accept is called, judged by the clock, then Accept shall return a nil Line and telnet.ErrDeadlineEnded, wrapping context.DeadlineExceeded or context.Canceled, without writing to the connection.", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name  string
			make  func(t *testing.T) context.Context
			cause error
		}{
			{"cancelled", func(t *testing.T) context.Context {
				t.Helper()
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				return ctx
			}, context.Canceled},
			{"its deadline passed", func(t *testing.T) context.Context {
				t.Helper()
				ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
				t.Cleanup(cancel)
				return ctx
			}, context.DeadlineExceeded},
			{"its deadline passed, not yet reported", func(t *testing.T) context.Context {
				t.Helper()
				return endsLate(t, time.Now().Add(-time.Second))
			}, context.DeadlineExceeded},
		}
		for _, row := range cases {
			t.Run("a context "+row.name+", a caller sending a ClientHello: ErrDeadlineEnded wrapping the cause, nothing written, the connection open", func(t *testing.T) {
				t.Parallel()
				connection := connect(t)
				send(t, connection.client, clientHello(t, tls.VersionTLS13))
				got := waitAccepted(t, acceptOn(row.make(t), connection.server, readCertificate(t, goodFiles(t, ecdsaP256))), time.Now().Add(testrun.Patient(margin)))
				if got.line != nil || !errors.Is(got.err, telnet.ErrDeadlineEnded) || !errors.Is(got.err, row.cause) {
					t.Fatalf("Accept gave %v and %v, want no Line and ErrDeadlineEnded wrapping %v", got.line, got.err, row.cause)
				}
				expectNothingWritten(t, connection)
			})
		}
	})

	t.Run("Accept shall write nothing to the connection but the TLS handshake until the handshake completes.", func(t *testing.T) {
		t.Parallel()
		for _, version := range versions {
			t.Run(version.name+": a caller that stops after its ClientHello receives whole TLS records alone, and no byte outside them", func(t *testing.T) {
				t.Parallel()
				connection := connect(t)
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				t.Cleanup(cancel)
				done := acceptOn(ctx, connection.server, readCertificate(t, goodFiles(t, ecdsaP256)))
				send(t, connection.client, clientHello(t, version.id))
				got := waitAccepted(t, done, time.Now().Add(testrun.Patient(time.Second+margin)))
				if got.line != nil {
					t.Fatalf("Accept gave a Line where the caller never finished its handshake")
				}
				received, err := rawToEnd(connection.client, time.Now().Add(quiet))
				if !isDeadline(err) {
					t.Fatalf("the caller's read ended with %v, want nothing more until the test closes", err)
				}
				types, trailing := recordTypes(received)
				if trailing != 0 || len(types) == 0 || types[0] != handshakeRecord {
					t.Fatalf("the caller received % x, want whole TLS records, a handshake record first", received)
				}
				for _, kind := range types {
					if !slices.Contains([]byte{handshakeRecord, changeCipherSpecRecord, applicationDataRecord, alertRecord}, kind) {
						t.Fatalf("the caller received a record of type %d among % x", kind, received)
					}
				}
			})
		}
	})

	t.Run("If the handshake fails, then Accept shall return a nil Line, having written no Telnet byte to the connection, with telnet.ErrDeadlineEnded, wrapping context.DeadlineExceeded or context.Canceled so that errors.Is matches it and the one wrapped, when the context has ended by then, and otherwise with ErrHandshakeFailed.", func(t *testing.T) {
		t.Parallel()
		for _, failure := range failedHandshakes {
			t.Run(failure.name+": no Line, the error the line gives, and at most one alert record written", func(t *testing.T) {
				t.Parallel()
				connection := runFailedHandshake(t, failure)
				expectAtMostAlert(t, connection.client)
			})
		}
	})

	t.Run("Accept shall leave closing the connection to the shared execution path, the context ending during the handshake included.", func(t *testing.T) {
		t.Parallel()
		for _, failure := range failedHandshakes {
			t.Run(failure.name+": once Accept has returned, the server's end still carries a byte to the caller", func(t *testing.T) {
				t.Parallel()
				connection := runFailedHandshake(t, failure)
				expectNotClosed(t, connection)
			})
		}
	})

	t.Run("When the handshake completes, Accept shall call telnet.Open once over the encrypted connection, under the same context, so that negotiation, its 3 seconds and its eight opening requests start only then, and return its Line, or a nil Line and Open's error.", func(t *testing.T) {
		t.Parallel()
		for _, version := range versions {
			t.Run(version.name+": the eight requests inside the channel, then a Line at once when the caller answers", func(t *testing.T) {
				t.Parallel()
				connection := connect(t)
				done := acceptOn(t.Context(), connection.server, readCertificate(t, goodFiles(t, ecdsaP256)))
				call := handshake(t, connection.client, clientConfig(version.id))
				call.readExactly(t, opening, time.Now().Add(testrun.Patient(margin)))
				answered := time.Now()
				call.send(t, answers)
				got := waitAccepted(t, done, answered.Add(testrun.Patient(margin)))
				if got.err != nil || got.line == nil {
					t.Fatalf("Accept gave %v and %v, want a Line", got.line, got.err)
				}
				expectWithin(t, "Accept's return", got.returned, answered, answered.Add(margin))
			})
			t.Run(version.name+": a caller whose ClientHello comes 2 seconds after it connects and that answers nothing gets a Line 3 seconds after its last handshake flight began, not after it connected", func(t *testing.T) {
				t.Parallel()
				connection := connect(t)
				done := acceptOn(t.Context(), connection.server, readCertificate(t, goodFiles(t, ecdsaP256)))
				wait(t.Context(), connection.dialed.Add(2*time.Second))
				call := handshake(t, connection.client, clientConfig(version.id))
				call.readExactly(t, opening, time.Now().Add(testrun.Patient(margin)))
				got := waitAccepted(t, done, call.lastFlight.Add(negotiationLimit+testrun.Patient(margin)))
				if got.err != nil || got.line == nil {
					t.Fatalf("Accept gave %v and %v, want a Line", got.line, got.err)
				}
				expectWithin(t, "Accept's return", got.returned, call.lastFlight.Add(negotiationLimit), call.lastFlight.Add(negotiationLimit+margin))
			})
			t.Run(version.name+": a caller that sends close_notify during negotiation: no Line, and Open's telnet.ErrCallerClosed", func(t *testing.T) {
				t.Parallel()
				connection := connect(t)
				done := acceptOn(t.Context(), connection.server, readCertificate(t, goodFiles(t, ecdsaP256)))
				call := handshake(t, connection.client, clientConfig(version.id))
				call.readExactly(t, opening, time.Now().Add(testrun.Patient(margin)))
				if err := call.tls.CloseWrite(); err != nil {
					t.Fatalf("the caller's close_notify failed: %v", err)
				}
				got := waitAccepted(t, done, time.Now().Add(testrun.Patient(margin)))
				if got.line != nil || !errors.Is(got.err, telnet.ErrCallerClosed) {
					t.Fatalf("Accept gave %v and %v, want no Line and ErrCallerClosed", got.line, got.err)
				}
			})
			t.Run(version.name+": the context cancelled during negotiation: no Line, and Open's telnet.ErrDeadlineEnded wrapping context.Canceled, at once", func(t *testing.T) {
				t.Parallel()
				connection := connect(t)
				ctx, cancel := context.WithCancel(t.Context())
				t.Cleanup(cancel)
				done := acceptOn(ctx, connection.server, readCertificate(t, goodFiles(t, ecdsaP256)))
				call := handshake(t, connection.client, clientConfig(version.id))
				call.readExactly(t, opening, time.Now().Add(testrun.Patient(margin)))
				cancelledAt := time.Now()
				cancel()
				got := waitAccepted(t, done, cancelledAt.Add(testrun.Patient(margin)))
				if got.line != nil || !errors.Is(got.err, telnet.ErrDeadlineEnded) || !errors.Is(got.err, context.Canceled) {
					t.Fatalf("Accept gave %v and %v, want no Line and ErrDeadlineEnded wrapping context.Canceled", got.line, got.err)
				}
				expectWithin(t, "Accept's return", got.returned, cancelledAt, cancelledAt.Add(margin))
			})
		}
	})

	t.Run("When the engine sends a Synch on a Line Accept made, the caller shall receive IAC DM inside the encrypted stream, DM as an ordinary byte, and the engine shall send no TCP urgent data on the connection.", func(t *testing.T) {
		t.Parallel()
		for _, version := range versions {
			t.Run(version.name+": AO then x from the caller: no urgent byte on the TCP connection, then IAC DM inside the channel, and the Line reads x", func(t *testing.T) {
				t.Parallel()
				connection, call, line := acceptedCaller(t, version.id)
				call.send(t, []byte{iac, abortOutput, 'x'})
				character, err := line.RecvChar(t.Context(), time.Now().Add(testrun.Patient(margin)))
				if err != nil || character != 'x' {
					t.Fatalf("RecvChar gave %q and %v, want x", character, err)
				}
				// Looked for before the caller reads anything, since a read past the mark loses
				// the urgent byte.
				if urgent, err := receiveUrgent(t.Context(), connection.client, time.Now().Add(quiet)); !errors.Is(err, errNoUrgentData) {
					t.Fatalf("the caller's TCP connection held urgent data % x (%v), want none", urgent, err)
				}
				call.readExactly(t, []byte{iac, dataMark}, time.Now().Add(testrun.Patient(margin)))
			})
		}
	})

	t.Run("When the Line's Close shuts down the sending side, the encrypted connection shall send close_notify, then shut down the TCP connection's sending side.", func(t *testing.T) {
		t.Parallel()
		t.Run("TLS 1.2: the last record before the TCP end is an alert, the caller's writes after the end are taken, and Close returns no error when the caller closes", func(t *testing.T) {
			t.Parallel()
			connection, call, line := acceptedCaller(t, tls.VersionTLS12)
			done := make(chan error, 1)
			go func() { done <- line.Close(t.Context()) }()
			if received, err := call.readToEnd(time.Now().Add(testrun.Patient(margin))); len(received) != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("the caller read % x and %v inside the channel, want close_notify's end of file", received, err)
			}
			if received, err := rawToEnd(connection.client, time.Now().Add(testrun.Patient(margin))); len(received) != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("after close_notify the caller's TCP connection gave % x and %v, want end of stream", received, err)
			}
			types, trailing := recordTypes(call.tap.receivedSoFar())
			if trailing != 0 || len(types) == 0 || types[len(types)-1] != alertRecord {
				t.Fatalf("the records' types were %v with %d bytes trailing, want an alert last", types, trailing)
			}
			// Inside the channel, which a caller may write to after the engine's close_notify.
			call.send(t, []byte("after the end"))
			select {
			case err := <-done:
				t.Fatalf("Close returned %v before the caller closed", err)
			default:
			}
			_ = connection.client.Close()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("Close gave %v, want no error", err)
				}
			case <-time.After(testrun.Patient(margin)):
				t.Fatalf("Close had not returned %v after the caller closed", testrun.Patient(margin))
			}
		})
		t.Run("TLS 1.3, s_client -msg: a close_notify alert, then the end, and Close returns no error when s_client closes", func(t *testing.T) {
			t.Parallel()
			listening, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listening.Close() })
			client := startSClient(t, listening.Addr().String(), "-tls1_3")
			accepted, err := listening.Accept()
			if err != nil {
				t.Fatal(err)
			}
			server, isTCP := accepted.(*net.TCPConn)
			if !isTCP {
				t.Fatalf("loopback connection is not TCP: %T", accepted)
			}
			t.Cleanup(func() { _ = server.Close() })
			// s_client answers nothing, so the Line comes once negotiation's 3 seconds pass.
			got := waitAccepted(t, acceptOn(t.Context(), server, readCertificate(t, goodFiles(t, ecdsaP256))), time.Now().Add(negotiationLimit+testrun.Patient(testrun.HangBound)))
			if got.err != nil || got.line == nil {
				t.Fatalf("Accept gave %v and %v, want a Line", got.line, got.err)
			}
			done := make(chan error, 1)
			go func() { done <- got.line.Close(t.Context()) }()
			text := client.finish(t)
			if !strings.Contains(text, "<<< TLS 1.3, Alert [length 0002], warning close_notify") {
				t.Fatalf("s_client received no close_notify:\n%s", text)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("Close gave %v, want no error", err)
				}
			case <-time.After(testrun.Patient(margin)):
				t.Fatalf("Close had not returned %v after s_client ended", testrun.Patient(margin))
			}
		})
	})

	t.Run("If close_notify's write fails, then the encrypted connection shall still shut down the TCP connection's sending side, and return an error; every later write on it fails.", func(t *testing.T) {
		t.Parallel()
		t.Run("TLS 1.2, a caller that stops reading until the buffers are full: Close returns an error, a later write fails, and the caller then reads its backlog to end of stream", func(t *testing.T) {
			t.Parallel()
			connection, _, line := acceptedCaller(t, tls.VersionTLS12)
			fillBuffers(t, connection.server)
			done := make(chan error, 1)
			go func() { done <- line.Close(t.Context()) }()
			// How long close_notify may wait for room is crypto/tls's own, five seconds today,
			// and not pinned: the wait is bounded, not judged.
			var closeErr error
			select {
			case closeErr = <-done:
			case <-time.After(testrun.Patient(2 * testrun.HangBound)):
				t.Fatalf("Close had not returned within %v", testrun.Patient(2*testrun.HangBound))
			}
			if !errors.Is(closeErr, telnet.ErrConnectionFailed) {
				t.Fatalf("Close gave %v, want ErrConnectionFailed", closeErr)
			}
			if err := line.SendChar(t.Context(), 'q'); err == nil {
				if err := line.Flush(t.Context()); err == nil {
					t.Fatalf("a write after the failed close_notify succeeded")
				}
			}
			// What part of close_notify found room before its write failed is crypto/tls's own
			// and the system's, so only the end of the stream is judged.
			if _, err := rawToEnd(connection.client, time.Now().Add(testrun.Patient(testrun.HangBound))); !errors.Is(err, io.EOF) {
				t.Fatalf("the caller's read of the backlog ended with %v, want end of stream", err)
			}
		})
	})

	t.Run("When the caller sends close_notify, the encrypted connection's reads shall end with end of file; when it sends a damaged record or asks to renegotiate, they shall end with a failure.", func(t *testing.T) {
		t.Parallel()
		for _, version := range versions {
			t.Run(version.name+": the caller's close_notify: RecvChar gives io.EOF", func(t *testing.T) {
				t.Parallel()
				_, call, line := acceptedCaller(t, version.id)
				if err := call.tls.CloseWrite(); err != nil {
					t.Fatalf("the caller's close_notify failed: %v", err)
				}
				if _, err := line.RecvChar(t.Context(), time.Now().Add(testrun.Patient(margin))); !errors.Is(err, io.EOF) {
					t.Fatalf("RecvChar gave %v, want io.EOF", err)
				}
			})
			t.Run(version.name+": a record with its last byte changed: RecvChar gives telnet.ErrConnectionFailed", func(t *testing.T) {
				t.Parallel()
				_, call, line := acceptedCaller(t, version.id)
				call.tap.damageNext()
				call.send(t, []byte("x"))
				if _, err := line.RecvChar(t.Context(), time.Now().Add(testrun.Patient(margin))); !errors.Is(err, telnet.ErrConnectionFailed) {
					t.Fatalf("RecvChar gave %v, want ErrConnectionFailed", err)
				}
			})
		}
		t.Run("TLS 1.2, a renegotiation asked for with s_client's R after the Line is made: RecvChar gives telnet.ErrConnectionFailed", func(t *testing.T) {
			t.Parallel()
			listening, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listening.Close() })
			client := startSClientCommands(t, listening.Addr().String(), "-tls1_2")
			accepted, err := listening.Accept()
			if err != nil {
				t.Fatal(err)
			}
			server, isTCP := accepted.(*net.TCPConn)
			if !isTCP {
				t.Fatalf("loopback connection is not TCP: %T", accepted)
			}
			t.Cleanup(func() { _ = server.Close() })
			got := waitAccepted(t, acceptOn(t.Context(), server, readCertificate(t, goodFiles(t, ecdsaP256))), time.Now().Add(negotiationLimit+testrun.Patient(testrun.HangBound)))
			if got.err != nil || got.line == nil {
				t.Fatalf("Accept gave %v and %v, want a Line", got.line, got.err)
			}
			client.send(t, "R\n")
			if _, err := got.line.RecvChar(t.Context(), time.Now().Add(testrun.Patient(testrun.HangBound))); !errors.Is(err, telnet.ErrConnectionFailed) {
				t.Fatalf("RecvChar gave %v, want ErrConnectionFailed", err)
			}
			_ = server.Close()
			if text := client.finish(t); !strings.Contains(text, "RENEGOTIATING") {
				t.Fatalf("s_client did not renegotiate:\n%s", text)
			}
		})
	})
}

// expectNothingWritten checks nothing reached the caller within the quiet time, and that the
// server's end is still open.
func expectNothingWritten(t *testing.T, connection pair) {
	t.Helper()
	received, err := rawToEnd(connection.client, time.Now().Add(quiet))
	if len(received) != 0 || !isDeadline(err) {
		t.Fatalf("the caller read % x and %v, want nothing", received, err)
	}
	expectNotClosed(t, connection)
}

// fillBuffers writes records shaped like TLS 1.2 application data, of random bytes, to the
// server's end beneath the encrypted connection until a write cannot finish, so the caller's
// receive buffer and the server's send buffer are full and close_notify finds no room.
func fillBuffers(t *testing.T, server *net.TCPConn) {
	t.Helper()
	const mostFiller = 256 << 20
	record := make([]byte, 5+16384)
	record[0], record[1], record[2], record[3], record[4] = applicationDataRecord, 3, 3, 0x40, 0x00
	if _, err := rand.Read(record[5:]); err != nil {
		t.Fatal(err)
	}
	// Whole records until one cannot finish, then single bytes until one cannot: a record's write
	// that times out can leave room for a short message such as close_notify, which Linux then
	// takes whole.
	for _, size := range []int{len(record), 1} {
		for written := 0; ; written += size {
			if written >= mostFiller {
				t.Fatalf("a fault in the test: %d bytes of filler never filled the buffers", mostFiller)
			}
			_ = server.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
			if _, err := server.Write(record[:size]); err != nil {
				if !isDeadline(err) {
					t.Fatalf("the filler's write failed: %v", err)
				}
				break
			}
		}
	}
	_ = server.SetWriteDeadline(time.Time{})
}
