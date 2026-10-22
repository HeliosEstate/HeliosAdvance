// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The test side of the Telnet wire: the byte values of RFC 854, 857 and 858, a reading of a
// caller's bytes written from RFC 854, RFC 855 and RFC 1143 section 7, and the scripted caller
// that drives Negotiate over real loopback sockets. None of it uses the telnet package's own
// constants or code, so a fault there cannot hide in the oracle too.
package telnet_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// The command and option codes, from the RFCs, not from the package.
const (
	iac                 byte = 255
	dont                byte = 254
	doVerb              byte = 253
	wont                byte = 252
	will                byte = 251
	subnegotiationBegin byte = 250
	nop                 byte = 241
	ayt                 byte = 246
	subnegotiationEnd   byte = 240

	echo byte = 1
	sga  byte = 3

	telnetTypeOption byte = 24
	windowSizeOption byte = 31
)

// The engine's limits, as the contract's lines state them, written here so that a changed
// constant in the package cannot move a test's expectation with it.
const (
	negotiationLimit = 3 * time.Second
	readBufferBytes  = 256
)

// margin is how late past a limit an event may come on the slowest runner, under the race
// detector and with every test running in parallel. On 2026-10-16 the three runners woke a
// deadline at most 1.2 ms late and moved bytes over loopback in under 0.5 ms, forty connections
// at once; the rest is room for the engine's own work under load.
const margin = 750 * time.Millisecond

var opening = []byte{iac, will, echo, iac, will, sga}

// request is one option request: IAC, the verb, the option.
func request(verb, option byte) []byte {
	return []byte{iac, verb, option}
}

// join puts byte sequences one after another into a new slice.
func join(parts ...[]byte) []byte {
	var joined []byte
	for _, part := range parts {
		joined = append(joined, part...)
	}
	return joined
}

// repeated is count copies of part.
func repeated(part []byte, count int) []byte {
	return bytes.Repeat(part, count)
}

// The states of RFC 1143 the engine's side of ECHO and SGA can be in.
const (
	stateWantYes = iota
	stateYes
	stateNo
)

// Where the reading stands between two bytes.
const (
	phaseData = iota
	phaseAfterCommand
	phaseAfterVerb
	phaseInSubnegotiation
	phaseInSubnegotiationAfterCommand
)

// reading is the test's own reading of a caller's bytes, one byte at a time: the reply each
// byte completes, and whether negotiation has ended.
type reading struct {
	states   [2]int
	answers  int
	ended    bool
	phase    int
	verb     byte
	replied  int
	consumed int
}

// feed reads one byte and returns the reply it completes, if any.
func (state *reading) feed(value byte) []byte {
	state.consumed++
	if state.ended {
		return nil
	}
	switch state.phase {
	case phaseData:
		if value == iac {
			state.phase = phaseAfterCommand
		}
	case phaseAfterCommand:
		switch value {
		case will, wont, doVerb, dont:
			state.verb = value
			state.phase = phaseAfterVerb
		case subnegotiationBegin:
			state.phase = phaseInSubnegotiation
		default:
			state.phase = phaseData
		}
	case phaseAfterVerb:
		state.phase = phaseData
		reply := state.answer(state.verb, value)
		state.replied += len(reply)
		return reply
	case phaseInSubnegotiation:
		if value == iac {
			state.phase = phaseInSubnegotiationAfterCommand
		}
	case phaseInSubnegotiationAfterCommand:
		if value == subnegotiationEnd {
			state.phase = phaseData
		} else {
			state.phase = phaseInSubnegotiation
		}
	}
	return nil
}

// answer is the reply to one option request, by the tables of RFC 1143 section 7 with the
// engine's side as "us", and the refusal of every other option.
func (state *reading) answer(verb, option byte) []byte {
	if verb == will {
		return request(dont, option)
	}
	if verb == wont {
		return nil
	}
	index := -1
	switch option {
	case echo:
		index = 0
	case sga:
		index = 1
	}
	if index < 0 {
		if verb == doVerb {
			return request(wont, option)
		}
		return nil
	}
	var reply []byte
	switch {
	case verb == doVerb && state.states[index] == stateWantYes:
		state.states[index] = stateYes
		state.answers++
	case verb == dont && state.states[index] == stateWantYes:
		state.states[index] = stateNo
		state.answers++
	case verb == dont && state.states[index] == stateYes:
		state.states[index] = stateNo
		reply = request(wont, option)
	case verb == doVerb && state.states[index] == stateNo:
		state.states[index] = stateYes
		reply = request(will, option)
	}
	if state.answers == 2 {
		state.ended = true
	}
	return reply
}

// readAll feeds every byte of input and returns the replies and whether negotiation ended.
func (state *reading) readAll(input []byte) ([]byte, bool) {
	var replies []byte
	for _, value := range input {
		replies = append(replies, state.feed(value)...)
	}
	return replies, state.ended
}

// expectedReplies is what the whole stream gets, by the test's own reading.
func expectedReplies(input []byte) []byte {
	replies, _ := (&reading{}).readAll(input)
	return replies
}

// connected is one loopback connection: the client end the scripted caller holds and the
// server end handed to the code under test.
type connected struct {
	client *net.TCPConn
	server *net.TCPConn
	// dialed is a moment before the server end existed, so before anything the server side did.
	dialed time.Time
}

// connect opens a loopback listener on a port the operating system picks, dials it and
// accepts, and closes both ends when the test ends.
func connect(t *testing.T) connected {
	t.Helper()
	listening, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on loopback: %v", err)
	}
	defer func() { _ = listening.Close() }()
	dialed := time.Now()
	clientEnd, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", listening.Addr().String())
	if err != nil {
		t.Fatalf("dialing loopback: %v", err)
	}
	serverEnd, err := listening.Accept()
	if err != nil {
		t.Fatalf("accepting on loopback: %v", err)
	}
	client, clientIsTCP := clientEnd.(*net.TCPConn)
	server, serverIsTCP := serverEnd.(*net.TCPConn)
	if !clientIsTCP || !serverIsTCP {
		t.Fatalf("loopback connection is not TCP: %T, %T", clientEnd, serverEnd)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return connected{client: client, server: server, dialed: dialed}
}

// readExactly reads count bytes from the connection, giving up at the deadline.
func readExactly(t *testing.T, connection net.Conn, count int, deadline time.Time) []byte {
	t.Helper()
	_ = connection.SetReadDeadline(deadline)
	received := make([]byte, count)
	got, err := io.ReadFull(connection, received)
	if err != nil {
		t.Fatalf("reading %d bytes, got %d (% x): %v", count, got, received[:got], err)
	}
	return received
}

// readToEnd reads until end of stream, giving up at the deadline, and returns every byte and
// how the stream ended.
func readToEnd(connection net.Conn, deadline time.Time) ([]byte, error) {
	_ = connection.SetReadDeadline(deadline)
	var received []byte
	chunk := make([]byte, 4096)
	for {
		got, err := connection.Read(chunk)
		received = append(received, chunk[:got]...)
		if err != nil {
			return received, err
		}
	}
}

// expectStream checks every byte the client reads until end of stream, and that the stream
// ended in order by the deadline.
func expectStream(t *testing.T, connection net.Conn, want []byte, deadline time.Time) {
	t.Helper()
	received, err := readToEnd(connection, deadline)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("the stream did not end in order by the deadline: %v, after % x", err, received)
	}
	if !bytes.Equal(received, want) {
		t.Fatalf("the stream was\n% x\nwant\n% x", received, want)
	}
}

// write sends bytes from the scripted caller and fails the test if they do not go.
func write(t *testing.T, connection net.Conn, data []byte) time.Time {
	t.Helper()
	_ = connection.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := connection.Write(data); err != nil {
		t.Fatalf("the caller's write failed: %v", err)
	}
	return time.Now()
}

// flood sends option requests and never reads, until its writes stop going through: the
// engine's replies have filled the caller's receive buffer and the engine's send buffer, so a
// write of the engine's waits. It returns once it has seen its own writes block.
func flood(t *testing.T, connection *net.TCPConn) {
	t.Helper()
	_ = connection.SetReadBuffer(4096)
	requests := repeated(request(doVerb, telnetTypeOption), 1024)
	for {
		_ = connection.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
		_, err := connection.Write(requests)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			_ = connection.SetWriteDeadline(time.Time{})
			return
		}
		if err != nil {
			t.Fatalf("flooding: %v", err)
		}
	}
}

// reset closes the caller's end abortively, so the engine's next read or write fails with a
// reset.
func reset(t *testing.T, connection *net.TCPConn) {
	t.Helper()
	if err := connection.SetLinger(0); err != nil {
		t.Fatalf("setting linger: %v", err)
	}
	_ = connection.Close()
}

// wait blocks until the moment comes or the test ends. It waits on the clock only where the
// clock is what a line is about.
func wait(ctx context.Context, until time.Time) {
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}
