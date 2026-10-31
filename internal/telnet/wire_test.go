// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The test side of the Telnet wire: the byte values of RFC 854, 856, 857, 858, 1073, 1079, 1091
// and 1572, a reading of a caller's bytes written from RFC 854, RFC 855 and RFC 1143 section 7,
// and the scripted caller that drives Negotiate and the Line over real loopback sockets. None of
// it uses the telnet package's own constants or code, so a fault there cannot hide in the oracle
// too.
package telnet_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// The command codes, from RFC 854 and RFC 885, not from the package.
const (
	iac                 byte = 255
	dont                byte = 254
	doVerb              byte = 253
	wont                byte = 252
	will                byte = 251
	subnegotiationBegin byte = 250
	goAhead             byte = 249
	eraseLine           byte = 248
	eraseCharacter      byte = 247
	ayt                 byte = 246
	abortOutput         byte = 245
	interruptProcess    byte = 244
	breakCommand        byte = 243
	dataMark            byte = 242
	nop                 byte = 241
	subnegotiationEnd   byte = 240
	endOfRecord         byte = 239
)

// The option codes: BINARY (RFC 856), ECHO (857), SGA (858), TTYPE (1091), NAWS (1073), TSPEED
// (1079) and NEW-ENVIRON (1572).
const (
	binary           byte = 0
	echo             byte = 1
	sga              byte = 3
	telnetTypeOption byte = 24
	windowSizeOption byte = 31
	speedOption      byte = 32
	environOption    byte = 39
)

// The data bytes EC and EL are handed on as, and the subnegotiation codes of the SENDs.
const (
	backspace      byte = 0x08
	eraseLineByte  byte = 0x15
	sendCode       byte = 1
	isCode         byte = 0
	variableCode   byte = 0
	valueCode      byte = 1
	mostOneReply        = 14
	aytAnswerBytes      = "\r\n[Yes]\r\n"
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

// opening is the eight requests the contract's New line gives, in order.
var opening = join(
	request(will, echo), request(will, sga), request(will, binary), request(doVerb, binary),
	request(doVerb, telnetTypeOption), request(doVerb, windowSizeOption),
	request(doVerb, environOption), request(doVerb, speedOption))

// answers answers all eight, ECHO, SGA and BINARY agreed and the four terminal options refused,
// so that no SEND follows: the call most rows start from.
var answers = join(
	request(doVerb, echo), request(doVerb, sga), request(doVerb, binary), request(will, binary),
	request(wont, telnetTypeOption), request(wont, windowSizeOption),
	request(wont, environOption), request(wont, speedOption))

// lateAnswers is the same eight with ECHO and SGA last, so that code still on Part 1's two
// answers ends where Part 4's does and leaves none of the others to the Line.
var lateAnswers = join(answers[6:], answers[:6])

// The SENDs, by RFC 1091, RFC 1079 and RFC 1572: TTYPE's and TSPEED's SEND alone, NEW-ENVIRON's
// SEND for the variable USER.
var (
	terminalTypeSend = []byte{iac, subnegotiationBegin, telnetTypeOption, sendCode, iac, subnegotiationEnd}
	speedSend        = []byte{iac, subnegotiationBegin, speedOption, sendCode, iac, subnegotiationEnd}
	environSend      = []byte{iac, subnegotiationBegin, environOption, sendCode, variableCode, 'U', 'S', 'E', 'R', iac, subnegotiationEnd}
)

// request is one option request: IAC, the verb, the option.
func request(verb, option byte) []byte {
	return []byte{iac, verb, option}
}

// command is IAC and one command byte.
func command(code byte) []byte {
	return []byte{iac, code}
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

// The states of RFC 1143.
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

// The options on each side, and which of them the opening asked for.
var (
	engineSide = []byte{echo, sga, binary}
	callerSide = []byte{sga, binary, telnetTypeOption, windowSizeOption, environOption, speedOption}
)

// reading is the test's own reading of a caller's bytes, one byte at a time: the reply each
// byte completes, the Synchs owed, the data handed on once negotiation is over, and whether
// negotiation has ended. A reading starts from freshReading, as New's negotiation does.
type reading struct {
	engine  map[byte]int
	caller  map[byte]int
	sent    map[byte]bool
	answers int
	// ended is set at the byte that completes the eighth answer; after it, negotiation reads
	// nothing. lineTook is set when the Line takes over, after which every byte is read again.
	ended    bool
	lineTook bool
	synchs   int
	phase    int
	verb     byte
	replied  int
	consumed int
}

func freshReading() *reading {
	state := &reading{engine: map[byte]int{}, caller: map[byte]int{}, sent: map[byte]bool{}}
	for _, option := range engineSide {
		state.engine[option] = stateWantYes
	}
	for _, option := range callerSide {
		state.caller[option] = stateWantYes
	}
	state.caller[sga] = stateNo
	return state
}

// takeOver is the Line taking over from negotiation, wherever it stopped.
func (state *reading) takeOver() *reading {
	state.lineTook = true
	return state
}

// feed reads one byte and returns the reply it completes, and the data byte it hands on, if
// any, once the Line has taken over.
func (state *reading) feed(value byte) ([]byte, byte, bool) {
	state.consumed++
	if state.ended && !state.lineTook {
		return nil, 0, false
	}
	var reply []byte
	switch state.phase {
	case phaseData:
		if value == iac {
			state.phase = phaseAfterCommand
			return nil, 0, false
		}
		return nil, value, state.lineTook
	case phaseAfterCommand:
		state.phase = phaseData
		switch value {
		case will, wont, doVerb, dont:
			state.verb = value
			state.phase = phaseAfterVerb
		case subnegotiationBegin:
			state.phase = phaseInSubnegotiation
		case iac:
			return nil, iac, state.lineTook
		case ayt:
			reply = []byte(aytAnswerBytes)
		case abortOutput, interruptProcess:
			state.synchs++
		case eraseCharacter:
			return nil, backspace, state.lineTook
		case eraseLine:
			return nil, eraseLineByte, state.lineTook
		}
	case phaseAfterVerb:
		state.phase = phaseData
		reply = state.answer(state.verb, value)
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
	state.replied += len(reply)
	return reply, 0, false
}

// answer is the reply to one option request by RFC 1143 section 7, the engine's side as "us"
// for DO and DONT and the caller's side as "him" for WILL and WONT, with the SEND that follows
// a move to YES, and the refusal of every other option.
func (state *reading) answer(verb, option byte) []byte {
	var reply []byte
	switch verb {
	case will, wont:
		current, known := state.caller[option]
		if !known {
			if verb == will {
				return request(dont, option)
			}
			return nil
		}
		switch {
		case verb == will && current == stateWantYes:
			state.caller[option] = stateYes
			state.answered()
		case verb == will && current == stateNo:
			state.caller[option] = stateYes
			reply = request(doVerb, option)
		case verb == wont && current == stateWantYes:
			state.caller[option] = stateNo
			state.answered()
		case verb == wont && current == stateYes:
			state.caller[option] = stateNo
			reply = request(dont, option)
		}
		if verb == will && current != stateYes && !state.sent[option] {
			switch option {
			case telnetTypeOption:
				reply = append(reply, terminalTypeSend...)
				state.sent[option] = true
			case speedOption:
				reply = append(reply, speedSend...)
				state.sent[option] = true
			case environOption:
				reply = append(reply, environSend...)
				state.sent[option] = true
			}
		}
	case doVerb, dont:
		current, known := state.engine[option]
		if !known {
			if verb == doVerb {
				return request(wont, option)
			}
			return nil
		}
		switch {
		case verb == doVerb && current == stateWantYes:
			state.engine[option] = stateYes
			state.answered()
		case verb == doVerb && current == stateNo:
			state.engine[option] = stateYes
			reply = request(will, option)
		case verb == dont && current == stateWantYes:
			state.engine[option] = stateNo
			state.answered()
		case verb == dont && current == stateYes:
			state.engine[option] = stateNo
			reply = request(wont, option)
		}
	}
	return reply
}

// answered counts one of the eight opening requests answered, the last of which ends
// negotiation; after the Line has taken over the count no longer matters.
func (state *reading) answered() {
	state.answers++
	if state.answers == len(opening)/3 && !state.lineTook {
		state.ended = true
	}
}

// readAll feeds every byte of input and returns the replies and whether negotiation ended.
func (state *reading) readAll(input []byte) ([]byte, bool) {
	var replies []byte
	for _, value := range input {
		reply, _, _ := state.feed(value)
		replies = append(replies, reply...)
	}
	return replies, state.ended
}

// readLine feeds every byte of input as the Line reads it and returns the replies, the data
// handed on and the Synchs owed.
func (state *reading) readLine(input []byte) ([]byte, []byte, int) {
	var replies, data []byte
	before := state.synchs
	for _, value := range input {
		reply, handed, isData := state.feed(value)
		replies = append(replies, reply...)
		if isData {
			data = append(data, handed)
		}
	}
	return replies, data, state.synchs - before
}

// expectedReplies is what the whole stream gets during negotiation, by the test's own reading.
func expectedReplies(input []byte) []byte {
	replies, _ := freshReading().readAll(input)
	return replies
}

// connected is one loopback connection: the client end the scripted caller holds and the
// server end handed to the code under test, which writes urgent data as Accept's connection
// does, by the test's own call.
type connected struct {
	client *net.TCPConn
	server urgentConn
	// dialed is a moment before the server end existed, so before anything the server side did.
	dialed time.Time
}

// urgentConn is a server end that writes urgent data, as the contract's Conn needs, through
// the test's own MSG_OOB send.
type urgentConn struct {
	*net.TCPConn
}

func (connection urgentConn) WriteUrgent(buffer []byte) (int, error) {
	return sendUrgent(connection.TCPConn, buffer)
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
	return connected{client: client, server: urgentConn{TCPConn: server}, dialed: dialed}
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

// expectOpening reads the opening requests, which must come whole by the deadline.
func expectOpening(t *testing.T, connection net.Conn, deadline time.Time) {
	t.Helper()
	if got := readExactly(t, connection, len(opening), deadline); !bytes.Equal(got, opening) {
		t.Fatalf("the opening was\n% x\nwant\n% x", got, opening)
	}
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

// expectSynchs reads the bytes before a write of count Synchs and the Synchs' own bytes, then
// takes the urgent byte out of band: the stream holds IAC DM for each Synch but the last, then
// IAC, and the last DM is the urgent byte. The client keeps urgent data out of line, as every
// socket does by default, so the last DM can only be read as urgent data.
func expectSynchs(t *testing.T, client *net.TCPConn, before []byte, count int, deadline time.Time) {
	t.Helper()
	want := join(before, repeated(command(dataMark), count-1), []byte{iac})
	got := readExactly(t, client, len(want), deadline)
	if !bytes.Equal(got, want) {
		t.Fatalf("before the urgent byte the caller received\n% x\nwant\n% x", got, want)
	}
	urgent, err := receiveUrgent(t.Context(), client, deadline)
	if err != nil || !bytes.Equal(urgent, []byte{dataMark}) {
		t.Fatalf("the urgent data was % x and %v, want DM, %#02x", urgent, err, dataMark)
	}
}

// sending is when a caller's write began and when it returned. The engine can read the bytes and
// act on them before the writer's goroutine reads the clock again, so a window on what the
// engine does with them opens from began and closes from done.
type sending struct {
	began, done time.Time
}

// write sends bytes from the scripted caller and fails the test if they do not go. It returns
// when the write began and when it returned.
func write(t *testing.T, connection net.Conn, data []byte) sending {
	t.Helper()
	_ = connection.SetWriteDeadline(time.Now().Add(testrun.Patient(testrun.HangBound)))
	began := time.Now()
	if _, err := connection.Write(data); err != nil {
		t.Fatalf("the caller's write failed: %v", err)
	}
	return sending{began: began, done: time.Now()}
}

// writeUrgent sends bytes from the scripted caller with the last one as TCP urgent data, as a
// caller's Synch is sent.
func writeUrgent(t *testing.T, connection *net.TCPConn, data []byte) time.Time {
	t.Helper()
	if _, err := sendUrgent(connection, data); err != nil {
		t.Fatalf("the caller's urgent write failed: %v", err)
	}
	return time.Now()
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
