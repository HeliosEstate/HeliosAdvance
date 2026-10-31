// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests of the built program with two Telnet clients others wrote, run as outside programs and
// driven through their standard input and output, never read for their source: the stock Linux
// telnet client and PuTTY's Plink. A relay of the test's own between the client and the program
// records both directions, so each row holds the program's bytes to the test's own reading of
// what the client asked. Also what a caller sends inside a subnegotiation, kept from the local
// log and from the program's working directory.
package main_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// The engine's prompt, and the SENDs by RFC 1091, RFC 1079 and RFC 1572, written here from the
// page and the RFCs.
var (
	asked            = []byte(greeting + "What is your name? ")
	terminalTypeSend = []byte{iac, subnegotiationBegin, telnetTypeOption, 1, iac, subnegotiationEnd}
	speedSend        = []byte{iac, subnegotiationBegin, speedOption, 1, iac, subnegotiationEnd}
	environSend      = []byte{iac, subnegotiationBegin, environOption, 1, 0, 'U', 'S', 'E', 'R', iac, subnegotiationEnd}
)

// The states of RFC 1143.
const (
	stateWantYes = "WANTYES"
	stateYes     = "YES"
	stateNo      = "NO"
)

// replyReading is the test's own reading of the option requests a client sends, by RFC 1143
// section 7 and Part 4's two tables: the replies and SENDs each request draws, in order. It
// reads requests and skips subnegotiations; a client's other commands draw nothing here.
type replyReading struct {
	engine, caller map[byte]string
	sent           map[byte]bool
}

func newReplyReading() *replyReading {
	return &replyReading{
		engine: map[byte]string{echo: stateWantYes, sga: stateWantYes, binary: stateWantYes},
		caller: map[byte]string{sga: stateNo, binary: stateWantYes, telnetTypeOption: stateWantYes, windowSizeOption: stateWantYes, environOption: stateWantYes, speedOption: stateWantYes},
		sent:   map[byte]bool{},
	}
}

func (state *replyReading) replies(input []byte) []byte {
	var replies []byte
	for index := 0; index < len(input); index++ {
		if input[index] != iac || index+1 >= len(input) {
			continue
		}
		verb := input[index+1]
		if verb == subnegotiationBegin {
			for index += 2; index+1 < len(input) && (input[index] != iac || input[index+1] != subnegotiationEnd); index++ {
				if input[index] == iac {
					index++
				}
			}
			index++
			continue
		}
		if verb == iac {
			index++
			continue
		}
		if verb < will || index+2 >= len(input) {
			index++
			continue
		}
		replies = append(replies, state.answer(verb, input[index+2])...)
		index += 2
	}
	return replies
}

func (state *replyReading) answer(verb, option byte) []byte {
	switch verb {
	case will, wont:
		current, known := state.caller[option]
		if !known {
			if verb == will {
				return []byte{iac, dont, option}
			}
			return nil
		}
		var reply []byte
		switch {
		case verb == will && current == stateNo:
			reply = []byte{iac, doVerb, option}
		case verb == wont && current == stateYes:
			reply = []byte{iac, dont, option}
		}
		if verb == will {
			state.caller[option] = stateYes
			if current != stateYes && !state.sent[option] {
				switch option {
				case telnetTypeOption:
					reply = append(reply, terminalTypeSend...)
				case speedOption:
					reply = append(reply, speedSend...)
				case environOption:
					reply = append(reply, environSend...)
				}
				state.sent[option] = true
			}
		} else {
			state.caller[option] = stateNo
		}
		return reply
	default:
		current, known := state.engine[option]
		if !known {
			if verb == doVerb {
				return []byte{iac, wont, option}
			}
			return nil
		}
		var reply []byte
		switch {
		case verb == doVerb && current == stateNo:
			reply = []byte{iac, will, option}
		case verb == dont && current == stateYes:
			reply = []byte{iac, wont, option}
		}
		if verb == doVerb {
			state.engine[option] = stateYes
		} else {
			state.engine[option] = stateNo
		}
		return reply
	}
}

// relay passes one client's connection through to the program, recording each direction.
type relay struct {
	address    string
	mutex      sync.Mutex
	fromClient []byte
	fromEngine []byte
	done       chan struct{}
}

// startRelay listens on loopback for one client and connects it to the engine at address.
func startRelay(t *testing.T, address string) *relay {
	t.Helper()
	listening, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for the client: %v", err)
	}
	link := &relay{address: listening.Addr().String(), done: make(chan struct{})}
	go func() {
		defer close(link.done)
		defer func() { _ = listening.Close() }()
		client, err := listening.Accept()
		if err != nil {
			return
		}
		defer func() { _ = client.Close() }()
		engine, err := (&net.Dialer{Timeout: testrun.Patient(5 * time.Second)}).DialContext(context.Background(), "tcp", address)
		if err != nil {
			return
		}
		defer func() { _ = engine.Close() }()
		var copying sync.WaitGroup
		copying.Go(func() { link.copy(engine, client, &link.fromClient) })
		copying.Go(func() { link.copy(client, engine, &link.fromEngine) })
		copying.Wait()
	}()
	t.Cleanup(func() {
		_ = listening.Close()
		<-link.done
	})
	return link
}

// copy passes bytes on until the source ends, then shuts the destination's sending side.
func (link *relay) copy(destination, source net.Conn, record *[]byte) {
	chunk := make([]byte, 4096)
	for {
		_ = source.SetReadDeadline(time.Now().Add(30 * time.Second))
		got, err := source.Read(chunk)
		if got > 0 {
			link.mutex.Lock()
			*record = append(*record, chunk[:got]...)
			link.mutex.Unlock()
			_ = destination.SetWriteDeadline(time.Now().Add(testrun.Patient(5 * time.Second)))
			if _, writeErr := destination.Write(chunk[:got]); writeErr != nil {
				return
			}
		}
		if err != nil {
			if half, isTCP := destination.(*net.TCPConn); isTCP {
				_ = half.CloseWrite()
			}
			return
		}
	}
}

// clientRun is what an outside client showed and did.
type clientRun struct {
	stdout   []byte
	stderr   string
	exitErr  error
	timedOut bool
}

// runClient starts the client, waits for the prompt on its standard output, types Bob and LF, and
// reads its output to its end.
func runClient(t *testing.T, command *exec.Cmd) clientRun {
	t.Helper()
	command.WaitDelay = testrun.Patient(5 * time.Second)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var errorOutput bytes.Buffer
	command.Stderr = &errorOutput
	if err := command.Start(); err != nil {
		t.Fatalf("starting %s: %v", command.Path, err)
	}
	var result clientRun
	var mutex sync.Mutex
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		chunk := make([]byte, 4096)
		for {
			got, err := output.Read(chunk)
			mutex.Lock()
			result.stdout = append(result.stdout, chunk[:got]...)
			mutex.Unlock()
			if err != nil {
				return
			}
		}
	}()
	shown := func(text string) bool {
		mutex.Lock()
		defer mutex.Unlock()
		return bytes.Contains(result.stdout, []byte(text))
	}
	for deadline := time.Now().Add(testrun.Patient(15 * time.Second)); !shown("What is your name? ") && time.Now().Before(deadline); {
		pause(t, 20*time.Millisecond)
	}
	_, _ = io.WriteString(input, "Bob\n")
	timer := time.NewTimer(testrun.Patient(15 * time.Second))
	defer timer.Stop()
	select {
	case <-ended:
	case <-timer.C:
		result.timedOut = true
		_ = command.Process.Kill()
		<-ended
	}
	_ = input.Close()
	result.exitErr = command.Wait()
	result.stderr = errorOutput.String()
	return result
}

// expectClientCall checks one outside client's call: what it showed, and every byte the program
// sent it, against the test's own reading of what the client asked before it typed.
func expectClientCall(t *testing.T, link *relay, result clientRun) {
	t.Helper()
	<-link.done
	link.mutex.Lock()
	defer link.mutex.Unlock()
	t.Logf("the client sent % x", link.fromClient)
	if result.timedOut || result.exitErr != nil {
		t.Fatalf("the client did not end by itself: timed out %v, %v; stderr %q", result.timedOut, result.exitErr, result.stderr)
	}
	if !bytes.Contains(result.stdout, []byte(greeting+"What is your name? ")) || !bytes.HasSuffix(bytes.TrimSuffix(result.stdout, []byte("Connection closed by foreign host.\r\n")), []byte("Bob\r\nHello Bob\r\n")) {
		t.Fatalf("the client showed %q, want the greeting, the prompt, Bob and Hello Bob", result.stdout)
	}
	typed := bytes.Index(link.fromClient, []byte("Bob"))
	if typed < 0 {
		t.Fatalf("the client never sent Bob: % x", link.fromClient)
	}
	want := join(opening, newReplyReading().replies(link.fromClient[:typed]), asked, []byte("Bob\r\nHello Bob\r\n"))
	if !bytes.Equal(link.fromEngine, want) {
		t.Fatalf("the program sent the client\n% x\nwant\n% x", link.fromEngine, want)
	}
}

func join(parts ...[]byte) []byte {
	var joined []byte
	for _, part := range parts {
		joined = append(joined, part...)
	}
	return joined
}

// clientPath finds an outside client on the PATH; a missing one fails the row.
func clientPath(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("the %s client is not on this machine's PATH, which this row needs: %v", name, err)
	}
	return path
}

func TestPlinkClient(t *testing.T) {
	t.Parallel()
	plink := clientPath(t, "plink")
	lines := []string{
		"When it accepts a Telnet caller, the engine shall send IAC WILL ECHO, IAC WILL SGA, IAC WILL BINARY, IAC DO BINARY, IAC DO TTYPE, IAC DO NAWS, IAC DO NEW-ENVIRON and IAC DO TSPEED, in that order, and no other option request.",
		"When a Telnet caller has answered all eight opening requests, or 3 seconds after the engine sent them, whichever comes first, the engine shall write `Hello Helios Advance BBS!` and CR LF, then `What is your name? `.",
	}
	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			t.Parallel()
			t.Run("Plink, -telnet -batch, its input a pipe: it negotiates, shows the greeting, the prompt and Hello Bob", func(t *testing.T) {
				t.Parallel()
				program := startProgram(t, portOption, "0")
				link := startRelay(t, program.listening(t)[0])
				_, port, err := net.SplitHostPort(link.address)
				if err != nil {
					t.Fatal(err)
				}
				result := runClient(t, exec.CommandContext(t.Context(), plink, "-telnet", "-batch", "-P", port, "127.0.0.1"))
				expectClientCall(t, link, result)
			})
		})
	}
}

func TestLinuxTelnetClient(t *testing.T) {
	t.Parallel()
	telnet := clientPath(t, "telnet")
	lines := []string{
		"When it accepts a Telnet caller, the engine shall send IAC WILL ECHO, IAC WILL SGA, IAC WILL BINARY, IAC DO BINARY, IAC DO TTYPE, IAC DO NAWS, IAC DO NEW-ENVIRON and IAC DO TSPEED, in that order, and no other option request.",
		"When a Telnet caller has answered all eight opening requests, or 3 seconds after the engine sent them, whichever comes first, the engine shall write `Hello Helios Advance BBS!` and CR LF, then `What is your name? `.",
	}
	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			t.Parallel()
			t.Run("the stock telnet client, its input a pipe: it negotiates, shows the greeting, the prompt and Hello Bob", func(t *testing.T) {
				t.Parallel()
				program := startProgram(t, portOption, "0")
				link := startRelay(t, program.listening(t)[0])
				host, port, err := net.SplitHostPort(link.address)
				if err != nil {
					t.Fatal(err)
				}
				result := runClient(t, exec.CommandContext(t.Context(), telnet, host, port))
				expectClientCall(t, link, result)
			})
		})
	}
}

func TestNothingKept(t *testing.T) {
	t.Parallel()
	t.Run("The engine shall not store, log or show anything a caller sends inside a subnegotiation.", func(t *testing.T) {
		t.Parallel()
		t.Run("TTYPE, NEW-ENVIRON and NAWS reports holding a marker, during and after negotiation: not in the log, the stream or the working directory", func(t *testing.T) {
			t.Parallel()
			send := stopSignals()[0].prepare(t)
			directory := t.TempDir()
			command := exec.CommandContext(t.Context(), programPath, databaseOption, sharedRowFile(t), portOption, "0")
			command.Dir = directory
			program := startCommand(t, command)
			call := dial(t, program.listening(t)[0])
			reports := join(
				[]byte{iac, subnegotiationBegin, telnetTypeOption, 0}, []byte(canary), []byte{iac, subnegotiationEnd},
				[]byte{iac, subnegotiationBegin, environOption, 0, 0}, []byte("USER"), []byte{1}, []byte(canary), []byte{iac, subnegotiationEnd},
				[]byte{iac, subnegotiationBegin, windowSizeOption, 0, 80, 0, 24, iac, subnegotiationEnd})
			agreed := []byte{iac, doVerb, echo, iac, doVerb, sga, iac, doVerb, binary, iac, will, binary,
				iac, will, telnetTypeOption, iac, will, windowSizeOption, iac, will, environOption, iac, will, speedOption}
			call.readExactly(t, opening, call.connected.Add(testrun.Patient(margin)))
			call.send(t, join(agreed, reports))
			call.readExactly(t, join(terminalTypeSend, environSend, speedSend, asked), time.Now().Add(testrun.Patient(margin)))
			call.send(t, join([]byte("a"), reports, []byte("b\r")))
			call.readExactly(t, []byte("ab\r\nHello ab\r\n"), time.Now().Add(testrun.Patient(margin)))
			call.expectEnd(t, time.Now(), time.Now().Add(testrun.Patient(margin)))
			_, sentBy := send(t, program)
			program.exit(t, sentBy.Add(testrun.Patient(margin)))
			if strings.Contains(program.text(), canary) {
				t.Fatalf("the local log holds what a caller sent inside a subnegotiation:\n%s", program.text())
			}
			program.expectLog(t, "started")
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 0 {
				t.Fatalf("the program's working directory holds %v (%v), want nothing", entries, err)
			}
		})
	})
}
