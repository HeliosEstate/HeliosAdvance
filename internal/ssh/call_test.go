// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The page's lines for an SSH caller, from outside: the built program with a host key made for
// the row, called by the OpenSSH client, the oracle for the call, and by QA's own client for what
// that client will not send in order.
package ssh_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

const asked = greeting + prompt

// echoOf is the echo of a name ended with CR or LF while the board echoes.
func echoOf(name string) string { return name + "\r\n" }

func helloTo(name string) string { return "Hello " + name + "\r\n" }

// readUntil reads channel data until what the caller received ends with suffix.
func (client *rawClient) readUntil(suffix string, deadline time.Time) {
	client.t.Helper()
	for !bytes.HasSuffix(client.received, []byte(suffix)) {
		payload, err := client.next(deadline)
		if err != nil {
			client.t.Fatalf("after %q, waiting for %q: %v", client.received, suffix, err)
		}
		if payload[0] != messageChannelData {
			client.t.Fatalf("after %q, message %d where channel data belongs", client.received, payload[0])
		}
	}
}

// callAtPrompt signs in to the program, asks for a terminal when terminal is set, asks for the
// shell, and reads the greeting and the prompt.
func callAtPrompt(t *testing.T, program *engine, terminal bool) *rawClient {
	t.Helper()
	client := readyClient(t, program.ssh, "anyone")
	client.toShell(terminal)
	client.readUntil(asked, time.Now().Add(patient(5*time.Second)))
	return client
}

// expectStream fails the row unless the caller received exactly want.
func (client *rawClient) expectStream(want string) {
	client.t.Helper()
	if string(client.received) != want {
		client.t.Fatalf("the caller received %q, want %q", client.received, want)
	}
}

// expectNameEnd reads until the Hello that ends want, and checks the whole stream.
func (client *rawClient) expectNameEnd(want string) {
	client.t.Helper()
	client.readUntil(want[strings.LastIndex(want, "Hello "):], time.Now().Add(patient(5*time.Second)))
	client.expectStream(want)
}

// callAfterEnd signs in to the program, asks for a terminal when terminal is set, sends typed as
// channel data, then end of file, and fails the row unless the connection stays open and quiet;
// then it asks for the shell and returns once the shell is answered.
func callAfterEnd(t *testing.T, program *engine, terminal bool, typed string) *rawClient {
	t.Helper()
	client := readyClient(t, program.ssh, "anyone")
	if terminal {
		if reply := client.request("pty-req", true, ptyRequest("xterm", []byte{0})); reply[0] != messageChannelSuccess {
			t.Fatalf("the pty-req: message %d, want SUCCESS", reply[0])
		}
	}
	if typed != "" {
		client.sendData(typed)
	}
	client.sendPacket(message(messageChannelEOF).uint32Value(client.engineChannel).data)
	client.expectOpen()
	if reply := client.request("shell", true, nil); reply[0] != messageChannelSuccess {
		t.Fatalf("the shell after the end of file: message %d, want SUCCESS", reply[0])
	}
	return client
}

// expectOpen fails the row unless, for quietFor, nothing comes and the connection stays open: the
// read must give up at its deadline, not see the connection end.
func (client *rawClient) expectOpen() {
	client.t.Helper()
	payload, err := client.next(time.Now().Add(quietFor))
	if err == nil {
		client.t.Fatalf("the engine sent message %d after the end of file alone, want nothing", payload[0])
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		client.t.Fatalf("the connection ended after the end of file alone (%v), want it open", err)
	}
}

// expectClosedAfter reads to the connection's end and fails the row unless the caller received
// exactly want, as channel data and no other message, and the end came within margin of from.
func (client *rawClient) expectClosedAfter(from time.Time, want string) {
	client.t.Helper()
	kinds, ended := client.expectEnd(from.Add(patient(margin + time.Second)))
	for _, kind := range kinds {
		if kind != messageChannelData {
			client.t.Fatalf("the engine sent messages %v before the close, want channel data alone", kinds)
		}
	}
	client.expectStream(want)
	expectWithin(client.t, "the engine's close", ended, from, from.Add(margin))
}

// expectOneCloseAfter reads to the connection's end and fails the row unless, beside channel data,
// the engine sent one channel close and nothing else, and the end came within margin of from.
func (client *rawClient) expectOneCloseAfter(from time.Time) {
	client.t.Helper()
	kinds, ended := client.expectEnd(from.Add(patient(margin + time.Second)))
	closes, others := 0, 0
	for _, kind := range kinds {
		switch kind {
		case messageChannelData:
		case messageChannelClose:
			closes++
		default:
			others++
		}
	}
	if closes != 1 || others != 0 {
		client.t.Fatalf("the engine sent messages %v before the close, want one channel close beside channel data", kinds)
	}
	expectWithin(client.t, "the engine's close", ended, from, from.Add(margin))
}

func TestCall(t *testing.T) {
	t.Parallel()

	t.Run("When an SSH caller has signed in and asked for a shell, the engine shall write `Hello Helios Advance BBS!` and CR LF, then `What is your name? `.", func(t *testing.T) {
		t.Parallel()
		for _, terminal := range []bool{true, false} {
			name := "the OpenSSH client with -T"
			if terminal {
				name = "the OpenSSH client with -tt"
			}
			t.Run(name+": the greeting and the prompt, first", func(t *testing.T) {
				t.Parallel()
				program := startEngine(t)
				result := runOpenSSH(t, program, openSSHCall{terminal: terminal, waitFor: prompt, typed: typedBob})
				if !bytes.HasPrefix(result.stdout, []byte(asked)) {
					t.Fatalf("the client wrote %q, want it to begin with %q", result.stdout, asked)
				}
			})
		}
		t.Run("signed in with a terminal, no shell yet: nothing; then the shell: the greeting and the prompt", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := readyClient(t, program.ssh, "anyone")
			if reply := client.request("pty-req", true, ptyRequest("xterm", []byte{0})); reply[0] != messageChannelSuccess {
				t.Fatalf("the pty-req: message %d", reply[0])
			}
			client.expectQuiet()
			client.toShell(false)
			client.readData(len(asked), time.Now().Add(patient(5*time.Second)))
			client.expectQuiet()
			client.expectStream(asked)
		})
		t.Run("the shell with no terminal: the greeting and the prompt as channel data", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := readyClient(t, program.ssh, "anyone")
			client.toShell(false)
			client.readData(len(asked), time.Now().Add(patient(5*time.Second)))
			client.expectQuiet()
			client.expectStream(asked)
		})
	})

	echoRows := []struct{ name, typed, echo, hello string }{
		{"abc CR", "abc\r", echoOf("abc"), helloTo("abc")},
		{"abc LF", "abc\n", echoOf("abc"), helloTo("abc")},
		{"abx BS c CR", "abx\bc\r", "abx\b \bc\r\n", helloTo("abc")},
		{"abx DEL c CR", "abx\x7fc\r", "abx\b \bc\r\n", helloTo("abc")},
	}

	t.Run("While an SSH caller has asked for a terminal, the engine shall echo as it does for a Telnet caller that agreed to ECHO.", func(t *testing.T) {
		t.Parallel()
		for _, row := range echoRows {
			t.Run("the OpenSSH client with -tt, "+row.name+": the echo, then Hello", func(t *testing.T) {
				t.Parallel()
				program := startEngine(t)
				result := runOpenSSH(t, program, openSSHCall{terminal: true, waitFor: prompt, typed: row.typed})
				expectCall(t, result, asked+row.echo+row.hello)
			})
			t.Run("QA's client with a pty-req, "+row.name+": the echo, then Hello", func(t *testing.T) {
				t.Parallel()
				program := startEngine(t)
				client := callAtPrompt(t, program, true)
				client.sendData(row.typed)
				client.expectNameEnd(asked + row.echo + row.hello)
			})
		}
	})

	t.Run("While an SSH caller has not asked for a terminal, the engine shall echo nothing.", func(t *testing.T) {
		t.Parallel()
		t.Run("the OpenSSH client with -T, abc BS d CR: Hello abd alone", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			result := runOpenSSH(t, program, openSSHCall{waitFor: prompt, typed: "abc\bd\r"})
			expectCall(t, result, asked+helloTo("abd"))
		})
		t.Run("QA's client with no pty-req, ab CR: Hello ab alone", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := callAtPrompt(t, program, false)
			client.sendData("ab\r")
			client.expectNameEnd(asked + helloTo("ab"))
		})
		t.Run("QA's client with a pty-req after the shell, refused, ab CR: Hello ab alone", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := callAtPrompt(t, program, false)
			if reply := client.request("pty-req", true, ptyRequest("xterm", []byte{0})); reply[0] != messageChannelFailure {
				t.Fatalf("a pty-req after the shell: message %d, want FAILURE", reply[0])
			}
			client.sendData("ab\r")
			client.expectNameEnd(asked + helloTo("ab"))
		})
	})

	t.Run("When `Hello <name>` is written to an SSH caller, the engine shall send exit status 0 and end of file, and close the channel.", func(t *testing.T) {
		t.Parallel()
		t.Run("QA's client: Hello bob, then exactly exit-status 0, end of file and the close, once, and nothing more", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := callAtPrompt(t, program, false)
			client.sendData(typedBob)
			client.readUntil(helloTo("bob"), time.Now().Add(patient(5*time.Second)))
			expectClosingMessages(t, client, "")
			client.expectStream(asked + helloTo("bob"))
			client.sendPacket(message(messageChannelClose).uint32Value(client.engineChannel).data)
			if kinds, _ := client.expectEnd(time.Now().Add(closingWait + patient(margin+time.Second))); len(kinds) != 0 {
				t.Fatalf("after the close the engine sent messages %v, want none", kinds)
			}
		})
		for _, terminal := range []bool{true, false} {
			name := "bob CR, end of file, a wait, then shell, with no pty-req"
			want := asked + helloTo("bob")
			if terminal {
				name = "a pty-req, bob CR, end of file, a wait, then shell"
				want = asked + echoOf("bob") + helloTo("bob")
			}
			t.Run(name+": Hello bob, then exactly exit-status 0, end of file and the close", func(t *testing.T) {
				t.Parallel()
				program := startEngine(t)
				client := callAfterEnd(t, program, terminal, typedBob)
				client.readUntil(helloTo("bob"), time.Now().Add(patient(5*time.Second)))
				expectClosingMessages(t, client, "")
				client.expectStream(want)
				// The engine's close waits up to 3 seconds for the caller's.
				_ = client.connection.Close()
			})
		}
		for _, terminal := range []bool{true, false} {
			name := "-T"
			want := asked + helloTo("bob")
			if terminal {
				name = "-tt"
				want = asked + echoOf("bob") + helloTo("bob")
			}
			t.Run("the OpenSSH client with "+name+": the call, and exit code 0", func(t *testing.T) {
				t.Parallel()
				program := startEngine(t)
				expectCall(t, runOpenSSH(t, program, openSSHCall{terminal: terminal, waitFor: prompt, typed: typedBob}), want)
			})
		}
	})

	t.Run("When an SSH caller closes the connection, or 3 seconds after the engine closed the channel, whichever comes first, the engine shall close the connection.", func(t *testing.T) {
		t.Parallel()
		t.Run("callers that close once the channel's close arrives: their places are free at once", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			var closed time.Time
			for range connectionCap {
				closingCaller(t, program)
				closed = time.Now()
			}
			expectServedBy(t, program.ssh, closed.Add(margin))
		})
		t.Run("a caller that stays: closed 3 seconds after the channel's close, not before", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := callAtPrompt(t, program, false)
			nameSent := time.Now()
			client.sendData(typedBob)
			client.readUntil(helloTo("bob"), time.Now().Add(patient(5*time.Second)))
			expectClosingMessages(t, client, "")
			closeReceived := time.Now()
			_, ended := client.expectEnd(closeReceived.Add(closingWait + patient(2*margin)))
			// The window opens 3 seconds after the name's CR went, a moment provably before the
			// engine's channel close, and shuts 3 seconds and the margin after the caller saw it.
			expectWithin(t, "the engine's close", ended, nameSent.Add(closingWait), closeReceived.Add(closingWait+margin))
		})
		t.Run("Hello after 68 seconds: closed at the 70-second ceiling, not 3 seconds after the channel's close", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			dialed := time.Now()
			client := readyClient(t, program.ssh, "anyone")
			connected := time.Now()
			// The shell at 9 seconds sets the name's 60 seconds to end at 69, so a name typed
			// at 68.3 gets its Hello after 68 seconds and inside the ceiling.
			waitUntil(t, dialed.Add(9*time.Second))
			client.toShell(false)
			client.readUntil(asked, time.Now().Add(patient(5*time.Second)))
			waitUntil(t, dialed.Add(68300*time.Millisecond))
			client.sendData("a\r")
			client.readUntil(helloTo("a"), time.Now().Add(patient(5*time.Second)))
			helloAt := time.Now()
			if helloAt.Before(dialed.Add(68 * time.Second)) {
				t.Fatalf("Hello came %v after the dial, before 68 seconds: the row proves nothing", helloAt.Sub(dialed))
			}
			_, ended := client.expectEnd(connected.Add(ceilingLimit + closingWait + patient(margin)))
			expectWithin(t, "the engine's close", ended, dialed.Add(ceilingLimit), connected.Add(ceilingLimit+margin))
		})
	})

	t.Run("The engine shall send the version line `SSH-2.0-HeliosAdvance` and CR LF.", func(t *testing.T) {
		t.Parallel()
		t.Run("a caller that sends nothing: exactly the version line first", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := dialRaw(t, program.ssh)
			if err := client.fill(len(versionLine), time.Now().Add(patient(5*time.Second))); err != nil {
				t.Fatalf("reading the version line: %v", err)
			}
			if got := string(client.take(len(versionLine))); got != versionLine {
				t.Fatalf("the first bytes were %q, want %q", got, versionLine)
			}
		})
		t.Run("the OpenSSH client: the remote software version is HeliosAdvance", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			result := runOpenSSH(t, program, openSSHCall{verbose: true, waitFor: prompt, typed: typedBob})
			if !strings.Contains(result.stderr, "remote software version HeliosAdvance") {
				t.Fatalf("the client's report holds no remote software version HeliosAdvance")
			}
		})
	})

	t.Run("The engine shall offer only the key exchanges `mlkem768x25519-sha256`, `curve25519-sha256` and `curve25519-sha256@libssh.org` with the marker `kex-strict-s-v00@openssh.com`, the ciphers `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com` and `aes128-gcm@openssh.com`, the MAC `hmac-sha2-256-etm@openssh.com`, compression `none` and an `ssh-ed25519` host key.", func(t *testing.T) {
		t.Parallel()
		t.Run("the engine's KEXINIT: exactly these lists", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := dialRaw(t, program.ssh)
			client.sendVersion()
			expectKexInit(t, client.readServerKexInit(time.Now().Add(patient(5*time.Second))))
		})
		for _, option := range []string{"KexAlgorithms=diffie-hellman-group14-sha256", "KexAlgorithms=ecdh-sha2-nistp256",
			"Ciphers=aes128-ctr", "Ciphers=aes256-cbc", "HostKeyAlgorithms=rsa-sha2-256", "HostKeyAlgorithms=ecdsa-sha2-nistp256"} {
			t.Run("the OpenSSH client offering only "+option+": refused", func(t *testing.T) {
				t.Parallel()
				program := startEngine(t)
				expectRefused(t, runOpenSSH(t, program, openSSHCall{options: []string{"-o", option}, closeInput: true}))
			})
		}
		for _, option := range []string{"Ciphers=chacha20-poly1305@openssh.com", "Ciphers=aes256-gcm@openssh.com",
			"Ciphers=aes128-gcm@openssh.com", "KexAlgorithms=curve25519-sha256", "KexAlgorithms=curve25519-sha256@libssh.org"} {
			t.Run("the edge, the OpenSSH client offering only "+option+": the call", func(t *testing.T) {
				t.Parallel()
				program := startEngine(t)
				expectCall(t, runOpenSSH(t, program, openSSHCall{options: []string{"-o", option}, waitFor: prompt, typed: typedBob}),
					asked+helloTo("bob"))
			})
		}
		t.Run("the edge, QA's client offering only mlkem768x25519-sha256: the call", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := dialRaw(t, program.ssh)
			client.handshake(hybridExchange(t), true)
			client.signIn("anyone")
			client.openChannel("session", 0, nil)
			client.toShell(false)
			client.readUntil(asked, time.Now().Add(patient(5*time.Second)))
		})
	})

	t.Run("When an SSH caller offers strict key exchange, the engine shall use it.", func(t *testing.T) {
		t.Parallel()
		ignoreDuringExchange := func(t *testing.T, strict bool) ([]byte, error) {
			t.Helper()
			program := startEngine(t)
			client := dialRaw(t, program.ssh)
			client.sendVersion()
			client.readServerKexInit(time.Now().Add(patient(5 * time.Second)))
			client.sendKexInit(defaultOffer("curve25519-sha256", strict))
			client.sendPacket(message(messageIgnore).text("strict").data)
			exchange := curveExchange(t, "curve25519-sha256")
			client.sendPacket(message(messageKexInit30).bytesValue(exchange.initial).data)
			return client.nextIgnoring(time.Now().Add(patient(margin + time.Second)))
		}
		t.Run("strict offered, an IGNORE before the key exchange's first message: the connection ends with no reply", func(t *testing.T) {
			t.Parallel()
			if payload, err := ignoreDuringExchange(t, true); !isEnd(err) {
				t.Fatalf("after the IGNORE the engine sent %v, %v, want the end of the connection", payload, err)
			}
		})
		t.Run("the same IGNORE, strict not offered: the key exchange's reply", func(t *testing.T) {
			t.Parallel()
			if payload, err := ignoreDuringExchange(t, false); err != nil || payload[0] != messageKexReply31 {
				t.Fatalf("after the IGNORE the engine sent %v, %v, want the key exchange's reply", payload, err)
			}
		})
		t.Run("the OpenSSH client: it reports strict key exchange in use", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			result := runOpenSSH(t, program, openSSHCall{verbose: true, waitFor: prompt, typed: typedBob})
			if !strings.Contains(result.stderr, "will use strict KEX ordering") {
				t.Fatalf("the client's report does not say strict key exchange is in use")
			}
		})
	})

	t.Run("The engine shall accept the sign-in method `none` under any username.", func(t *testing.T) {
		t.Parallel()
		for _, user := range []struct{ name, user string }{
			{"an empty username", ""},
			{"root", "root"},
			{"255 characters", strings.Repeat("u", 255)},
			{"UTF-8 beyond ASCII", "café-名前"},
		} {
			t.Run("QA's client, "+user.name+": signed in, and the call", func(t *testing.T) {
				t.Parallel()
				program := startEngine(t)
				client := readyClient(t, program.ssh, user.user)
				client.toShell(false)
				client.readUntil(asked, time.Now().Add(patient(5*time.Second)))
			})
		}
		t.Run("the OpenSSH client as anyone: the call", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			expectCall(t, runOpenSSH(t, program, openSSHCall{user: "anyone", waitFor: prompt, typed: typedBob}), asked+helloTo("bob"))
		})
	})

	t.Run("If an SSH caller tries any sign-in method but `none`, then the engine shall close the connection.", func(t *testing.T) {
		t.Parallel()
		for _, method := range []struct {
			name  string
			extra []byte
		}{
			{"password", (&wire{}).boolean(false).text("secret").data},
			{"publickey", (&wire{}).boolean(false).text("ssh-ed25519").bytesValue(make([]byte, 51)).data},
			{"keyboard-interactive", (&wire{}).text("").text("").data},
			{"hostbased", (&wire{}).text("ssh-ed25519").bytesValue(nil).text("host").text("user").bytesValue(nil).data},
			{unknownName, nil},
		} {
			t.Run(method.name+" first: no reply, and the connection closed at once", func(t *testing.T) {
				t.Parallel()
				program := startEngine(t)
				client := dialRaw(t, program.ssh)
				client.handshake(curveExchange(t, "curve25519-sha256"), true)
				out := message(messageUserauthRequest).text("anyone").text("ssh-connection").text(method.name)
				out.data = append(out.data, method.extra...)
				client.sendPacket(out.data)
				sent := time.Now()
				kinds, ended := client.expectEnd(sent.Add(patient(margin + time.Second)))
				if len(kinds) > 1 || (len(kinds) == 1 && kinds[0] != messageDisconnect) {
					t.Fatalf("the engine sent messages %v before the close, want at most a DISCONNECT", kinds)
				}
				expectWithin(t, "the engine's close", ended, sent, sent.Add(margin))
			})
		}
		t.Run("the edge: none first, signed in", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := dialRaw(t, program.ssh)
			client.handshake(curveExchange(t, "curve25519-sha256"), true)
			client.signIn("anyone")
		})
	})

	t.Run("The engine shall accept the first `session` channel on a connection, and refuse every other channel.", func(t *testing.T) {
		t.Parallel()
		t.Run("a second session, before and after the shell: refused, and the first's call goes on", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := readyClient(t, program.ssh, "anyone")
			if reply := client.openChannel("session", 1, nil); reply[0] != messageChannelOpenFailure {
				t.Fatalf("a second session: message %d, want OPEN_FAILURE", reply[0])
			}
			client.toShell(false)
			client.readUntil(asked, time.Now().Add(patient(5*time.Second)))
			if reply := client.openChannel("session", 2, nil); reply[0] != messageChannelOpenFailure {
				t.Fatalf("a session after the shell: message %d, want OPEN_FAILURE", reply[0])
			}
			client.sendData(typedBob)
			client.expectNameEnd(asked + helloTo("bob"))
		})
		for _, kind := range []string{directChannel, streamLocalChannel, "x11", unknownName} {
			t.Run(kind+" before any session: refused, and the session after it accepted", func(t *testing.T) {
				t.Parallel()
				program := startEngine(t)
				client := dialRaw(t, program.ssh)
				client.handshake(curveExchange(t, "curve25519-sha256"), true)
				client.signIn("anyone")
				extra := (&wire{}).text("127.0.0.1").uint32Value(9).text("127.0.0.1").uint32Value(1).data
				if reply := client.openChannel(kind, 5, extra); reply[0] != messageChannelOpenFailure {
					t.Fatalf("the %s channel: message %d, want OPEN_FAILURE", kind, reply[0])
				}
				if reply := client.openChannel("session", 0, nil); reply[0] != messageChannelConfirmation {
					t.Fatalf("the session: message %d, want OPEN_CONFIRMATION", reply[0])
				}
			})
		}
		t.Run("the OpenSSH client forwarding a local port: the forwarded connection closed, and the call goes on", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			local := freePort(t)
			result := runOpenSSHForwarding(t, program, local)
			expectCall(t, result.openSSHResult, asked+helloTo("bob"))
			if result.forwardedBytes != 0 || !errors.Is(result.forwardedEnd, io.EOF) {
				t.Fatalf("the forwarded connection read %d bytes and %v, want end of file at once", result.forwardedBytes, result.forwardedEnd)
			}
		})
	})

	t.Run("The engine shall accept `pty-req` and `shell` on the session channel until the first `shell`, and refuse every other channel request and every global request.", func(t *testing.T) {
		t.Parallel()
		t.Run("pty-req twice and then shell: each accepted", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := readyClient(t, program.ssh, "anyone")
			for range 2 {
				if reply := client.request("pty-req", true, ptyRequest("xterm", []byte{0})); reply[0] != messageChannelSuccess {
					t.Fatalf("the pty-req: message %d, want SUCCESS", reply[0])
				}
			}
			client.toShell(false)
		})
		for _, request := range []string{"exec", "subsystem", "env", "x11-req", "auth-agent-req@openssh.com",
			"window-change", "signal", "break", unknownName} {
			t.Run(request+" before the shell: refused, and the call goes on", func(t *testing.T) {
				t.Parallel()
				program := startEngine(t)
				client := readyClient(t, program.ssh, "anyone")
				if reply := client.request(request, true, (&wire{}).text("x").text("y").data); reply[0] != messageChannelFailure {
					t.Fatalf("the %s request: message %d, want FAILURE", request, reply[0])
				}
				client.toShell(false)
				client.readUntil(asked, time.Now().Add(patient(5*time.Second)))
			})
		}
		t.Run("a second shell after the first: refused, and no second greeting", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := callAtPrompt(t, program, false)
			if reply := client.request("shell", true, nil); reply[0] != messageChannelFailure {
				t.Fatalf("a second shell: message %d, want FAILURE", reply[0])
			}
			client.expectQuiet()
			client.expectStream(asked)
		})
		t.Run("pty-req after the shell: refused, and still no echo", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := callAtPrompt(t, program, false)
			if reply := client.request("pty-req", true, ptyRequest("xterm", []byte{0})); reply[0] != messageChannelFailure {
				t.Fatalf("a pty-req after the shell: message %d, want FAILURE", reply[0])
			}
			client.sendData("ab\r")
			client.expectNameEnd(asked + helloTo("ab"))
		})
		for _, request := range []string{"tcpip-forward", "cancel-tcpip-forward", "keepalive@openssh.com",
			"no-more-sessions@openssh.com", unknownName} {
			t.Run("the global request "+request+": refused", func(t *testing.T) {
				t.Parallel()
				program := startEngine(t)
				client := callAtPrompt(t, program, false)
				client.sendPacket(message(messageGlobalRequest).text(request).boolean(true).text("127.0.0.1").uint32Value(0).data)
				if reply, err := client.next(time.Now().Add(patient(5 * time.Second))); err != nil || reply[0] != messageRequestFailure {
					t.Fatalf("the %s request: %v, %v, want REQUEST_FAILURE", request, reply, err)
				}
			})
		}
		t.Run("a refused request asking no reply: nothing written, and the call goes on", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := callAtPrompt(t, program, false)
			client.request("exec", false, (&wire{}).text("ls").data)
			client.expectQuiet()
			client.sendData("ab\r")
			client.expectNameEnd(asked + helloTo("ab"))
		})
		t.Run("1000 refused channels and 1000 refused requests before the shell: each answered once, then the call", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := readyClient(t, program.ssh, "anyone")
			for number := range 1000 {
				out := message(messageChannelOpen).text(directChannel).uint32Value(uint32(number + 10)).
					uint32Value(clientWindow).uint32Value(clientMaxPacket)
				out.data = append(out.data, (&wire{}).text("127.0.0.1").uint32Value(9).text("127.0.0.1").uint32Value(1).data...)
				client.sendPacket(out.data)
				client.sendPacket(message(messageChannelRequest).uint32Value(client.engineChannel).text("env").boolean(true).text("A").text("B").data)
			}
			failures := map[byte]int{}
			for range 2000 {
				payload, err := client.next(time.Now().Add(patient(10 * time.Second)))
				if err != nil {
					t.Fatalf("after %v replies: %v", failures, err)
				}
				failures[payload[0]]++
			}
			if failures[messageChannelOpenFailure] != 1000 || failures[messageChannelFailure] != 1000 {
				t.Fatalf("the replies were %v, want 1000 OPEN_FAILURE and 1000 FAILURE", failures)
			}
			client.toShell(false)
			client.readUntil(asked, time.Now().Add(patient(5*time.Second)))
			client.expectStream(asked)
		})
		for _, row := range []struct {
			name string
			call openSSHCall
		}{
			{"a command, which asks for exec", openSSHCall{command: []string{"ls"}, closeInput: true}},
			{"-s sftp, which asks for the subsystem", openSSHCall{options: []string{"-s"}, command: []string{"sftp"}, closeInput: true}},
			{"-R with ExitOnForwardFailure, which sends tcpip-forward", openSSHCall{
				options: []string{"-o", "ExitOnForwardFailure=yes", "-R", "0:127.0.0.1:9"}, closeInput: true}},
		} {
			t.Run("the OpenSSH client with "+row.name+": refused", func(t *testing.T) {
				t.Parallel()
				program := startEngine(t)
				expectRefused(t, runOpenSSH(t, program, row.call))
			})
		}
	})

	t.Run("The engine shall discard everything an SSH caller sends as extended data.", func(t *testing.T) {
		t.Parallel()
		t.Run("extended XYZ before the shell and between a and b CR, with a terminal: the echo of ab alone, and Hello ab", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := readyClient(t, program.ssh, "anyone")
			client.sendExtended("XYZ")
			client.toShell(true)
			client.readUntil(asked, time.Now().Add(patient(5*time.Second)))
			client.sendData("a")
			client.sendExtended("XYZ")
			client.sendData("b\r")
			client.expectNameEnd(asked + echoOf("ab") + helloTo("ab"))
		})
	})

	t.Run("If an SSH caller closes the channel before the name ends, then the engine shall close the connection, writing nothing more but the channel close SSH requires in reply.", func(t *testing.T) {
		t.Parallel()
		t.Run("ab, then the channel's close: one channel close, and the connection closed at once", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := callAtPrompt(t, program, true)
			client.sendData("ab")
			client.readUntil("ab", time.Now().Add(patient(5*time.Second)))
			client.sendPacket(message(messageChannelClose).uint32Value(client.engineChannel).data)
			client.expectOneCloseAfter(time.Now())
			client.expectStream(asked + "ab")
		})
		t.Run("before the shell, 300 bytes unread, then the channel's close: one channel close and nothing else, and the connection closed at once", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := readyClient(t, program.ssh, "anyone")
			client.sendData(strings.Repeat("a", 300))
			client.sendPacket(message(messageChannelClose).uint32Value(client.engineChannel).data)
			client.expectOneCloseAfter(time.Now())
			client.expectStream("")
		})
		t.Run("before the shell, end of file, a wait, then the channel's close: one channel close and nothing else, and the connection closed at once from the close", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := readyClient(t, program.ssh, "anyone")
			client.sendPacket(message(messageChannelEOF).uint32Value(client.engineChannel).data)
			client.expectOpen()
			client.sendPacket(message(messageChannelClose).uint32Value(client.engineChannel).data)
			client.expectOneCloseAfter(time.Now())
			client.expectStream("")
		})
	})

	t.Run("If an SSH caller's data ends, by end of file, before the name ends, then, once the caller has asked for a shell and the greeting and name prompt are written, the engine shall close the connection when it reaches the end of file, writing nothing more but the channel close SSH requires in reply.", func(t *testing.T) {
		t.Parallel()
		for _, row := range []struct {
			name     string
			terminal bool
			typed    string
			want     string
		}{
			{"a pty-req, ab, end of file, a wait, then shell: the greeting, the prompt and the echo of ab, then the close and nothing more",
				true, "ab", asked + "ab"},
			{"ab, end of file, a wait, then shell, with no pty-req: the greeting and the prompt, then the close and nothing more",
				false, "ab", asked},
			{"a pty-req, 300 bytes, more than the Channel holds, end of file, a wait, then shell: the greeting, the prompt and the first 30 echoed, then the close and nothing more",
				true, strings.Repeat("a", 300), asked + strings.Repeat("a", 30)},
			{"a pty-req, end of file, a wait, then shell: the greeting and the prompt, then the close and nothing more",
				true, "", asked},
		} {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				program := startEngine(t)
				client := callAfterEnd(t, program, row.terminal, row.typed)
				client.expectClosedAfter(time.Now(), row.want)
			})
		}
		for _, row := range []struct {
			name     string
			terminal bool
			typed    string
			want     string
		}{
			{"end of file and shell in one write: the greeting and the prompt, then the close and nothing more",
				false, "", asked},
			{"a pty-req, then ab, end of file and shell in one write: the greeting, the prompt and the echo of ab, then the close and nothing more",
				true, "ab", asked + "ab"},
		} {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				program := startEngine(t)
				client := readyClient(t, program.ssh, "anyone")
				if row.terminal {
					if reply := client.request("pty-req", true, ptyRequest("xterm", []byte{0})); reply[0] != messageChannelSuccess {
						t.Fatalf("the pty-req: message %d, want SUCCESS", reply[0])
					}
				}
				var together [][]byte
				if row.typed != "" {
					together = append(together, message(messageChannelData).uint32Value(client.engineChannel).text(row.typed).data)
				}
				together = append(together,
					message(messageChannelEOF).uint32Value(client.engineChannel).data,
					message(messageChannelRequest).uint32Value(client.engineChannel).text("shell").boolean(true).data)
				client.sendTogether(together...)
				if reply, err := client.next(time.Now().Add(patient(5 * time.Second))); err != nil || reply[0] != messageChannelSuccess {
					t.Fatalf("the shell's reply: %v, %v, want SUCCESS", reply, err)
				}
				client.expectClosedAfter(time.Now(), row.want)
			})
		}
		t.Run("after the prompt, with a terminal, ab and its echo, then end of file: nothing more, and the connection closed at once", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := callAtPrompt(t, program, true)
			client.sendData("ab")
			client.readUntil("ab", time.Now().Add(patient(5*time.Second)))
			client.sendPacket(message(messageChannelEOF).uint32Value(client.engineChannel).data)
			client.expectClosedAfter(time.Now(), asked+"ab")
		})
		t.Run("the OpenSSH client with -T, its input closed after ab: the greeting and the prompt, no Hello", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			result := runOpenSSH(t, program, openSSHCall{waitFor: prompt, typed: "ab", closeInput: true})
			if string(result.stdout) != asked {
				t.Fatalf("the client wrote %q, want %q alone", result.stdout, asked)
			}
		})
	})

	t.Run("When Open returns an error or a nil KindConnection, or Run returns anything but session.Answered, the listener package shall close the connection without writing to it and without calling Close.", func(t *testing.T) {
		t.Parallel()
		t.Run("over SSH, end of file before the shell, then shell: no exit status, end of file or channel close from the engine", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := callAfterEnd(t, program, false, "")
			client.expectClosedAfter(time.Now(), asked)
		})
		t.Run("over SSH, after the prompt, end of file: no exit status, end of file or channel close from the engine", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := callAtPrompt(t, program, false)
			client.sendPacket(message(messageChannelEOF).uint32Value(client.engineChannel).data)
			client.expectClosedAfter(time.Now(), asked)
		})
		t.Run("over SSH, after the prompt, the channel's close: the one channel close in reply, and no exit status or end of file", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := callAtPrompt(t, program, false)
			client.sendPacket(message(messageChannelClose).uint32Value(client.engineChannel).data)
			client.expectOneCloseAfter(time.Now())
			client.expectStream(asked)
		})
	})

	t.Run("The engine shall not store, log or show the SSH username, nor anything a `pty-req` carries.", func(t *testing.T) {
		t.Parallel()
		t.Run("a username, a TERM and terminal modes holding the canary: the log holds the started line alone, the caller only the call", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := readyClient(t, program.ssh, canary+"-user")
			modes := append([]byte{1, 0, 0, 0, 3}, append([]byte(canary), 0)...)
			if reply := client.request("pty-req", true, ptyRequest(canary+"-term", modes)); reply[0] != messageChannelSuccess {
				t.Fatalf("the pty-req: message %d", reply[0])
			}
			client.toShell(false)
			client.readUntil(asked, time.Now().Add(patient(5*time.Second)))
			client.sendData(typedBob)
			client.expectNameEnd(asked + echoOf("bob") + helloTo("bob"))
			program.expectOnlyStarted(t)
			if strings.Contains(program.text(), canary) || bytes.Contains(client.received, []byte(canary)) {
				t.Fatalf("the canary reached the log or the caller")
			}
		})
	})

	t.Run("The engine shall not write any part of the host key to the local log.", func(t *testing.T) {
		t.Parallel()
		t.Run("a whole call: the log holds no 8 characters in a row of the key file or its public half", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := callAtPrompt(t, program, false)
			client.sendData(typedBob)
			client.expectNameEnd(asked + helloTo("bob"))
			expectNoKeyInLog(t, program.text(), program.key)
		})
	})

	t.Run("Apart from BS, DEL, Ctrl-U, CR and LF, the engine shall drop every other byte the caller sends after negotiation or, over SSH, after `shell`, and every character past the 30th.", func(t *testing.T) {
		t.Parallel()
		var controls strings.Builder
		for character := range 256 {
			if (character < 0x20 || character > 0x7e) && character != 0x08 && character != 0x7f && character != 0x15 && character != '\r' && character != '\n' {
				controls.WriteByte(byte(character))
			}
		}
		rows := []struct{ name, typed, name2 string }{
			{"31 characters: the first 30", strings.Repeat("a", 31) + "\r", strings.Repeat("a", 30)},
			{"every byte from 0x00 to 0xFF that is not printable, BS, DEL, Ctrl-U, CR or LF, between a and b: dropped, never echoed",
				"a" + controls.String() + "b\r", "ab"},
			{"ESC sequences: ESC dropped, the rest kept as typed", "\x1b[2Jx\r", "[2Jx"},
			{"0x9B, BEL, NUL and TAB: dropped", "a\x9b\x07\x00\tb\r", "ab"},
			{"0xFF, one byte and not doubled: dropped", "a\xffb\r", "ab"},
		}
		for _, row := range rows {
			t.Run("over SSH with a terminal, "+row.name, func(t *testing.T) {
				t.Parallel()
				program := startEngine(t)
				client := callAtPrompt(t, program, true)
				client.sendData(row.typed)
				client.expectNameEnd(asked + echoOf(row.name2) + helloTo(row.name2))
			})
		}
		t.Run("over SSH with a terminal, the edge: Ctrl-U is not dropped, ab Ctrl-U c CR gives Hello c", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := callAtPrompt(t, program, true)
			client.sendData("ab\x15c\r")
			client.expectNameEnd(asked + "ab" + strings.Repeat("\b \b", 2) + echoOf("c") + helloTo("c"))
		})
		t.Run("over SSH, ab sent before the shell and c CR after: the name abc", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := readyClient(t, program.ssh, "anyone")
			client.sendData("ab")
			client.toShell(false)
			client.readUntil(asked, time.Now().Add(patient(5*time.Second)))
			client.sendData("c\r")
			client.expectNameEnd(asked + helloTo("abc"))
		})
	})

	t.Run("If 70 seconds pass since it accepted a connection, then the engine shall close that connection.", func(t *testing.T) {
		t.Parallel()
		t.Run("an SSH caller silent after its version line: closed at the ceiling", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			dialed := time.Now()
			client := dialRaw(t, program.ssh)
			connected := time.Now()
			client.sendVersion()
			client.readServerKexInit(time.Now().Add(patient(5 * time.Second)))
			_, ended := client.expectEnd(connected.Add(ceilingLimit + patient(2*margin)))
			expectWithin(t, "the engine's close", ended, dialed.Add(ceilingLimit), connected.Add(ceilingLimit+margin))
		})
		t.Run("an SSH caller that sends end of file before the shell and never asks for one: nothing written, closed at the ceiling, not before", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			dialed := time.Now()
			client := dialRaw(t, program.ssh)
			connected := time.Now()
			client.handshake(curveExchange(t, "curve25519-sha256"), true)
			client.signIn("anyone")
			if reply := client.openChannel("session", 0, nil); reply[0] != messageChannelConfirmation {
				t.Fatalf("the session channel: message %d", reply[0])
			}
			client.sendPacket(message(messageChannelEOF).uint32Value(client.engineChannel).data)
			// The ceiling's nearest fault is one 900 ms too long, so the window keeps margin.
			kinds, ended := client.expectEnd(connected.Add(ceilingLimit + patient(2*margin)))
			if len(kinds) != 0 || len(client.received) != 0 {
				t.Fatalf("the engine sent messages %v and %q before the close, want nothing", kinds, client.received)
			}
			expectWithin(t, "the engine's close", ended, dialed.Add(ceilingLimit), connected.Add(ceilingLimit+margin))
		})
	})
}

// closingCaller runs a whole call and closes the connection once the channel's close arrives.
func closingCaller(t *testing.T, program *engine) {
	t.Helper()
	client := readyClient(t, program.ssh, "anyone")
	client.toShell(false)
	client.readUntil(asked, time.Now().Add(patient(10*time.Second)))
	client.sendData("n\r")
	client.readUntil(helloTo("n"), time.Now().Add(patient(10*time.Second)))
	for {
		payload, err := client.next(time.Now().Add(patient(10 * time.Second)))
		if err != nil {
			t.Fatalf("waiting for the channel's close: %v", err)
		}
		if payload[0] == messageChannelClose {
			_ = client.connection.Close()
			return
		}
	}
}

// expectServedBy dials until a caller is sent the version line, by deadline. Under the race
// detector it dials on for a stretched margin past the deadline, or past now where the test
// itself came late, so only a place that is never freed fails, as a hang would.
func expectServedBy(t *testing.T, address string, deadline time.Time) {
	t.Helper()
	giveUp := deadline
	if raceBuild {
		giveUp = time.Now()
		if deadline.After(giveUp) {
			giveUp = deadline
		}
		giveUp = giveUp.Add(patient(margin))
	}
	for {
		client := dialRaw(t, address)
		if version, err := client.readVersion(time.Now().Add(patient(margin))); err == nil && string(version) == versionLine {
			return
		}
		if time.Now().After(giveUp) {
			t.Fatalf("no caller was served by %v, %v past the deadline", giveUp.Format(time.RFC3339Nano), giveUp.Sub(deadline))
		}
	}
}

// waitUntil waits on the clock, which these rows are about.
func waitUntil(t *testing.T, moment time.Time) {
	t.Helper()
	select {
	case <-time.After(time.Until(moment)):
	case <-t.Context().Done():
	}
}

// expectNoKeyInLog fails the row if the log holds 8 characters in a row of the key file's
// base64 body or of its public half's.
func expectNoKeyInLog(t *testing.T, log, keyPath string) {
	t.Helper()
	private := readFile(t, keyPath)
	public := strings.Fields(string(readFile(t, keyPath+".pub")))
	if holdsPartOf(log, pemBody(private)) || (len(public) > 1 && holdsPartOf(log, public[1])) {
		t.Fatalf("the log %q holds part of the host key", log)
	}
	raw, err := base64.StdEncoding.DecodeString(pemBody(private))
	if err == nil && holdsPartOf(log, string(raw)) {
		t.Fatalf("the log %q holds part of the host key's bytes", log)
	}
}
