// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Accept, SSH's way in, called through its exported name on a loopback connection, with QA's own
// client on the other end: what it sends first, how it answers everything a caller opens or
// sends before the shell, and each way it ends.
package ssh_test

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/ssh"
)

// The table's values, as the contract's wire format states them.
const (
	offeredKex         = "mlkem768x25519-sha256,curve25519-sha256,curve25519-sha256@libssh.org,kex-strict-s-v00@openssh.com"
	offeredHostKeys    = "ssh-ed25519"
	offeredCiphers     = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com"
	offeredMACs        = "hmac-sha2-256-etm@openssh.com"
	offeredCompression = "none"
)

// expectNoBytes closes the engine's end and fails the row if the caller had received anything.
func (client *rawClient) expectNoBytes(server *net.TCPConn) {
	client.t.Helper()
	_ = server.Close()
	err := client.fill(1, time.Now().Add(5*time.Second))
	if len(client.pending) > 0 || err == nil {
		client.t.Fatalf("the caller received %q, want nothing", client.pending)
	}
}

// expectKexInit checks a KEXINIT's lists against the table.
func expectKexInit(t *testing.T, offer kexInit) {
	t.Helper()
	got := []string{offer.kex, offer.hostKeys, offer.ciphersOut, offer.ciphersIn, offer.macsOut,
		offer.macsIn, offer.compressionOut, offer.compressionIn, offer.languagesOut, offer.languagesIn}
	want := []string{offeredKex, offeredHostKeys, offeredCiphers, offeredCiphers, offeredMACs,
		offeredMACs, offeredCompression, offeredCompression, "", ""}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("the KEXINIT's list %d was %q, want %q", index+1, got[index], want[index])
		}
	}
	if offer.firstFollows || offer.reserved != 0 || len(offer.rest) != 0 {
		t.Fatalf("the KEXINIT ended first_kex_packet_follows %v, reserved %d, then %q, want false, 0 and nothing",
			offer.firstFollows, offer.reserved, offer.rest)
	}
}

// lateReport is a context whose deadline has passed by the clock but which reports its end only
// at reportAt: the moment a context's own timer has not yet fired.
type lateReport struct {
	deadline time.Time
	reportAt time.Time
	once     sync.Once
	done     chan struct{}
}

func newLateReport(deadline, reportAt time.Time) *lateReport {
	late := &lateReport{deadline: deadline, reportAt: reportAt, done: make(chan struct{})}
	time.AfterFunc(time.Until(reportAt), func() { late.once.Do(func() { close(late.done) }) })
	return late
}

func (late *lateReport) Deadline() (time.Time, bool) { return late.deadline, true }
func (late *lateReport) Done() <-chan struct{}       { return late.done }
func (late *lateReport) Value(any) any               { return nil }
func (late *lateReport) Err() error {
	select {
	case <-late.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

// toShell signs in, opens the session, asks for a terminal when terminal is set, and asks for the
// shell, failing the row unless each is accepted.
func (client *rawClient) toShell(terminal bool) {
	client.t.Helper()
	if terminal {
		if reply := client.request("pty-req", true, ptyRequest("xterm", []byte{0})); reply[0] != messageChannelSuccess {
			client.t.Fatalf("the pty-req: message %d, want SUCCESS", reply[0])
		}
	}
	if reply := client.request("shell", true, nil); reply[0] != messageChannelSuccess {
		client.t.Fatalf("the shell: message %d, want SUCCESS", reply[0])
	}
}

func expectChannel(t *testing.T, result acceptResult) *ssh.Channel {
	t.Helper()
	if result.err != nil || result.channel == nil {
		t.Fatalf("Accept gave %v and %v, want a Channel and no error", result.channel, result.err)
	}
	return result.channel
}

func expectAcceptError(t *testing.T, result acceptResult, want ...error) {
	t.Helper()
	if result.channel != nil {
		t.Fatalf("Accept gave a Channel with %v, want no Channel", result.err)
	}
	for _, each := range want {
		if !errors.Is(result.err, each) {
			t.Fatalf("Accept gave %v, want it to match %v", result.err, each)
		}
	}
}

func TestAccept(t *testing.T) {
	t.Parallel()

	t.Run("Accept shall send VersionLine and CR LF, and set the key exchange's fields to the package's table.", func(t *testing.T) {
		t.Parallel()
		t.Run("the version line first, before the caller sends anything", func(t *testing.T) {
			t.Parallel()
			address, _, _ := acceptPair(t, t.Context(), readKey(t))
			client := dialRaw(t, address)
			version, err := client.readVersion(time.Now().Add(5 * time.Second))
			if err != nil || string(version) != versionLine {
				t.Fatalf("the first line was %q, %v, want %q", version, err, versionLine)
			}
		})
		t.Run("the KEXINIT: exactly the table's lists", func(t *testing.T) {
			t.Parallel()
			address, _, _ := acceptPair(t, t.Context(), readKey(t))
			client := dialRaw(t, address)
			client.sendVersion()
			expectKexInit(t, client.readServerKexInit(time.Now().Add(5*time.Second)))
		})
	})

	t.Run("When the caller offers strict key exchange, Accept shall use it.", func(t *testing.T) {
		t.Parallel()
		ignoreDuringExchange := func(t *testing.T, strict bool) (<-chan acceptResult, []byte, error) {
			t.Helper()
			address, results, _ := acceptPair(t, t.Context(), readKey(t))
			client := dialRaw(t, address)
			client.sendVersion()
			client.readServerKexInit(time.Now().Add(5 * time.Second))
			client.sendKexInit(defaultOffer("curve25519-sha256", strict))
			client.sendPacket(message(messageIgnore).text("strict").data)
			exchange := curveExchange(t, "curve25519-sha256")
			client.sendPacket(message(messageKexInit30).bytesValue(exchange.initial).data)
			payload, err := client.nextIgnoring(time.Now().Add(margin + time.Second))
			return results, payload, err
		}
		t.Run("an IGNORE between the caller's KEXINIT and its key exchange, strict offered: the connection ends, no reply", func(t *testing.T) {
			t.Parallel()
			results, payload, err := ignoreDuringExchange(t, true)
			if !isEnd(err) {
				t.Fatalf("after the IGNORE the engine sent %v, %v, want the end of the connection", payload, err)
			}
			expectNoShell(t, waitAccept(t, results, 5*time.Second))
		})
		t.Run("the same IGNORE, strict not offered: the key exchange's reply comes", func(t *testing.T) {
			t.Parallel()
			_, payload, err := ignoreDuringExchange(t, false)
			if err != nil || payload[0] != messageKexReply31 {
				t.Fatalf("after the IGNORE the engine sent %v, %v, want the key exchange's reply", payload, err)
			}
		})
		t.Run("strict offered and followed: the shell is reached", func(t *testing.T) {
			t.Parallel()
			address, results, _ := acceptPair(t, t.Context(), readKey(t))
			client := readyClient(t, address, "anyone")
			client.toShell(false)
			expectChannel(t, waitAccept(t, results, 5*time.Second))
		})
	})

	t.Run("Accept shall answer each thing the caller opens or sends before the shell as the table above gives.", func(t *testing.T) {
		t.Parallel()
		t.Run("a second session channel: refused, and the first goes on", func(t *testing.T) {
			t.Parallel()
			address, results, _ := acceptPair(t, t.Context(), readKey(t))
			client := readyClient(t, address, "anyone")
			if reply := client.openChannel("session", 1, nil); reply[0] != messageChannelOpenFailure {
				t.Fatalf("the second session: message %d, want OPEN_FAILURE", reply[0])
			}
			client.toShell(false)
			expectChannel(t, waitAccept(t, results, 5*time.Second))
		})
		for _, kind := range []struct{ name, kind string }{
			{directChannel, directChannel},
			{streamLocalChannel, streamLocalChannel},
			{"x11", x11Channel},
			{"auth-agent@openssh.com", "auth-agent@openssh.com"},
			{"a type no one defines", unknownName},
		} {
			t.Run("any other channel, "+kind.name+", before the session: refused, and the session still accepted", func(t *testing.T) {
				t.Parallel()
				address, results, _ := acceptPair(t, t.Context(), readKey(t))
				client := dialRaw(t, address)
				client.handshake(curveExchange(t, "curve25519-sha256"), true)
				client.signIn("anyone")
				extra := (&wire{}).text("127.0.0.1").uint32Value(9).text("127.0.0.1").uint32Value(1).data
				if reply := client.openChannel(kind.kind, 5, extra); reply[0] != messageChannelOpenFailure {
					t.Fatalf("the %s channel: message %d, want OPEN_FAILURE", kind.kind, reply[0])
				}
				if reply := client.openChannel("session", 0, nil); reply[0] != messageChannelConfirmation {
					t.Fatalf("the session after it: message %d, want OPEN_CONFIRMATION", reply[0])
				}
				client.toShell(false)
				expectChannel(t, waitAccept(t, results, 5*time.Second))
			})
		}
		t.Run("pty-req before shell: accepted, twice; the board will echo", func(t *testing.T) {
			t.Parallel()
			address, results, _ := acceptPair(t, t.Context(), readKey(t))
			client := readyClient(t, address, "anyone")
			for range 2 {
				if reply := client.request("pty-req", true, ptyRequest("vt100", []byte{0})); reply[0] != messageChannelSuccess {
					t.Fatalf("the pty-req: message %d, want SUCCESS", reply[0])
				}
			}
			client.toShell(false)
			if channel := expectChannel(t, waitAccept(t, results, 5*time.Second)); !channel.Echoes() {
				t.Fatalf("Echoes was false after an accepted pty-req")
			}
		})
		for _, request := range []string{"exec", "subsystem", "env", "x11-req", "auth-agent-req@openssh.com",
			"window-change", "signal", "break", unknownName} {
			t.Run("any other channel request, "+request+": refused, and the shell still accepted", func(t *testing.T) {
				t.Parallel()
				address, results, _ := acceptPair(t, t.Context(), readKey(t))
				client := readyClient(t, address, "anyone")
				if reply := client.request(request, true, (&wire{}).text("x").text("y").data); reply[0] != messageChannelFailure {
					t.Fatalf("the %s request: message %d, want FAILURE", request, reply[0])
				}
				client.toShell(false)
				expectChannel(t, waitAccept(t, results, 5*time.Second))
			})
		}
		t.Run("a refused request that asks for no reply: nothing written, the next request's reply comes next", func(t *testing.T) {
			t.Parallel()
			address, results, _ := acceptPair(t, t.Context(), readKey(t))
			client := readyClient(t, address, "anyone")
			client.request("exec", false, (&wire{}).text("ls").data)
			client.toShell(false)
			expectChannel(t, waitAccept(t, results, 5*time.Second))
		})
		for _, request := range []string{"tcpip-forward", "cancel-tcpip-forward", "keepalive@openssh.com",
			"no-more-sessions@openssh.com", unknownName} {
			t.Run("any global request, "+request+": refused", func(t *testing.T) {
				t.Parallel()
				address, results, _ := acceptPair(t, t.Context(), readKey(t))
				client := readyClient(t, address, "anyone")
				client.sendPacket(message(messageGlobalRequest).text(request).boolean(true).text("127.0.0.1").uint32Value(0).data)
				if reply, err := client.next(time.Now().Add(5 * time.Second)); err != nil || reply[0] != messageRequestFailure {
					t.Fatalf("the %s request: %v, %v, want REQUEST_FAILURE", request, reply, err)
				}
				client.toShell(false)
				expectChannel(t, waitAccept(t, results, 5*time.Second))
			})
		}
		t.Run("ping@openssh.com: the pong, holding the same data", func(t *testing.T) {
			t.Parallel()
			address, _, _ := acceptPair(t, t.Context(), readKey(t))
			client := readyClient(t, address, "anyone")
			client.sendPacket(message(messagePing).text(canary).data)
			reply, err := client.nextIgnoring(time.Now().Add(5 * time.Second))
			if want := message(messagePong).text(canary).data; err != nil || string(reply) != string(want) {
				t.Fatalf("the ping's reply was %v, %v, want %v", reply, err, want)
			}
		})
		t.Run("data on the channel before the shell: kept, in order, for the Channel", func(t *testing.T) {
			t.Parallel()
			address, results, _ := acceptPair(t, t.Context(), readKey(t))
			client := readyClient(t, address, "anyone")
			client.sendData("ab")
			client.sendData("c")
			client.toShell(false)
			channel := expectChannel(t, waitAccept(t, results, 5*time.Second))
			expectReceived(t, channel, "abc")
		})
		t.Run("extended data before the shell: never read as the caller's data", func(t *testing.T) {
			t.Parallel()
			address, results, _ := acceptPair(t, t.Context(), readKey(t))
			client := readyClient(t, address, "anyone")
			client.sendData("a")
			client.sendExtended("XYZ")
			client.sendData("b")
			client.toShell(false)
			channel := expectChannel(t, waitAccept(t, results, 5*time.Second))
			expectReceived(t, channel, "ab")
			expectNothingMore(t, channel)
		})
	})

	t.Run("When the caller has signed in, opened a session channel and asked for a shell, Accept shall return the Channel and no error.", func(t *testing.T) {
		t.Parallel()
		for _, terminal := range []bool{true, false} {
			name := "without a terminal"
			if terminal {
				name = "with a terminal"
			}
			t.Run(name+": the Channel, as soon as the shell is accepted", func(t *testing.T) {
				t.Parallel()
				address, results, _ := acceptPair(t, t.Context(), readKey(t))
				client := readyClient(t, address, "anyone")
				shellSent := time.Now()
				client.toShell(terminal)
				accepted := time.Now()
				result := waitAccept(t, results, 5*time.Second)
				expectChannel(t, result)
				expectWithin(t, "Accept's return", result.returned, shellSent, accepted.Add(margin))
			})
		}
		t.Run("signed in, the session open, no shell: no Channel yet", func(t *testing.T) {
			t.Parallel()
			address, results, _ := acceptPair(t, t.Context(), readKey(t))
			client := readyClient(t, address, "anyone")
			select {
			case result := <-results:
				t.Fatalf("Accept returned %v and %v before the shell", result.channel, result.err)
			case <-time.After(quietFor):
			}
			client.toShell(false)
			expectChannel(t, waitAccept(t, results, 5*time.Second))
		})
	})

	t.Run("If the connection or the session channel ends before the shell, however it ends, end of file apart, and the context has not ended, then Accept shall return ErrNoShell.", func(t *testing.T) {
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
			t.Run("the sign-in method "+method.name+" first: ErrNoShell", func(t *testing.T) {
				t.Parallel()
				address, results, _ := acceptPair(t, t.Context(), readKey(t))
				client := dialRaw(t, address)
				client.handshake(curveExchange(t, "curve25519-sha256"), true)
				out := message(messageUserauthRequest).text("anyone").text("ssh-connection").text(method.name)
				out.data = append(out.data, method.extra...)
				client.sendPacket(out.data)
				expectNoShell(t, waitAccept(t, results, 5*time.Second))
			})
		}
		rows := []struct {
			name  string
			setUp func(t *testing.T, address string)
		}{
			{"300 bytes with no line break, not SSH", func(t *testing.T, address string) {
				t.Helper()
				dialRaw(t, address).write(make([]byte, 300))
			}},
			{"a caller offering only diffie-hellman-group14-sha256", func(t *testing.T, address string) {
				t.Helper()
				client := dialRaw(t, address)
				client.sendVersion()
				client.sendKexInit(defaultOffer("diffie-hellman-group14-sha256", true))
			}},
			{"a caller offering only the cipher aes128-ctr", func(t *testing.T, address string) {
				t.Helper()
				client := dialRaw(t, address)
				client.sendVersion()
				offer := defaultOffer("curve25519-sha256", true)
				offer.ciphers = []string{"aes128-ctr"}
				client.sendKexInit(offer)
			}},
			// Under the earlier lines a close here could give either of two results; now one.
			{"the caller closes the connection in the handshake's middle", func(t *testing.T, address string) {
				t.Helper()
				client := dialRaw(t, address)
				client.sendVersion()
				client.readServerKexInit(time.Now().Add(5 * time.Second))
				_ = client.connection.CloseWrite()
			}},
			{"a caller that resets mid-handshake", func(t *testing.T, address string) {
				t.Helper()
				client := dialRaw(t, address)
				client.sendVersion()
				client.readServerKexInit(time.Now().Add(5 * time.Second))
				_ = client.connection.SetLinger(0)
				_ = client.connection.Close()
			}},
			{"a caller that resets once its session is open, before the shell", func(t *testing.T, address string) {
				t.Helper()
				client := readyClient(t, address, "anyone")
				_ = client.connection.SetLinger(0)
				_ = client.connection.Close()
			}},
			{"the caller closes the connection after signing in", func(t *testing.T, address string) {
				t.Helper()
				client := dialRaw(t, address)
				client.handshake(curveExchange(t, "curve25519-sha256"), true)
				client.signIn("anyone")
				_ = client.connection.CloseWrite()
			}},
			{"the caller closes the connection after the session opened", func(t *testing.T, address string) {
				t.Helper()
				client := readyClient(t, address, "anyone")
				_ = client.connection.CloseWrite()
			}},
			{"the caller closes the session", func(t *testing.T, address string) {
				t.Helper()
				client := readyClient(t, address, "anyone")
				client.sendPacket(message(messageChannelClose).uint32Value(client.engineChannel).data)
			}},
			// The socket stays open, so that only the disconnect ends the handshake.
			{"the caller sends a disconnect after the version lines", func(t *testing.T, address string) {
				t.Helper()
				client := dialRaw(t, address)
				client.sendVersion()
				if _, err := client.readVersion(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatalf("the engine's version line: %v", err)
				}
				client.sendPacket(disconnectMessage())
			}},
			{"the caller sends a disconnect after both key exchange offers", func(t *testing.T, address string) {
				t.Helper()
				client := dialRaw(t, address)
				client.sendVersion()
				client.readServerKexInit(time.Now().Add(5 * time.Second))
				client.sendKexInit(defaultOffer("curve25519-sha256", true))
				client.sendPacket(disconnectMessage())
			}},
			{"the caller sends a disconnect after the key exchange, before signing in", func(t *testing.T, address string) {
				t.Helper()
				client := dialRaw(t, address)
				client.handshake(curveExchange(t, "curve25519-sha256"), true)
				client.sendPacket(disconnectMessage())
			}},
		}
		for _, row := range rows {
			t.Run(row.name+": ErrNoShell", func(t *testing.T) {
				t.Parallel()
				address, results, _ := acceptPair(t, t.Context(), readKey(t))
				row.setUp(t, address)
				expectNoShell(t, waitAccept(t, results, 5*time.Second))
			})
		}
	})

	t.Run("If the caller sends end of file on the session channel before the shell, then Accept shall not return because of it; every other line still applies.", func(t *testing.T) {
		t.Parallel()
		t.Run("end of file, a wait, then shell: the Channel, Echoes false, and RecvChar io.EOF with no byte", func(t *testing.T) {
			t.Parallel()
			client, results := endBeforeShell(t, false, "")
			client.toShell(false)
			channel := expectChannel(t, waitAccept(t, results, 5*time.Second))
			if channel.Echoes() {
				t.Fatalf("Echoes gave true with no pty-req, want false")
			}
			if got, err := channel.RecvChar(t.Context(), time.Now().Add(5*time.Second)); !errors.Is(err, io.EOF) {
				t.Fatalf("RecvChar gave %q, %v, want io.EOF", got, err)
			}
		})
		t.Run("a pty-req, end of file, a wait, then shell: the Channel, and Echoes true", func(t *testing.T) {
			t.Parallel()
			client, results := endBeforeShell(t, true, "")
			client.toShell(false)
			if channel := expectChannel(t, waitAccept(t, results, 5*time.Second)); !channel.Echoes() {
				t.Fatalf("Echoes gave false after a pty-req before the end of file, want true")
			}
		})
		t.Run("end of file, then a pty-req: SUCCESS, and after shell Echoes true", func(t *testing.T) {
			t.Parallel()
			client, results := endBeforeShell(t, false, "")
			client.toShell(true)
			if channel := expectChannel(t, waitAccept(t, results, 5*time.Second)); !channel.Echoes() {
				t.Fatalf("Echoes gave false after a pty-req after the end of file, want true")
			}
		})
		for _, row := range []struct {
			name, before string
		}{
			{"ab", "ab"},
			{"300 bytes, more than the Channel holds", patterned(300)},
		} {
			t.Run(row.name+", end of file, a wait, then shell: every byte in order, then io.EOF", func(t *testing.T) {
				t.Parallel()
				client, results := endBeforeShell(t, false, row.before)
				client.toShell(false)
				channel := expectChannel(t, waitAccept(t, results, 5*time.Second))
				expectReceived(t, channel, row.before)
				if got, err := channel.RecvChar(t.Context(), time.Now().Add(5*time.Second)); !errors.Is(err, io.EOF) {
					t.Fatalf("after the bytes RecvChar gave %q, %v, want io.EOF", got, err)
				}
			})
		}
		t.Run("end of file and shell in one write: SUCCESS, and the Channel", func(t *testing.T) {
			t.Parallel()
			address, results, _ := acceptPair(t, t.Context(), readKey(t))
			client := readyClient(t, address, "anyone")
			client.sendTogether(
				message(messageChannelEOF).uint32Value(client.engineChannel).data,
				message(messageChannelRequest).uint32Value(client.engineChannel).text("shell").boolean(true).data)
			if reply, err := client.next(time.Now().Add(5 * time.Second)); err != nil || reply[0] != messageChannelSuccess {
				t.Fatalf("the shell's reply: %v, %v, want SUCCESS", reply, err)
			}
			expectChannel(t, waitAccept(t, results, 5*time.Second))
		})
		for _, row := range []struct {
			name string
			end  func(client *rawClient)
		}{
			{"the session's close", func(client *rawClient) {
				client.sendPacket(message(messageChannelClose).uint32Value(client.engineChannel).data)
			}},
			{connectionCloseRow, func(client *rawClient) { _ = client.connection.CloseWrite() }},
			{disconnectRow, func(client *rawClient) { client.sendPacket(disconnectMessage()) }},
		} {
			t.Run("end of file, a wait, then "+row.name+": ErrNoShell", func(t *testing.T) {
				t.Parallel()
				client, results := endBeforeShell(t, false, "")
				row.end(client)
				expectNoShell(t, waitAccept(t, results, 5*time.Second))
			})
		}
		t.Run("end of file, a wait, then the context cancelled: ErrDeadlineEnded wrapping context.Canceled at once, and nothing more written", func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			address, results, _ := acceptPair(t, ctx, readKey(t))
			client := reachEnd(t, address, results, false, "")
			cancelled := time.Now()
			cancel()
			result := waitAccept(t, results, margin+time.Second)
			expectAcceptError(t, result, ssh.ErrDeadlineEnded, context.Canceled)
			expectWithin(t, "Accept's return", result.returned, cancelled, cancelled.Add(margin))
			expectNothingWritten(t, client)
		})
		t.Run("end of file, then the deadline passing while it waits: ErrDeadlineEnded wrapping context.DeadlineExceeded at the deadline", func(t *testing.T) {
			t.Parallel()
			deadline := time.Now().Add(2 * time.Second)
			ctx, cancel := context.WithDeadline(t.Context(), deadline)
			t.Cleanup(cancel)
			address, results, _ := acceptPair(t, ctx, readKey(t))
			reachEnd(t, address, results, false, "")
			result := waitAccept(t, results, 2*time.Second+margin+time.Second)
			expectAcceptError(t, result, ssh.ErrDeadlineEnded, context.DeadlineExceeded)
			expectWithin(t, "Accept's return", result.returned, deadline, deadline.Add(margin))
		})
		t.Run("end of file, then a second session channel: refused, and then shell: the Channel", func(t *testing.T) {
			t.Parallel()
			client, results := endBeforeShell(t, false, "")
			if reply := client.openChannel("session", 1, nil); reply[0] != messageChannelOpenFailure {
				t.Fatalf("the second session channel: message %d, want OPEN_FAILURE", reply[0])
			}
			client.toShell(false)
			expectChannel(t, waitAccept(t, results, 5*time.Second))
		})
		t.Run("end of file, then a global request wanting a reply: REQUEST_FAILURE, and then shell: the Channel", func(t *testing.T) {
			t.Parallel()
			client, results := endBeforeShell(t, false, "")
			client.sendPacket(message(messageGlobalRequest).text(unknownName).boolean(true).data)
			if reply, err := client.next(time.Now().Add(5 * time.Second)); err != nil || reply[0] != messageRequestFailure {
				t.Fatalf("the global request's reply: %v, %v, want REQUEST_FAILURE", reply, err)
			}
			client.toShell(false)
			expectChannel(t, waitAccept(t, results, 5*time.Second))
		})
		t.Run("end of file, then exec wanting a reply: FAILURE, and then shell: the Channel", func(t *testing.T) {
			t.Parallel()
			client, results := endBeforeShell(t, false, "")
			if reply := client.request("exec", true, (&wire{}).text("ls").data); reply[0] != messageChannelFailure {
				t.Fatalf("exec: message %d, want FAILURE", reply[0])
			}
			client.toShell(false)
			expectChannel(t, waitAccept(t, results, 5*time.Second))
		})
	})

	t.Run("If the context has ended when Accept is called, or ends while it waits, then Accept shall return ErrDeadlineEnded wrapping the context's error, without writing more.", func(t *testing.T) {
		t.Parallel()
		ended := func(t *testing.T) (context.Context, error) {
			t.Helper()
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			return ctx, context.Canceled
		}
		passed := func(t *testing.T) (context.Context, error) {
			t.Helper()
			ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
			t.Cleanup(cancel)
			return ctx, context.DeadlineExceeded
		}
		for _, row := range []struct {
			name    string
			context func(t *testing.T) (context.Context, error)
		}{
			{"a cancelled context at the call", ended},
			{"a context whose deadline passed before the call", passed},
		} {
			t.Run(row.name+": ErrDeadlineEnded, and the caller receives no byte", func(t *testing.T) {
				t.Parallel()
				ctx, cause := row.context(t)
				address, results, servers := acceptPair(t, ctx, readKey(t))
				client := dialRaw(t, address)
				client.sendVersion()
				result := waitAccept(t, results, 5*time.Second)
				expectAcceptError(t, result, ssh.ErrDeadlineEnded, cause)
				client.expectNoBytes(<-servers)
			})
		}
		stages := []struct {
			name  string
			reach func(t *testing.T, address string) *rawClient
		}{
			{"waiting for the key exchange", func(t *testing.T, address string) *rawClient {
				t.Helper()
				client := dialRaw(t, address)
				client.sendVersion()
				client.readServerKexInit(time.Now().Add(5 * time.Second))
				return client
			}},
			{"waiting for a channel", func(t *testing.T, address string) *rawClient {
				t.Helper()
				client := dialRaw(t, address)
				client.handshake(curveExchange(t, "curve25519-sha256"), true)
				client.signIn("anyone")
				return client
			}},
			{"waiting for the shell", func(t *testing.T, address string) *rawClient {
				t.Helper()
				return readyClient(t, address, "anyone")
			}},
		}
		for _, stage := range stages {
			t.Run("cancelled while "+stage.name+": ErrDeadlineEnded wrapping context.Canceled at once, and nothing more written", func(t *testing.T) {
				t.Parallel()
				ctx, cancel := context.WithCancel(t.Context())
				address, results, _ := acceptPair(t, ctx, readKey(t))
				client := stage.reach(t, address)
				cancelled := time.Now()
				cancel()
				result := waitAccept(t, results, margin+time.Second)
				expectAcceptError(t, result, ssh.ErrDeadlineEnded, context.Canceled)
				expectWithin(t, "Accept's return", result.returned, cancelled, cancelled.Add(margin))
				expectNothingWritten(t, client)
			})
			t.Run("the deadline passing while "+stage.name+": ErrDeadlineEnded wrapping context.DeadlineExceeded at the deadline", func(t *testing.T) {
				t.Parallel()
				deadline := time.Now().Add(2 * time.Second)
				ctx, cancel := context.WithDeadline(t.Context(), deadline)
				t.Cleanup(cancel)
				address, results, _ := acceptPair(t, ctx, readKey(t))
				stage.reach(t, address)
				result := waitAccept(t, results, 2*time.Second+margin+time.Second)
				expectAcceptError(t, result, ssh.ErrDeadlineEnded, context.DeadlineExceeded)
				expectWithin(t, "Accept's return", result.returned, deadline, deadline.Add(margin))
			})
		}
	})

	t.Run("If the context has ended when the connection or the session channel ends, however it ends, then Accept shall return ErrDeadlineEnded.", func(t *testing.T) {
		t.Parallel()
		t.Run("the deadline passed by the clock, reported only later, and the caller resets waiting for the shell: ErrDeadlineEnded", func(t *testing.T) {
			t.Parallel()
			deadline := time.Now().Add(time.Second)
			late := newLateReport(deadline, deadline.Add(10*time.Second))
			address, results, _ := acceptPair(t, late, readKey(t))
			client := readyClient(t, address, "anyone")
			for time.Now().Before(deadline.Add(100 * time.Millisecond)) {
				if reply := client.request("env", true, (&wire{}).text("A").text("B").data); reply[0] != messageChannelFailure {
					t.Fatalf("an env request: message %d, want FAILURE", reply[0])
				}
			}
			_ = client.connection.SetLinger(0)
			_ = client.connection.Close()
			result := waitAccept(t, results, 5*time.Second)
			expectAcceptError(t, result, ssh.ErrDeadlineEnded)
			if late.Err() != nil {
				t.Fatalf("the context had reported its end before Accept returned: the row proves nothing")
			}
		})
	})

	t.Run("If connection is nil, or key is nil or not made by ReadHostKey, then Accept shall return ErrConnectionFailed without writing to the connection.", func(t *testing.T) {
		t.Parallel()
		t.Run("a nil connection with a read key: ErrConnectionFailed and no Channel", func(t *testing.T) {
			t.Parallel()
			channel, err := ssh.Accept(t.Context(), nil, readKey(t))
			expectWrongCall(t, acceptResult{channel: channel, err: err})
		})
		for _, row := range []struct {
			name string
			key  *ssh.HostKey
		}{
			{"a nil key", nil},
			{"a HostKey not made by ReadHostKey", &ssh.HostKey{}},
		} {
			t.Run(row.name+": ErrConnectionFailed and no byte, where the same caller with a read key reaches the shell", func(t *testing.T) {
				t.Parallel()
				address, results, servers := acceptPair(t, t.Context(), row.key)
				client := dialRaw(t, address)
				client.sendVersion()
				expectWrongCall(t, waitAccept(t, results, 5*time.Second))
				client.expectNoBytes(<-servers)
				address, results, _ = acceptPair(t, t.Context(), readKey(t))
				readyClient(t, address, "anyone").toShell(false)
				expectChannel(t, waitAccept(t, results, 5*time.Second))
			})
		}
	})

}

// expectNoShell is ErrNoShell alone: an end before the shell is neither a wrong call nor the
// context's end, so a build that only renamed its old results fails here.
func expectNoShell(t *testing.T, result acceptResult) {
	t.Helper()
	expectAcceptError(t, result, ssh.ErrNoShell)
	if errors.Is(result.err, ssh.ErrConnectionFailed) || errors.Is(result.err, ssh.ErrDeadlineEnded) {
		t.Fatalf("Accept gave %v, want ErrNoShell alone", result.err)
	}
}

// expectWrongCall is ErrConnectionFailed alone, the result of a wrong call.
func expectWrongCall(t *testing.T, result acceptResult) {
	t.Helper()
	expectAcceptError(t, result, ssh.ErrConnectionFailed)
	if errors.Is(result.err, ssh.ErrNoShell) {
		t.Fatalf("Accept gave %v, want ErrConnectionFailed alone", result.err)
	}
}

// expectReceived reads text from the Channel, a byte at a time.
func expectReceived(t *testing.T, channel *ssh.Channel, text string) {
	t.Helper()
	for index := range len(text) {
		got, err := channel.RecvChar(t.Context(), time.Now().Add(5*time.Second))
		if err != nil || got != text[index] {
			t.Fatalf("byte %d was %q, %v, want %q", index, got, err, text[index])
		}
	}
}

// expectNothingMore is a RecvChar that must wait out its deadline: nothing else was kept.
func expectNothingMore(t *testing.T, channel *ssh.Channel) {
	t.Helper()
	if got, err := channel.RecvChar(t.Context(), time.Now().Add(quietFor)); !errors.Is(err, errDeadline) {
		t.Fatalf("RecvChar gave %q, %v, want its deadline to pass", got, err)
	}
}

// The row names of two ends a caller can make, each in rows of more than one line.
const (
	connectionCloseRow = "the connection's close"
	disconnectRow      = "a disconnect"
)

// endBeforeShell is reachEnd on an Accept under the row's own context.
func endBeforeShell(t *testing.T, terminal bool, before string) (*rawClient, <-chan acceptResult) {
	t.Helper()
	address, results, _ := acceptPair(t, t.Context(), readKey(t))
	return reachEnd(t, address, results, terminal, before), results
}

// reachEnd reaches the session channel, asks for a terminal when terminal is set, sends before as
// channel data, then end of file, and fails the row if Accept returns within quietFor: end of
// file alone must not end it.
func reachEnd(t *testing.T, address string, results <-chan acceptResult, terminal bool, before string) *rawClient {
	t.Helper()
	client := readyClient(t, address, "anyone")
	if terminal {
		if reply := client.request("pty-req", true, ptyRequest("xterm", []byte{0})); reply[0] != messageChannelSuccess {
			t.Fatalf("the pty-req: message %d, want SUCCESS", reply[0])
		}
	}
	if before != "" {
		client.sendData(before)
	}
	client.sendPacket(message(messageChannelEOF).uint32Value(client.engineChannel).data)
	select {
	case result := <-results:
		t.Fatalf("Accept gave %v and %v after the end of file alone, want it still waiting", result.channel, result.err)
	case <-time.After(quietFor):
	}
	return client
}

// patterned is count printable bytes, a to z over and over, so a byte lost or out of order shows.
func patterned(count int) string {
	text := make([]byte, count)
	for index := range text {
		text[index] = byte('a' + index%26)
	}
	return string(text)
}

// disconnectMessage is SSH_MSG_DISCONNECT with reason 11, by application, as RFC 4253 section 11.1
// lays it out.
func disconnectMessage() []byte {
	return message(messageDisconnect).uint32Value(11).text("bye").text("").data
}

// expectNothingWritten sends a request that would be answered and sees no answer: the engine
// writes nothing more.
func expectNothingWritten(t *testing.T, client *rawClient) {
	t.Helper()
	client.sendPacket(message(messageGlobalRequest).text("keepalive@openssh.com").boolean(true).data)
	if payload, err := client.next(time.Now().Add(quietFor)); err == nil {
		t.Fatalf("after the end the engine sent message %d", payload[0])
	}
}
