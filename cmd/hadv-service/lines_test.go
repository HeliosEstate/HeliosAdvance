// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The program's lines on every runner: where it listens, the port option, the stop signal and
// the local log, each driven from outside through the built program.
package main_test

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// stopSignal is one way the OS asks the program to stop. prepare readies the sender before the
// row starts its program; the function it returns sends the stop and gives a moment before it
// was sent and one after.
type stopSignal struct {
	name    string
	prepare func(*testing.T) func(*testing.T, *run) (time.Time, time.Time)
}

// canary marks what a caller sends, so the log can be searched for it.
const canary = "helios-canary-5821"

// The page's prompt, reply and name wait, written here so a changed constant in the engine
// cannot move a test with it, and the name a caller types.
const (
	prompt    = "What is your name? "
	reply     = "Hello "
	nameLimit = 60 * time.Second
	typedName = "Caller"
)

// typeName answers the option requests and types a name ended by CR, then reads what a caller
// who agreed to ECHO sees, through Hello and the engine's shutdown of its sending side, so the
// call is left in its closing wait.
func (call caller) typeName(t *testing.T) {
	t.Helper()
	call.send(t, append(append([]byte{}, answers...), typedName+"\r"...))
	call.readExactly(t, []byte(greeting+prompt+typedName+"\r\n"+reply+typedName+"\r\n"), time.Now().Add(margin))
	shutdownFrom := time.Now()
	call.expectEnd(t, shutdownFrom, shutdownFrom.Add(margin))
}

func TestProgram(t *testing.T) {
	t.Parallel()

	t.Run("The engine shall listen for callers at 127.0.0.1 and at ::1, and at no other address.", func(t *testing.T) {
		t.Parallel()
		t.Run("it serves 127.0.0.1 and ::1, and 127.0.0.2 and this machine's other addresses are refused at both ports", func(t *testing.T) {
			t.Parallel()
			program := startProgram(t, portOption, "0")
			addresses := program.listening(t)
			ipv4Port, ipv6Port := loopbackPorts(t, addresses)
			for _, address := range addresses {
				expectServed(t, address)
			}
			// A listener on every IPv4 address answers 127.0.0.2, and one on every address of
			// both families answers it at the IPv6 port too.
			targets := []string{net.JoinHostPort("127.0.0.2", ipv4Port), net.JoinHostPort("127.0.0.2", ipv6Port)}
			for _, address := range otherAddresses(t) {
				targets = append(targets, net.JoinHostPort(address.String(), ipv4Port), net.JoinHostPort(address.String(), ipv6Port))
			}
			var group sync.WaitGroup
			for _, target := range targets {
				group.Go(func() { expectRefused(t, target) })
			}
			group.Wait()
		})
	})

	t.Run("If the engine fails to listen at one of 127.0.0.1 and ::1, then the engine shall listen at the other alone.", func(t *testing.T) {
		t.Parallel()
		for _, taken := range []string{ipv4Loopback, ipv6Loopback} {
			t.Run(fmt.Sprintf("with %s taken at the port, it names and serves the other alone", taken), func(t *testing.T) {
				t.Parallel()
				port, ipv4, ipv6 := heldPort(t)
				free := ipv6Loopback
				if taken == ipv6Loopback {
					free = ipv4Loopback
					_ = ipv4.Close()
				} else {
					_ = ipv6.Close()
				}
				program := startProgram(t, portOption, port)
				addresses := program.listening(t)
				expectAddresses(t, addresses, net.JoinHostPort(free, port))
				expectServed(t, net.JoinHostPort(free, port))
			})
		}
	})

	t.Run("When the sysop passes a Telnet port on the command line, the engine shall listen on that port in place of port 23.", func(t *testing.T) {
		t.Parallel()
		t.Run("with -port and a free port, it names and serves that port at both addresses", func(t *testing.T) {
			t.Parallel()
			port, ipv4, ipv6 := heldPort(t)
			_ = ipv4.Close()
			_ = ipv6.Close()
			program := startProgram(t, portOption, port)
			addresses := program.listening(t)
			expectAddresses(t, addresses, net.JoinHostPort(ipv4Loopback, port), net.JoinHostPort(ipv6Loopback, port))
			for _, address := range addresses {
				expectServed(t, address)
			}
		})
	})

	t.Run("When the sysop passes port 0, the engine shall listen at each address on a free port the operating system picks.", func(t *testing.T) {
		t.Parallel()
		t.Run("with -port 0, it names and serves a port the system picked at each address", func(t *testing.T) {
			t.Parallel()
			program := startProgram(t, portOption, "0")
			addresses := program.listening(t)
			loopbackPorts(t, addresses)
			for _, address := range addresses {
				expectServed(t, address)
			}
		})
		t.Run("two programs with -port 0 at once both start, each on ports of its own", func(t *testing.T) {
			t.Parallel()
			// A port 0 read as some fixed port would put the second program on the first's
			// ports, where it cannot listen.
			first := startProgram(t, portOption, "0")
			second := startProgram(t, portOption, "0")
			firstAddresses := first.listening(t)
			secondAddresses := second.listening(t)
			firstIPv4, firstIPv6 := loopbackPorts(t, firstAddresses)
			secondIPv4, secondIPv6 := loopbackPorts(t, secondAddresses)
			if firstIPv4 == secondIPv4 || firstIPv6 == secondIPv6 {
				t.Fatalf("two programs named %q and %q, sharing a port", firstAddresses, secondAddresses)
			}
			for _, address := range append(firstAddresses, secondAddresses...) {
				expectServed(t, address)
			}
		})
	})

	t.Run("When it receives a stop signal, the engine shall close every open connection at once and exit.", func(t *testing.T) {
		t.Parallel()
		for _, signal := range stopSignals() {
			t.Run(signal.name+": a silent caller and one in the closing wait are closed, and the program exits, at once", func(t *testing.T) {
				t.Parallel()
				send := signal.prepare(t)
				program := startProgram(t, portOption, "0")
				addresses := program.listening(t)
				silent := expectServed(t, addresses[0])
				closing := expectServed(t, addresses[len(addresses)-1])
				closing.typeName(t)
				// The silent call is inside its 3 seconds of negotiation, and the closing call,
				// which shut down after the silent caller connected, inside its 3 seconds of
				// closing wait, so nothing but the stop ends either in the window.
				from, sentBy := send(t, program)
				notAfter := sentBy.Add(margin)
				if sentBy.After(silent.connected.Add(negotiationLimit)) {
					t.Fatalf("the stop was sent %v after the silent caller connected, past the negotiation's own end", sentBy.Sub(silent.connected))
				}
				silent.expectEnd(t, from, notAfter)
				closing.awaitReset(t, from, notAfter)
				_, exitedAt := program.exit(t, notAfter)
				expectWithin(t, "the exit", exitedAt, from, notAfter)
				program.expectLog(t, "started")
			})
		}
	})

	t.Run("When it has started listening, the engine shall write one `started` line to the local log naming the kind, address and port of every listener.", func(t *testing.T) {
		t.Parallel()
		t.Run("one started line, written once both listen: a caller at each, dialed as the line arrives, is served", func(t *testing.T) {
			t.Parallel()
			signal := stopSignals()[0]
			send := signal.prepare(t)
			program := startProgram(t, portOption, "0")
			addresses := program.listening(t)
			for _, address := range addresses {
				expectServed(t, address)
			}
			from, sentBy := send(t, program)
			program.exit(t, sentBy.Add(margin))
			_ = from
			values := program.expectLog(t, "started")
			want := "telnet://" + strings.Join(addresses, ",telnet://")
			if values[0] != want {
				t.Fatalf("the started line's value was %q, want %q", values[0], want)
			}
		})
		t.Run("with SSH on: one started line naming each listener as a URL, Telnet's then SSH's, each served by its kind", func(t *testing.T) {
			t.Parallel()
			program := startProgram(t, portOption, "0", hostKeyOption, makeKey(t, "ed25519", ""), sshPortOption, "0")
			listeners := program.listeners(t)
			telnet, ssh := kindsOf(t, listeners)
			telnetIPv4, telnetIPv6 := loopbackPorts(t, telnet)
			sshIPv4, sshIPv6 := loopbackPorts(t, ssh)
			want := []string{
				"telnet://" + net.JoinHostPort(ipv4Loopback, telnetIPv4), "telnet://" + net.JoinHostPort(ipv6Loopback, telnetIPv6),
				"ssh://" + net.JoinHostPort(ipv4Loopback, sshIPv4), "ssh://" + net.JoinHostPort(ipv6Loopback, sshIPv6),
			}
			if strings.Join(listeners, ",") != strings.Join(want, ",") {
				t.Fatalf("the started line named %q, want %q", listeners, want)
			}
			for _, address := range telnet {
				expectServed(t, address)
			}
			for _, address := range ssh {
				expectSSHServed(t, address)
			}
		})
	})

	t.Run("If a command-line option is malformed, or the engine fails to listen at both addresses for Telnet or, when SSH is on, for SSH, then the engine shall write one `start_failed` line to the local log saying why, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		for _, options := range [][]string{
			{portOption},
			{portOption, "abc"},
			{portOption, ""},
			{portOption, "-1"},
			{portOption, "65536"},
			{portOption, "0x2323"},
			{portOption, "2323", "extra"},
			{"extra"},
			{"-verbose"},
			{"-h"},
		} {
			t.Run(fmt.Sprintf("with the options %q: one start_failed line, and a non-zero exit", options), func(t *testing.T) {
				t.Parallel()
				startProgram(t, options...).expectRefusal(t)
			})
		}
		t.Run("with both addresses taken at the port: one start_failed line, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			port, _, _ := heldPort(t)
			startProgram(t, portOption, port).expectRefusal(t)
		})
	})

	t.Run("The engine shall write no line to the local log other than `started` and `start_failed`.", func(t *testing.T) {
		t.Parallel()
		t.Run("a whole call, a silent caller and a stop leave the started line alone", func(t *testing.T) {
			t.Parallel()
			send := stopSignals()[0].prepare(t)
			program := startProgram(t, portOption, "0")
			addresses := program.listening(t)
			whole := expectServed(t, addresses[0])
			whole.typeName(t)
			_ = whole.connection.Close()
			expectServed(t, addresses[len(addresses)-1])
			_, sentBy := send(t, program)
			program.exit(t, sentBy.Add(margin))
			program.expectLog(t, "started")
		})
	})

	t.Run("The engine shall write each line of the local log as one key and its value, `key=value`.", func(t *testing.T) {
		t.Parallel()
		t.Run("the started line is started= and the listeners, ending in LF", func(t *testing.T) {
			t.Parallel()
			send := stopSignals()[0].prepare(t)
			program := startProgram(t, portOption, "0")
			program.listening(t)
			_, sentBy := send(t, program)
			program.exit(t, sentBy.Add(margin))
			program.expectLog(t, "started")
		})
		t.Run("the start_failed line is start_failed= and a reason, ending in LF", func(t *testing.T) {
			t.Parallel()
			startProgram(t, portOption, "abc").expectRefusal(t)
		})
	})

	t.Run("The engine shall not write anything a caller sent to the local log.", func(t *testing.T) {
		t.Parallel()
		t.Run("text shaped like log lines, sent during and after negotiation, is not in the log", func(t *testing.T) {
			t.Parallel()
			send := stopSignals()[0].prepare(t)
			program := startProgram(t, portOption, "0")
			addresses := program.listening(t)
			during := expectServed(t, addresses[0])
			firstConnected := during.connected
			during.send(t, []byte("start_failed="+canary+"\r\n"))
			during.send(t, append(append([]byte{iac, subnegotiationBegin, telnetTypeOption}, canary...), iac, subnegotiationEnd))
			// The engine refuses a request only once it has read every byte the caller sent
			// before it, so the refusal shows the text above has been read.
			during.send(t, []byte{iac, will, telnetTypeOption})
			during.readExactly(t, []byte{iac, dont, telnetTypeOption}, time.Now().Add(margin))
			// The text sent after negotiation becomes the name, cut at 30 characters, and once
			// Hello is written the engine shuts its sending side and says nothing more, so the
			// only sign it has read all of the text, to the caller's end of stream, is the call
			// ending. With the engine full, a new caller is served only once a call has ended,
			// and the silent callers' calls cannot end before their negotiation and name wait
			// run out.
			for range connectionCap - 2 {
				expectServed(t, addresses[0])
			}
			after := expectServed(t, addresses[len(addresses)-1])
			answeredAt := time.Now()
			after.send(t, answers)
			after.readExactly(t, []byte(greeting), time.Now().Add(margin))
			if served(t, addresses[0]) {
				t.Fatalf("a caller was served with %d connections open", connectionCap)
			}
			after.send(t, []byte("started=127.0.0.1:1 "+canary+"\n"))
			if err := after.connection.CloseWrite(); err != nil {
				t.Fatalf("the caller's close of its sending side failed: %v", err)
			}
			for !served(t, addresses[0]) {
				pause(t, 10*time.Millisecond)
			}
			// Past the first moment the closing wait's own end, and past the second a silent
			// call's name wait, could have ended a call, and being served would no longer show
			// the engine read to the caller's end of stream.
			if servedAt := time.Now(); servedAt.After(answeredAt.Add(closingWait)) ||
				servedAt.After(firstConnected.Add(negotiationLimit+nameLimit)) {
				t.Fatalf("a caller was served only %v after the closing caller answered, too late to tell what ended the call",
					servedAt.Sub(answeredAt))
			}
			_, sentBy := send(t, program)
			program.exit(t, sentBy.Add(margin))
			if strings.Contains(program.text(), canary) {
				t.Fatalf("the local log holds what a caller sent:\n%s", program.text())
			}
			program.expectLog(t, "started")
		})
	})
}

// rootCommand runs the program as root: directly when the test is root, otherwise through sudo
// without a password, as the CI runners allow. A machine that allows neither fails the row.
func rootCommand(t *testing.T, options ...string) *exec.Cmd {
	t.Helper()
	if os.Geteuid() == 0 {
		return exec.CommandContext(t.Context(), programPath, options...)
	}
	if err := exec.CommandContext(t.Context(), "sudo", "-n", "true").Run(); err != nil {
		t.Fatalf("this row needs root: run it as root, or where sudo needs no password (%v)", err)
	}
	return exec.CommandContext(t.Context(), "sudo", append([]string{"-n", programPath}, options...)...)
}

func TestLinuxRoot(t *testing.T) {
	t.Parallel()
	t.Run("If the engine is started as root on Linux, then the engine shall write one `start_failed` line to the local log saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		for _, options := range [][]string{nil, {portOption, "0"}} {
			t.Run(fmt.Sprintf("as root with the options %q: one start_failed line naming root, and a non-zero exit", options), func(t *testing.T) {
				t.Parallel()
				if buildFailure != nil {
					t.Fatalf("the program did not build: %v", buildFailure)
				}
				reason := startCommand(t, rootCommand(t, options...)).expectRefusal(t)
				if !strings.Contains(strings.ToLower(reason), "root") {
					t.Fatalf("the start_failed reason %q does not say the engine was started as root", reason)
				}
			})
		}
	})
}

// TestLinuxHighestPort is Linux's alone because Windows hands out ports up to 65535 for port 0
// (49152 to 65535 on CI's runner, 2026-10-22), so a parallel row's program or caller can take it
// there; Linux's runners hand out 32768 to 60999.
func TestLinuxHighestPort(t *testing.T) {
	t.Parallel()
	t.Run("When the sysop passes a Telnet port on the command line, the engine shall listen on that port in place of port 23.", func(t *testing.T) {
		t.Parallel()
		t.Run("with -port 65535, the highest port, it names and serves it", func(t *testing.T) {
			t.Parallel()
			highestPort.Lock()
			defer highestPort.Unlock()
			for _, address := range []string{"127.0.0.1:65535", "[::1]:65535"} {
				held, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", address)
				if err != nil {
					t.Fatalf("%s is not free on this machine, so this row cannot run: %v", address, err)
				}
				_ = held.Close()
			}
			program := startProgram(t, portOption, "65535")
			addresses := program.listening(t)
			expectAddresses(t, addresses, "127.0.0.1:65535", "[::1]:65535")
			for _, address := range addresses {
				expectServed(t, address)
			}
			_ = program.command.Process.Kill()
			<-program.exited
		})
	})
}

func TestLinuxLowPort(t *testing.T) {
	t.Parallel()
	t.Run("If a command-line option is malformed, or the engine fails to listen at both addresses for Telnet or, when SSH is on, for SSH, then the engine shall write one `start_failed` line to the local log saying why, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("with no option, as an ordinary user who may not listen below port 1024: one start_failed line, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			if os.Geteuid() == 0 {
				t.Fatalf("this row needs an ordinary user, not root")
			}
			setting, err := os.ReadFile("/proc/sys/net/ipv4/ip_unprivileged_port_start")
			if err != nil {
				t.Fatalf("reading the lowest port an ordinary user may listen on: %v", err)
			}
			lowest, err := strconv.Atoi(strings.TrimSpace(string(setting)))
			if err != nil || lowest <= 23 {
				t.Fatalf("this machine lets an ordinary user listen from port %q, so port 23 cannot fail here", setting)
			}
			startProgram(t).expectRefusal(t)
		})
	})
}

// TestLinuxListeningSockets is Linux's alone because the page names the operating system's table
// of listening sockets as a second oracle there: a caller can tell a listener on every IPv6
// address from one at ::1 only by dialing a routable IPv6 address, and no runner has one.
func TestLinuxListeningSockets(t *testing.T) {
	t.Parallel()
	t.Run("The engine shall listen for callers at 127.0.0.1 and at ::1, and at no other address.", func(t *testing.T) {
		t.Parallel()
		t.Run("every listening socket the system's table shows for the program is at 127.0.0.1 or ::1", func(t *testing.T) {
			t.Parallel()
			program := startProgram(t, portOption, "0")
			addresses := program.listening(t)
			sockets := listeningSockets(t, program.command.Process.Pid)
			if len(sockets) == 0 {
				t.Fatalf("the system's table shows no listening socket for the program, which named %q", addresses)
			}
			for _, socket := range sockets {
				host, _, err := net.SplitHostPort(socket)
				if err != nil || (host != ipv4Loopback && host != ipv6Loopback) {
					t.Errorf("the program listens at %s, which is not 127.0.0.1 or ::1; it named %q", socket, addresses)
				}
			}
		})
	})
}
