// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Command hadv-service is the Helios Advance engine as a sysop runs it: it opens the loopback
// listening sockets, makes each kind's Listener from that kind's sockets, and closes everything
// when told to stop. It exists so the sysop has one program to start, and one local log, standard
// error, to read.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/heliosestate/heliosadvance/internal/listener"
	"github.com/heliosestate/heliosadvance/internal/ssh"
)

const (
	ipv4Address = "127.0.0.1"
	ipv6Address = "::1"

	exitFailed = 1
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

// run returns the exit code, so that every deferred call has run before the process ends.
func run(arguments []string, logOutput io.Writer) int {
	log := newLocalLog(logOutput)

	// Checked before the command line, so that a start as root is refused whatever else is wrong.
	if runtime.GOOS == "linux" && (os.Getuid() == 0 || os.Geteuid() == 0) {
		log("start_failed", "the engine was started as root, and does not run as root")
		return exitFailed
	}

	options, err := parseCommandLine(arguments)
	if err != nil {
		log("start_failed", "malformed command line: "+err.Error())
		return exitFailed
	}

	// Read before anything listens, so that a refused key opens no socket. The error is the ssh
	// package's, which names the refusal and holds nothing of the file.
	var hostKey *ssh.HostKey
	if options.hostKeyPath != "" {
		hostKey, err = ssh.ReadHostKey(options.hostKeyPath)
		if err != nil {
			log("start_failed", err.Error())
			return exitFailed
		}
	}

	// Registered before anything listens: a stop sent as soon as the started line is read must
	// not take the default action and kill the process without closing connections.
	stopContext, release := signal.NotifyContext(context.Background(), stopSignals()...)
	defer release()

	count := listener.NewCount()
	telnetListener, telnetAddresses, err := newTelnetListener(stopContext, options.telnetPort, count)
	if err != nil {
		log("start_failed", "telnet listeners: "+err.Error())
		return exitFailed
	}
	listeners := []*listener.Listener{telnetListener}
	addresses := urls("telnet", telnetAddresses)

	if hostKey != nil {
		sshListener, sshAddresses, err := newSSHListener(stopContext, options.sshPort, hostKey, count)
		if err != nil {
			telnetListener.Stop()
			log("start_failed", "ssh listeners: "+err.Error())
			return exitFailed
		}
		listeners = append(listeners, sshListener)
		addresses = append(addresses, urls("ssh", sshAddresses)...)
	}

	for _, started := range listeners {
		started.Start()
	}
	log("started", strings.Join(addresses, ","))

	<-stopContext.Done()
	var stopping sync.WaitGroup
	for _, stopped := range listeners {
		stopping.Go(stopped.Stop)
	}
	stopping.Wait()
	return 0
}

// newLocalLog writes one key=value line per call through log/slog's text form, which quotes and
// escapes a value so that whatever an error's text holds stays on one line.
func newLocalLog(output io.Writer) func(key, value string) {
	logger := slog.New(slog.NewTextHandler(output, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, attribute slog.Attr) slog.Attr {
			if len(groups) == 0 {
				switch attribute.Key {
				case slog.TimeKey, slog.LevelKey, slog.MessageKey:
					return slog.Attr{}
				}
			}
			return attribute
		},
	}))
	return func(key, value string) {
		logger.Info("", key, value)
	}
}

// commandLine is what the sysop asked for: the ports as decimal strings, and the host key file
// that turns SSH on.
type commandLine struct {
	telnetPort  string
	sshPort     string
	hostKeyPath string
}

// portFlag reads a port the way every port option does. ParseUint with base 10 refuses the 0x
// prefix, a sign and underscores that flag.Int takes.
func portFlag(port *string) func(string) error {
	return func(value string) error {
		parsed, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return err
		}
		*port = strconv.FormatUint(parsed, 10)
		return nil
	}
}

// parseCommandLine takes the last of an option given twice.
func parseCommandLine(arguments []string) (commandLine, error) {
	options := commandLine{telnetPort: defaultPort, sshPort: defaultSSHPort}
	sshPortGiven := false
	flags := flag.NewFlagSet("hadv-service", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Func("port", "port to listen on for Telnet", portFlag(&options.telnetPort))
	flags.Func("ssh-port", "port to listen on for SSH", func(value string) error {
		sshPortGiven = true
		return portFlag(&options.sshPort)(value)
	})
	flags.Func("ssh-host-key", "host key file, which turns SSH on", func(value string) error {
		if value == "" {
			return errors.New("the host key file's path is empty")
		}
		options.hostKeyPath = value
		return nil
	})
	if err := flags.Parse(arguments); err != nil {
		return commandLine{}, err
	}
	if flags.NArg() > 0 {
		return commandLine{}, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if sshPortGiven && options.hostKeyPath == "" {
		return commandLine{}, errors.New("-ssh-port needs -ssh-host-key")
	}
	return options, nil
}

// urls writes each address as the kind's URL, which is how the started line names a listener.
func urls(kind string, addresses []string) []string {
	named := make([]string, len(addresses))
	for index, address := range addresses {
		named[index] = kind + "://" + address
	}
	return named
}

func stopSignals() []os.Signal {
	if runtime.GOOS == "windows" {
		return []os.Signal{os.Interrupt}
	}
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

// listen opens each loopback address on its own network. One address failing is not a failure
// while the other opens; the addresses are taken here because the Listener owns the sockets
// once it has them.
func listen(ctx context.Context, targets []target, port string) ([]*net.TCPListener, []string, error) {
	var sockets []*net.TCPListener
	var addresses []string
	var failures []error
	for _, endpoint := range targets {
		socket, err := (&net.ListenConfig{}).Listen(ctx, endpoint.network,
			net.JoinHostPort(endpoint.address, port))
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", endpoint.address, err))
			continue
		}
		tcpSocket, ok := socket.(*net.TCPListener)
		if !ok {
			failures = append(failures, errors.Join(
				fmt.Errorf("%s: not a TCP listener", endpoint.address), socket.Close()))
			continue
		}
		sockets = append(sockets, tcpSocket)
		addresses = append(addresses, tcpSocket.Addr().String())
	}
	if len(sockets) == 0 {
		return nil, nil, errors.Join(failures...)
	}
	return sockets, addresses, nil
}

func closeAll(sockets []*net.TCPListener) error {
	var failures []error
	for _, socket := range sockets {
		failures = append(failures, socket.Close())
	}
	return errors.Join(failures...)
}

// target is a kind's address with the network it must be opened on, since the address alone does
// not say IPv4 or IPv6 to net.Listen.
type target struct{ network, address string }
