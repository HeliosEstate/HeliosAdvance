// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Command hadv-service is the Helios Advance engine as a sysop runs it: it opens the loopback
// listening sockets, hands them to the Listener, and closes everything when told to stop. It
// exists so the sysop has one program to start, and one local log, standard error, to read.
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
	"syscall"

	"github.com/heliosestate/heliosadvance/internal/listener"
)

const (
	defaultPort = "23"
	// The addresses are the only ones the engine listens on, IPv4 first.
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

	port, err := parseCommandLine(arguments)
	if err != nil {
		log("start_failed", "malformed command line: "+err.Error())
		return exitFailed
	}

	// Registered before anything listens: a stop sent as soon as the started line is read must
	// not take the default action and kill the process without closing connections.
	stopContext, release := signal.NotifyContext(context.Background(), stopSignals()...)
	defer release()

	sockets, addresses, err := listen(stopContext, port)
	if err != nil {
		log("start_failed", err.Error())
		return exitFailed
	}

	engine, err := listener.Start([]listener.Kind{{Sockets: sockets}})
	if err != nil {
		err = errors.Join(err, closeAll(sockets))
		log("start_failed", err.Error())
		return exitFailed
	}

	log("started", strings.Join(addresses, ","))

	<-stopContext.Done()
	engine.Stop()
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

// parseCommandLine returns the port as its decimal string. A port given twice takes the last.
func parseCommandLine(arguments []string) (string, error) {
	port := defaultPort
	flags := flag.NewFlagSet("hadv-service", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Func("port", "port to listen on", func(value string) error {
		// ParseUint with base 10 refuses the 0x prefix, a sign and underscores that flag.Int takes.
		parsed, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return err
		}
		port = strconv.FormatUint(parsed, 10)
		return nil
	})
	if err := flags.Parse(arguments); err != nil {
		return "", err
	}
	if flags.NArg() > 0 {
		return "", fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	return port, nil
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
func listen(ctx context.Context, port string) ([]*net.TCPListener, []string, error) {
	targets := []struct{ network, address string }{
		{"tcp4", ipv4Address},
		{"tcp6", ipv6Address},
	}
	var sockets []*net.TCPListener
	var addresses []string
	var failures []error
	for _, target := range targets {
		socket, err := (&net.ListenConfig{}).Listen(ctx, target.network,
			net.JoinHostPort(target.address, port))
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", target.address, err))
			continue
		}
		tcpSocket, ok := socket.(*net.TCPListener)
		if !ok {
			failures = append(failures, errors.Join(
				fmt.Errorf("%s: not a TCP listener", target.address), socket.Close()))
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
