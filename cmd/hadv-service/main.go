// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Command hadv-service is the Helios Advance engine as a sysop runs it: it opens the
// bootstrap folder, takes its server's lease, and only while it holds the lease opens the loopback
// listening sockets, closing everything when the lease is lost or it is told to stop. It exists so
// the sysop has one program to start, and one local log, standard output or a log file, to read.
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
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/heliosestate/heliosadvance/internal/bootstrap"
	"github.com/heliosestate/heliosadvance/internal/database"
	"github.com/heliosestate/heliosadvance/internal/language"
	"github.com/heliosestate/heliosadvance/internal/listener"
	"github.com/heliosestate/heliosadvance/internal/servicemanager"
	"github.com/heliosestate/heliosadvance/internal/ssh"
	"github.com/heliosestate/heliosadvance/internal/telnets"
)

const (
	ipv4Address = "127.0.0.1"
	ipv4Network = "tcp4"
	ipv6Network = "tcp6"
	ipv6Address = "::1"

	exitFailed = 1
)

func main() {
	os.Exit(start())
}

// start asks first whether Windows' service manager started the program, since a service that
// never answers it is reported as one that failed to start. After an unknown answer, a failed
// connection means no service manager started it, and it runs as an ordinary program.
func start() int {
	started, err := servicemanager.StartedByWindowsServiceManager()
	if started || err != nil {
		// A failed status update after the run has finished reports the same error as no
		// connection, and must not run the engine a second time.
		ran := false
		code, connectErr := servicemanager.RunWindowsService(
			func(stopContext context.Context, ready servicemanager.Ready) int {
				ran = true
				return run(os.Args[1:], os.Stdout, stopContext, ready, true)
			})
		if connectErr == nil || ran {
			return code
		}
		if started {
			newLocalLog(os.Stdout)("start_failed", connectErr.Error())
			return exitFailed
		}
	}
	// Registered before anything listens: a stop sent as soon as the started line is read must
	// not take the default action and kill the process without closing connections.
	stopContext, release := signal.NotifyContext(context.Background(), stopSignals()...)
	defer release()
	return run(os.Args[1:], os.Stdout, stopContext, servicemanager.NotifySystemdReady, false)
}

// run returns the exit code, so that every deferred call has run before the process ends. The
// local log starts on console and moves to the log file once that is open. A log file that cannot
// be closed makes the exit code non-zero: the local log has no line for it, and the log file is
// where it would be written.
func run(arguments []string, console io.Writer, stopContext context.Context,
	ready servicemanager.Ready, underService bool,
) (code int) {
	log := newLocalLog(console)

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

	if options.logFilePath != "" {
		file, err := os.OpenFile(filepath.Clean(options.logFilePath), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			log("start_failed", "the log file cannot be opened for appending: "+err.Error())
			return exitFailed
		}
		// Closed before the service is reported stopped, after which Windows may end the process.
		defer func() {
			if file.Close() != nil {
				code = exitFailed
			}
		}()
		log = newLocalLog(file)
	} else if underService {
		log("start_failed", "no log file: a service has no console, and the command line names none, with -log-file")
		return exitFailed
	}

	if options.bootstrapFolder == "" {
		log("start_failed", "no bootstrap folder: the command line names none, with -bootstrap")
		return exitFailed
	}
	// The errors are the bootstrap and database packages', which name the refusal and hold nothing
	// of either file.
	settings, err := bootstrap.Open(options.bootstrapFolder)
	if err != nil {
		log("start_failed", err.Error())
		return exitFailed
	}
	connection, err := database.ParseConnection(settings)
	clear(settings)
	if err != nil {
		log("start_failed", err.Error())
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

	// Read before anything listens, as the host key is. The error is the telnets package's, which
	// names the file and the refusal and holds nothing of either file.
	var certificate *telnets.Certificate
	if options.certificatePath != "" {
		certificate, err = telnets.ReadCertificate(options.certificatePath, options.keyPath)
		if err != nil {
			log("start_failed", err.Error())
			return exitFailed
		}
	}

	texts, err := loadTexts(options.language, log)
	if err != nil {
		log("start_failed", err.Error())
		return exitFailed
	}

	return serve(stopContext, ready, log, database.NewServerDatabase(connection), hostKey, certificate, texts)
}

// loadTexts reads the lang folder beside the executable, as the system names the executable and
// with no further resolving of links, before anything listens, and writes one text_missing line for
// each text the board's language lacks. A failure is returned for the caller to log, never logged
// here: the language package's errors name the file and why and hold nothing of it, so they are
// safe to log.
func loadTexts(code string, log func(key, value string)) (*language.Texts, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("the lang folder beside the executable cannot be found: %w", err)
	}
	folder := filepath.Join(filepath.Dir(executable), language.Folder)
	texts, err := language.Load(folder, code)
	if errors.Is(err, language.ErrNotInstalled) {
		return nil, fmt.Errorf("-lang %q names no language the lang folder %s holds", code, folder)
	}
	if err != nil {
		return nil, err
	}
	for _, key := range texts.Missing() {
		log("text_missing", code+" has no "+key+" that can be shown, so it is taken from further along the chain")
	}
	return texts, nil
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

// commandLine is what the sysop asked for: the bootstrap folder that holds what the database
// needs, the host key file for SSH, the certificate and key files for Telnet over TLS, the log
// file that takes the local log from standard output, and the code of the board's language. Which
// services run, and on which ports, is the server's settings in the database, never the command
// line.
type commandLine struct {
	hostKeyPath     string
	certificatePath string
	keyPath         string
	bootstrapFolder string
	logFilePath     string
	language        string
}

// parseCommandLine takes the last of an option given twice.
func parseCommandLine(arguments []string) (commandLine, error) {
	options := commandLine{language: language.Fallback}
	flags := flag.NewFlagSet("hadv-service", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Func("bootstrap", "bootstrap folder, which holds what the database needs", func(value string) error {
		options.bootstrapFolder = value
		return nil
	})
	flags.Func("ssh-host-key", "host key file, which SSH needs when the server's settings turn it on", func(value string) error {
		if value == "" {
			return errors.New("the host key file's path is empty")
		}
		options.hostKeyPath = value
		return nil
	})
	flags.Func("tls-cert", "certificate file, which Telnet over TLS needs when the server's settings turn it on", func(value string) error {
		if value == "" {
			return errors.New("the certificate file's path is empty")
		}
		options.certificatePath = value
		return nil
	})
	flags.Func("tls-key", "key file for the certificate", func(value string) error {
		if value == "" {
			return errors.New("the key file's path is empty")
		}
		options.keyPath = value
		return nil
	})
	flags.Func("log-file", "log file, which takes the local log in place of standard output", func(value string) error {
		if value == "" {
			return errors.New("the log file's path is empty")
		}
		options.logFilePath = value
		return nil
	})
	// An empty code is not refused here: it must reach Load and be refused as naming no language.
	flags.Func("lang", "language code of the board's texts", func(value string) error {
		options.language = value
		return nil
	})
	if err := flags.Parse(arguments); err != nil {
		return commandLine{}, err
	}
	if flags.NArg() > 0 {
		return commandLine{}, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if (options.certificatePath == "") != (options.keyPath == "") {
		return commandLine{}, errors.New("-tls-cert and -tls-key go together")
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

// newKindListener opens a kind's sockets and gives them to a new Listener with the kind's Accept,
// closing the sockets only when New refuses: once it has them they are the Listener's. The
// Listener wants a nil KindConnection on an error, never one holding a nil connection.
func newKindListener[K listener.KindConnection](ctx context.Context, targets []target, port string,
	accept func(context.Context, *net.TCPConn) (K, error), count *listener.ConnectionCount, texts *language.Texts,
) (*listener.Listener, []string, error) {
	sockets, addresses, err := listen(ctx, targets, port)
	if err != nil {
		return nil, nil, err
	}
	open := func(ctx context.Context, connection *net.TCPConn) (listener.KindConnection, error) {
		kindConnection, err := accept(ctx, connection)
		if err != nil {
			return nil, err
		}
		return kindConnection, nil
	}
	kindListener, err := listener.New(sockets, open, count, texts)
	if err != nil {
		return nil, nil, errors.Join(err, closeAll(sockets))
	}
	return kindListener, addresses, nil
}

// newCredentialListener is newKindListener for a kind whose Accept needs what was read at start,
// the SSH host key or the Telnet over TLS certificate, so that each kind states only its Accept.
func newCredentialListener[C any, K listener.KindConnection](ctx context.Context, targets []target,
	port string, credential C, accept func(context.Context, *net.TCPConn, C) (K, error),
	count *listener.ConnectionCount, texts *language.Texts,
) (*listener.Listener, []string, error) {
	bound := func(ctx context.Context, connection *net.TCPConn) (K, error) {
		return accept(ctx, connection, credential)
	}
	return newKindListener(ctx, targets, port, bound, count, texts)
}
