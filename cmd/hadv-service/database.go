// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/heliosestate/heliosadvance/internal/database"
	"github.com/heliosestate/heliosadvance/internal/listener"
	"github.com/heliosestate/heliosadvance/internal/ssh"
)

// retryEvery is how long after one try started the next starts, so a try that used its whole
// limit is followed at once.
const retryEvery = 10 * time.Second

// serve takes the server's lease, listens while it holds it, and takes it again after a loss,
// until a stop. It returns the exit code.
func serve(log func(key, value string), server *database.ServerDatabase,
	options commandLine, hostKey *ssh.HostKey,
) int {
	// Registered before anything listens: a stop sent as soon as the started line is read must
	// not take the default action and kill the process without closing connections.
	stopContext, release := signal.NotifyContext(context.Background(), stopSignals()...)
	defer release()

	count := listener.NewCount()
	// waitingFor is the reason the last waiting line gave, so a try that fails for the same reason
	// writes nothing.
	waitingFor := ""
	for {
		tried := time.Now()
		lease, err := server.Take(stopContext)
		if err != nil {
			if stopContext.Err() != nil {
				return 0
			}
			if !fixesItself(err) {
				log("start_failed", err.Error())
				return exitFailed
			}
			if reason := err.Error(); reason != waitingFor {
				log("waiting", reason)
				waitingFor = reason
			}
			select {
			case <-stopContext.Done():
				return 0
			case <-time.After(time.Until(tried.Add(retryEvery))):
			}
			continue
		}

		listeners, addresses, err := newListeners(stopContext, options, hostKey, count)
		if err != nil {
			lease.EndLease()
			log("start_failed", err.Error())
			return exitFailed
		}
		startAll(listeners)
		log("started", strings.Join(addresses, ","))
		waitingFor = ""

		select {
		case <-stopContext.Done():
			stopAll(listeners)
			// A select takes either ready case at random, and a lost lease has nothing to end.
			select {
			case <-lease.Lost():
			default:
				lease.EndLease()
			}
			return 0
		case <-lease.Lost():
			stopAll(listeners)
			log("lease_lost", "the server's lease was lost")
		}
	}
}

// fixesItself is true for the reasons Take fails that the program waits out; every other one
// stops it.
func fixesItself(err error) bool {
	for _, waited := range []error{database.ErrUnreachable, database.ErrNotReady, database.ErrNoConnectionFree,
		database.ErrReadOnly, database.ErrLeaseHeld} {
		if errors.Is(err, waited) {
			return true
		}
	}
	return false
}

// newListeners makes every kind's listener, sharing the one count. On a failure it stops those it
// made.
func newListeners(ctx context.Context, options commandLine, hostKey *ssh.HostKey, count *listener.ConnectionCount,
) ([]*listener.Listener, []string, error) {
	telnetListener, telnetAddresses, err := newTelnetListener(ctx, options.telnetPort, count)
	if err != nil {
		return nil, nil, errors.New("telnet listeners: " + err.Error())
	}
	listeners := []*listener.Listener{telnetListener}
	addresses := urls("telnet", telnetAddresses)
	if hostKey != nil {
		sshListener, sshAddresses, err := newSSHListener(ctx, options.sshPort, hostKey, count)
		if err != nil {
			telnetListener.Stop()
			return nil, nil, errors.New("ssh listeners: " + err.Error())
		}
		listeners = append(listeners, sshListener)
		addresses = append(addresses, urls("ssh", sshAddresses)...)
	}
	return listeners, addresses, nil
}

// startAll is apart from serve so that serve, which holds the stop context, does not call a
// Listener's Start, which takes none.
func startAll(listeners []*listener.Listener) {
	for _, kindListener := range listeners {
		kindListener.Start()
	}
}

// stopAll stops every listener together, since each drains its own callers.
func stopAll(listeners []*listener.Listener) {
	var stopping sync.WaitGroup
	for _, kindListener := range listeners {
		stopping.Go(kindListener.Stop)
	}
	stopping.Wait()
}
