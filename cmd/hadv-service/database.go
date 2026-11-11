// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/heliosestate/heliosadvance/internal/database"
	"github.com/heliosestate/heliosadvance/internal/language"
	"github.com/heliosestate/heliosadvance/internal/listener"
	"github.com/heliosestate/heliosadvance/internal/servicemanager"
	"github.com/heliosestate/heliosadvance/internal/ssh"
	"github.com/heliosestate/heliosadvance/internal/telnets"
)

// retryEvery is how long after one try started the next starts, so a try that used its whole
// limit is followed at once.
const retryEvery = 10 * time.Second

// serve takes the server's lease, listens while it holds it, and takes it again after a loss,
// until a stop. It returns the exit code.
func serve(stopContext context.Context, ready servicemanager.Ready, log func(key, value string),
	server *database.ServerDatabase, options commandLine, hostKey *ssh.HostKey, certificate *telnets.Certificate,
	texts *language.Texts,
) int {
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
				ready()
			}
			select {
			case <-stopContext.Done():
				return 0
			case <-time.After(time.Until(tried.Add(retryEvery))):
			}
			continue
		}

		listeners, addresses, err := newListeners(stopContext, options, hostKey, certificate, count, texts)
		if err != nil {
			lease.EndLease()
			log("start_failed", err.Error())
			return exitFailed
		}
		//nolint:contextcheck // a Listener lives one lease; its owner stops it with Stop
		startAll(listeners)
		log("started", strings.Join(addresses, ","))
		ready()
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
func newListeners(ctx context.Context, options commandLine, hostKey *ssh.HostKey,
	certificate *telnets.Certificate, count *listener.ConnectionCount, texts *language.Texts,
) ([]*listener.Listener, []string, error) {
	telnetListener, telnetAddresses, err := newTelnetListener(ctx, options.telnetPort, count, texts)
	if err != nil {
		return nil, nil, errors.New("telnet listeners: " + err.Error())
	}
	listeners := []*listener.Listener{telnetListener}
	addresses := urls("telnet", telnetAddresses)
	if hostKey != nil {
		sshListener, sshAddresses, err := newSSHListener(ctx, options.sshPort, hostKey, count, texts)
		if err != nil {
			stopAll(listeners)
			return nil, nil, errors.New("ssh listeners: " + err.Error())
		}
		listeners = append(listeners, sshListener)
		addresses = append(addresses, urls("ssh", sshAddresses)...)
	}
	if certificate != nil {
		telnetsListener, telnetsAddresses, err := newTelnetsListener(
			ctx, options.tlsPort, certificate, count, texts)
		if err != nil {
			stopAll(listeners)
			return nil, nil, errors.New("telnets listeners: " + err.Error())
		}
		listeners = append(listeners, telnetsListener)
		addresses = append(addresses, urls("telnets", telnetsAddresses)...)
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
