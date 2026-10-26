// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package listener

import (
	"context"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/heliosestate/heliosadvance/internal/session"
	"github.com/heliosestate/heliosadvance/internal/textio"
)

// The contract's operations hand their work to the unexported functions below, so the contract
// builds before the package is built and the build never needs to change the contract.

type listenerState struct {
	stopContext context.Context
	cancel      context.CancelFunc
	sockets     []*net.TCPListener
	goroutines  sync.WaitGroup
	stopOnce    sync.Once

	openLock sync.Mutex
	open     int
}

func start(kinds []Kind) (*Listener, error) {
	if len(kinds) == 0 {
		return nil, ErrNoListeners
	}
	for _, kind := range kinds {
		if len(kind.Sockets) == 0 || slices.Contains(kind.Sockets, nil) || kind.Open == nil {
			return nil, ErrNoListeners
		}
	}
	listener := &Listener{}
	state := &listener.state
	state.stopContext, state.cancel = context.WithCancel(context.Background())
	for _, kind := range kinds {
		state.sockets = append(state.sockets, kind.Sockets...)
	}
	for _, kind := range kinds {
		for _, socket := range kind.Sockets {
			state.goroutines.Go(func() { state.acceptLoop(socket, kind.Open) })
		}
	}
	return listener, nil
}

// acceptLoop's pause is its own, so one socket failing to accept never slows another. The pause
// is capped at AcceptPauseMostMilliseconds, which is what keeps "accept again within 1 second"
// true however long accepting keeps failing.
func (state *listenerState) acceptLoop(socket *net.TCPListener, open Open) {
	pause := time.Duration(AcceptPauseFirstMilliseconds) * time.Millisecond
	longest := time.Duration(AcceptPauseMostMilliseconds) * time.Millisecond
	for {
		connection, err := socket.AcceptTCP()
		if err != nil {
			if state.stopContext.Err() != nil {
				return
			}
			timer := time.NewTimer(pause)
			select {
			case <-timer.C:
			case <-state.stopContext.Done():
				timer.Stop()
				return
			}
			pause = min(pause*2, longest)
			continue
		}
		acceptedAt := time.Now()
		pause = time.Duration(AcceptPauseFirstMilliseconds) * time.Millisecond
		if !state.takePlace() {
			//nolint:errcheck // nothing was written to it, so a failed close has no one to tell
			connection.Close()
			continue
		}
		state.goroutines.Go(func() {
			defer state.givePlace()
			state.serve(connection, open, acceptedAt)
		})
	}
}

func (state *listenerState) takePlace() bool {
	state.openLock.Lock()
	defer state.openLock.Unlock()
	if state.open >= ConnectionCap {
		return false
	}
	state.open++
	return true
}

func (state *listenerState) givePlace() {
	state.openLock.Lock()
	defer state.openLock.Unlock()
	state.open--
}

// A failure in a call ends it without a log: the local log holds only the start and its failure.
func (state *listenerState) serve(connection *net.TCPConn, open Open, acceptedAt time.Time) {
	ceiling := acceptedAt.Add(CeilingSeconds * time.Second)
	ctx, cancel := context.WithDeadline(state.stopContext, ceiling)
	closed := make(chan struct{})
	// The ceiling, Stop and the end of the call all close the connection this one way.
	context.AfterFunc(ctx, func() {
		defer close(closed)
		//nolint:errcheck // the call has ended, and a failed close has no one to tell
		connection.Close()
	})
	defer func() {
		cancel()
		<-closed
	}()

	kindConnection, err := open(ctx, connection)
	if err != nil || kindConnection == nil {
		return
	}
	if ending, err := session.Run(ctx, textio.New(kindConnection)); err != nil || ending != session.Answered {
		return
	}
	//nolint:errcheck // the connection is closed next whatever the kind's close returns
	kindConnection.Close(ctx)
}

// stop cancels before it closes the sockets so that an accept loop sees the stop before it sees
// its socket fail, and does not take the close for a failed accept to pause on.
func (listener *Listener) stop() {
	if listener == nil || listener.state.cancel == nil {
		return
	}
	state := &listener.state
	state.stopOnce.Do(func() {
		state.cancel()
		for _, socket := range state.sockets {
			//nolint:errcheck // the socket is closing for good; a failed close has no one to tell
			socket.Close()
		}
		state.goroutines.Wait()
	})
}
