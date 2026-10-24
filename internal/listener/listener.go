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
	"github.com/heliosestate/heliosadvance/internal/telnet"
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

func start(sockets []*net.TCPListener) (*Listener, error) {
	if len(sockets) == 0 || slices.Contains(sockets, nil) {
		return nil, ErrNoListeners
	}
	listener := &Listener{}
	state := &listener.state
	state.sockets = slices.Clone(sockets)
	state.stopContext, state.cancel = context.WithCancel(context.Background())
	for _, socket := range state.sockets {
		state.goroutines.Go(func() { state.acceptLoop(socket) })
	}
	return listener, nil
}

// acceptLoop's pause is its own, so one socket failing to accept never slows another. The pause
// is capped at AcceptPauseMostMilliseconds, which is what keeps "accept again within 1 second"
// true however long accepting keeps failing.
func (state *listenerState) acceptLoop(socket *net.TCPListener) {
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
			state.serve(connection, acceptedAt)
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
func (state *listenerState) serve(connection *net.TCPConn, acceptedAt time.Time) {
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

	if err := keepUrgentInLine(connection); err != nil {
		return
	}
	line, _, err := telnet.Open(ctx, connection)
	if err != nil {
		return
	}
	if ending, err := session.Run(ctx, textio.New(line)); err != nil || ending != session.Answered {
		return
	}
	if err := connection.CloseWrite(); err != nil {
		return
	}
	closingEnd := time.Now().Add(ClosingWaitSeconds * time.Second)
	if err := connection.SetReadDeadline(earlier(closingEnd, ceiling)); err != nil {
		return
	}
	var discard [DiscardBufferSize]byte
	for {
		if _, err := connection.Read(discard[:]); err != nil {
			return
		}
	}
}

func earlier(first, second time.Time) time.Time {
	if second.Before(first) {
		return second
	}
	return first
}

// keepUrgentInLine is set before anything is read, since a Synch whose DM byte leaves the stream
// would leave its IAC to swallow the caller's next character.
func keepUrgentInLine(connection *net.TCPConn) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	if err := raw.Control(func(descriptor uintptr) { setErr = setUrgentInLine(descriptor) }); err != nil {
		return err
	}
	return setErr
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
