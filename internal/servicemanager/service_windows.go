// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package servicemanager

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows/svc"
)

func runWindowsService(run Run) (int, error) {
	handler := &serviceHandler{
		run:      run,
		readyAsk: make(chan struct{}, 1),
		finished: make(chan struct{}),
		gone:     make(chan struct{}),
	}
	err := svc.Run(ServiceName, handler)
	close(handler.gone)
	if !handler.started.Load() {
		return 0, errors.Join(ErrServiceManagerConnect, err)
	}
	// The library stops listening to the handler when it cannot tell the service manager a status,
	// so the program's run may still be running here.
	<-handler.finished
	if handler.statusFailed.Load() || err != nil {
		return handler.code, errors.Join(ErrServiceManagerConnect, err)
	}
	return handler.code, nil
}

// serviceHandler is the one place every status change is sent from: Execute's loop.
type serviceHandler struct {
	run          Run
	readyAsk     chan struct{}
	readyOnce    sync.Once
	started      atomic.Bool
	statusFailed atomic.Bool
	// finished closes when run has returned, and code is then run's code.
	finished chan struct{}
	code     int
	// gone closes when the library has stopped taking statuses.
	gone chan struct{}
}

func (handler *serviceHandler) ready() {
	handler.readyOnce.Do(func() { handler.readyAsk <- struct{}{} })
}

func (handler *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest,
	changes chan<- svc.Status,
) (bool, uint32) {
	handler.started.Store(true)
	stopContext, stop := context.WithCancel(context.Background())
	defer stop()

	current := svc.Status{State: svc.StartPending}
	report := func() {
		select {
		case changes <- current:
		case <-handler.gone:
			handler.statusFailed.Store(true)
			stop()
		}
	}
	report()

	go func() {
		handler.code = handler.run(stopContext, handler.ready)
		close(handler.finished)
	}()

	for {
		select {
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				report()
			case svc.Stop, svc.Shutdown:
				stop()
			}
		case <-handler.readyAsk:
			current = svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
			report()
		case <-handler.finished:
			if handler.code == 0 {
				return false, 0
			}
			return true, uint32(handler.code & math.MaxUint32)
		}
	}
}
