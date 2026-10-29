// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package orchestrator holds the engine's services for one hold of the server's lease: it starts
// them all, says when all are running, and on a stop stops them all at once and waits for each.
//
// It is built on the developer's design, in his words of 2026-10-25: "It's going to be running a
// lot of different IP components, and each need to operate separately while also not duplicating
// code", "Instead, we thread (or Go routines)", and "3 separate listens so any one of them can be
// brought up and shut down but a single execution path since they all ultimately do the same
// thing at the caller level". So each service keeps its own Start and Stop, its own goroutines and
// its own context, and the orchestrator only calls them. In this part each service is one kind's
// listener, which is a Service because it has a Start and a Stop.
//
// It owns starting every service it holds, saying when all have started, and stopping them all
// together, none waiting for another, and waiting for each. A service has started, which is all
// "healthy" means in this part, once its Start has returned. It does not own making a service: the
// program opens each kind's sockets and makes its listener before the orchestrator starts any, so
// a start that fails serves no caller. The lease, waiting for the database, the service manager,
// the stop signals and the local log are the program's; what a service does is its own. A health
// report beyond a service having started, restarting a service, and turning one on or off while
// the engine runs belong to later layers. It has no files and writes no local log.
//
// What the engine does as a whole, this package included, is in docs/behavior.md.
//
// # Untrusted input
//
// None reaches it: it holds services and calls their Start and Stop. Everything a caller sends is
// read by the services. There is no fuzz target here: this package parses nothing.
//
// # What it needs from its callers
//
// One Orchestrator per hold of the server's lease, made from services already made and not yet
// started, none of them a nil pointer, each handed to one New only and not started or stopped by
// the caller after. Its Start and Stop called from one goroutine: Stop after Start, or in its
// place. A Service's Start returns once it is serving; its Stop returns when nothing of it is
// running, works before Start as after it, and is safe to call on several services at once. A
// stopped service is not started again: when the program takes its server's lease again, it
// makes new services and a new Orchestrator.
//
// # Lines for the package
//
//   - The orchestrator package shall call nothing of a service but its Start and its Stop. [read]
//   - The orchestrator package shall write nothing to standard output or standard error. [read]
//   - The orchestrator package shall import nothing outside the Go standard library. [read]
package orchestrator

import "errors"

// ErrNoService means New was given a nil Service: its only error.
var ErrNoService = errors.New("orchestrator: a service is missing")

// Service is one of the engine's services; in this part, each kind's listener. Declared here,
// where it is used, so that the orchestrator names no kind of service.
type Service interface {
	// Start starts the service and returns once it is serving.
	Start()
	// Stop stops the service and returns when nothing of it is running.
	Stop()
}

// Orchestrator is the engine's services for one hold of the server's lease. An Orchestrator not
// made by New, or nil, holds nothing, and Start and Stop on it return at once.
type Orchestrator struct {
	state orchestratorState
}

// New holds the services the program made, and starts none of them. Given none, it holds none,
// and Start and Stop return at once. When it refuses, it returns a nil Orchestrator, and the
// services stay the caller's to stop.
//
//   - New shall call nothing of any service it is given.
//   - If any Service it is given is nil, then New shall return ErrNoService and hold none of
//     them.
func New(services []Service) (*Orchestrator, error) {
	return newOrchestrator(services)
}

// Start starts every service this Orchestrator holds and returns once each has started: the
// engine is then ready, and the program says so to the service manager.
//
//   - Start shall call each service's Start once, and return only once every one has returned.
//   - A second Start, or a Start after Stop, shall start nothing.
func (orchestrator *Orchestrator) Start() {
	orchestrator.start()
}

// Stop stops every service this Orchestrator holds, started or not, and returns when each has
// stopped, so that every connection closes at once, as Part 1's stop has it. It never fails.
//
//   - Stop shall call each service's Stop once, none waiting for another's to return.
//   - Stop shall return only once every service's Stop has returned.
//   - A second Stop shall do nothing.
func (orchestrator *Orchestrator) Stop() {
	orchestrator.stop()
}
