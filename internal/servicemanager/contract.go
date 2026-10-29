// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package servicemanager is what lets a service manager run the engine and hear that it is
// ready: Windows' service manager, which starts and stops Windows services, and systemd on Linux,
// which is told the engine is ready by one message on a socket it names.
//
// It owns telling whether Windows' service manager started this process; connecting to it as the
// service ServiceName; reporting the service starting, then running once the program says it is
// ready, then stopped with the program's exit code; accepting stop and shutdown and turning either
// into the end of the program's stop context; and answering the service manager's status queries.
// On Linux it owns sending READY=1 to the socket NOTIFY_SOCKET names. Windows' service manager is
// reached through the Go team's golang.org/x/sys/windows/svc, at v0.49.0 or later.
//
// It does not own what the program does while it runs: the command line, the local log and its
// file, the lease, the services and the stop signals of a run that Windows' service manager did
// not start are the program's. Installing the service, its account, its recovery after a crash
// and the systemd unit are hadv-setup's, and in the tests their setup. It has no files and writes
// no local log.
//
// What the engine does as a whole, this package included, is in docs/behavior.md.
//
// # Untrusted input
//
// None from a caller. What it reads comes from whoever started the engine: Windows' service
// manager's requests, through the library, and the NOTIFY_SOCKET environment variable, from the
// same party as the command line. It sends READY=1 and nothing else, so a socket named there
// learns only that the engine is ready. There is no fuzz target here: this package parses
// nothing but the variable's first character.
//
// # Oracles
//
// The service managers themselves, run from outside. On Windows, the service installed with
// sc.exe under NT SERVICE\hadv-service, and read with sc.exe query: its state, and its
// WIN32_EXIT_CODE and SERVICE_EXIT_CODE once stopped. On Linux, a systemd unit with Type=notify,
// so that systemd waits for READY=1 before it counts the service started, read with systemctl
// (ActiveState) and the journal. Tests run on Linux x86-64, Linux ARM64 and Windows x86-64.
//
// # What it needs from its callers
//
// StartedByWindowsServiceManager asked first, before anything that can fail, and when it says
// yes, or cannot say, RunWindowsService called next, once, so that even a refused start reaches
// the service manager as stopped with its code rather than as a service that never answered;
// after ErrStartedHowUnknown, ErrServiceManagerConnect from it means no service manager started
// the engine. A Run that returns 0 or a positive code, and that has finished all its work, its
// log file written and closed among it, before it returns: once the service is reported stopped,
// Windows may end the process at any moment. A Run that never ends the process itself, since the
// service manager reports a process that ends before the service reports stopped as ended
// unexpectedly. Ready, of either kind, called once the engine is ready; later calls are harmless.
//
// # Lines for the package
//
//   - The servicemanager package shall write nothing to the local log, standard output or
//     standard error. [read]
//   - The servicemanager package shall read no environment variable but NOTIFY_SOCKET. [read]
//   - The servicemanager package shall import nothing outside the Go standard library and, on
//     Windows, golang.org/x/sys/windows/svc. [read]
package servicemanager

import (
	"context"
	"errors"
)

// ServiceName is the Windows service's name, the one hadv-setup installs and the tests' setup
// registers.
const ServiceName = "hadv-service"

// Why the engine could not run under Windows' service manager. None holds anything but the
// reason.
var (
	// ErrStartedHowUnknown means Windows could not say whether its service manager started this
	// process.
	ErrStartedHowUnknown = errors.New("servicemanager: cannot tell whether Windows' service manager started the engine")
	// ErrServiceManagerConnect means the engine could not connect to Windows' service manager or
	// tell it the service's state, or, on Linux, that there is none.
	ErrServiceManagerConnect = errors.New("servicemanager: cannot connect to Windows' service manager")
)

// Ready tells the service manager that the engine is ready. The first call counts; later calls
// do nothing. It is safe to call from any goroutine.
type Ready func()

// Run is the engine's whole run under Windows' service manager. Stop ends when the service manager
// sends stop or shutdown, and carries no deadline; the run calls ready once it is ready, and
// returns its exit code rather than ending the process itself.
type Run func(stop context.Context, ready Ready) int

// StartedByWindowsServiceManager reports whether Windows' service manager started this process.
//
//   - When Windows' service manager started this process, StartedByWindowsServiceManager shall
//     return true.
//   - When this process was started any other way, StartedByWindowsServiceManager shall return
//     false.
//   - If Windows cannot say, then StartedByWindowsServiceManager shall return false with
//     ErrStartedHowUnknown. [read]
//   - On Linux, StartedByWindowsServiceManager shall return false and no error.
func StartedByWindowsServiceManager() (bool, error) {
	return startedByWindowsServiceManager()
}

// RunWindowsService runs run as the Windows service ServiceName, from start to stopped, and
// returns run's exit code once the service manager has been told it stopped. The arguments given
// to the start itself, as sc.exe start passes them, are not handed to run: the program reads its
// own command line, as the service was installed.
//
//   - RunWindowsService shall report the service as start pending until ready's first call, and
//     then as running, accepting stop and shutdown.
//   - RunWindowsService shall accept no request from the service manager but stop, shutdown and
//     its status queries.
//   - When the service manager sends stop or shutdown, RunWindowsService shall end stop.
//   - A call to ready after run has returned shall do nothing.
//   - When run returns 0, RunWindowsService shall report the service stopped with no error, and
//     return 0.
//   - When run returns any other code, RunWindowsService shall report the service stopped with
//     ERROR_SERVICE_SPECIFIC_ERROR (1066) as its Windows exit code and run's code as its
//     service-specific exit code, and return run's code.
//   - If it cannot connect to Windows' service manager, then RunWindowsService shall return
//     ErrServiceManagerConnect without calling run.
//   - If it cannot tell Windows' service manager the service's state while run runs, then
//     RunWindowsService shall end stop, and return ErrServiceManagerConnect only once run has
//     returned. [read]
//   - RunWindowsService shall call run once at most.
//   - On Linux, RunWindowsService shall return ErrServiceManagerConnect without calling run.
func RunWindowsService(run Run) (int, error) {
	return runWindowsService(run)
}

// NotifySystemdReady is the Ready of an engine that Windows' service manager did not start. It
// returns nothing: a message that cannot be sent is dropped, and systemd's own start timeout then
// marks the start failed.
//
//   - When NOTIFY_SOCKET names a socket by a path starting with "/", or by an abstract name
//     starting with "@", NotifySystemdReady's first call shall send it READY=1, as one datagram.
//   - NotifySystemdReady shall send nothing when NOTIFY_SOCKET is unset, empty or names anything
//     else, on Windows, or on any call but the first.
func NotifySystemdReady() {
	notifySystemdReady()
}
