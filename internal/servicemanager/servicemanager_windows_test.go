// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package servicemanager_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/servicemanager"
)

// quietWait is how long the Windows row waits for a connection that must not come. The child has
// ended before the row waits, so anything it did is done: the wait is generous, and on a slow
// machine still not proof of absence.
const quietWait = 500 * time.Millisecond

func TestRunWindowsServiceUnstarted(t *testing.T) {
	t.Parallel()
	// The library under RunWindowsService writes variables the whole process shares before it
	// tries to connect, which the engine's one call per process allows. These rows make the test
	// process's only calls, the helper's being in a process of its own, so they take turns: side
	// by side, the race detector reports their writes and fails every test running beside them.
	var calling sync.Mutex
	// The test process: no service manager started it, so there is none to connect to.
	run := func(t *testing.T) (runs int) {
		t.Helper()
		calling.Lock()
		defer calling.Unlock()
		_, err := servicemanager.RunWindowsService(func(context.Context, servicemanager.Ready) int {
			runs++
			return 0
		})
		if !errors.Is(err, servicemanager.ErrServiceManagerConnect) {
			t.Errorf("RunWindowsService returned %v; want ErrServiceManagerConnect", err)
		}
		return runs
	}
	t.Run("If it cannot connect to Windows' service manager, then RunWindowsService shall return ErrServiceManagerConnect without calling run.", func(t *testing.T) {
		t.Parallel()
		t.Run("the test process, which no service manager started", func(t *testing.T) {
			t.Parallel()
			if runs := run(t); runs != 0 {
				t.Errorf("run was called %d times; want none", runs)
			}
		})
	})
	t.Run("RunWindowsService shall call run once at most.", func(t *testing.T) {
		t.Parallel()
		t.Run("no call, where it cannot connect", func(t *testing.T) {
			t.Parallel()
			if runs := run(t); runs != 0 {
				t.Errorf("run was called %d times; want none", runs)
			}
		})
	})
}

func TestNotifySystemdReadyOnWindows(t *testing.T) {
	t.Parallel()
	if calls, isChild := notifyChildCalls(t); isChild {
		sendAsChild(calls)
		return
	}
	t.Run("NotifySystemdReady shall send nothing when NOTIFY_SOCKET is unset, empty or names anything else, on Windows, or on any call but the first.", func(t *testing.T) {
		t.Parallel()
		t.Run(`on Windows, NOTIFY_SOCKET a path starting with "/" where a local socket listens`, func(t *testing.T) {
			t.Parallel()
			// Not the subtest's own folder, whose path carries the subtest's whole name: a local
			// socket's address holds 108 bytes.
			folder, err := os.MkdirTemp("", "n") //nolint:usetesting // the subtest's folder is too long for a socket's address
			if err != nil {
				t.Fatalf("making the socket's folder: %v", err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(folder) })
			path := filepath.Join(folder, "notify.sock")
			// Windows has local stream sockets but no datagram ones, so a stream socket listens
			// for whatever a send would reach.
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatalf("listening on a local socket at %s: %v", path, err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			// The same file named from the current drive's root, starting with "/", as the
			// line's first form names a socket.
			rooted := filepath.ToSlash(strings.TrimPrefix(path, filepath.VolumeName(path)))
			runNotifyChild(t, "TestNotifySystemdReadyOnWindows", notifySocket{set: true, value: rooted}, "", 1)
			if err := listener.SetDeadline(time.Now().Add(quietWait)); err != nil {
				t.Fatalf("setting the socket's deadline: %v", err)
			}
			connection, err := listener.Accept()
			if err == nil {
				_ = connection.Close()
				t.Fatal("the socket NOTIFY_SOCKET names was connected to; want nothing sent on Windows")
			}
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("waiting on the socket: %v", err)
			}
		})
	})
}
