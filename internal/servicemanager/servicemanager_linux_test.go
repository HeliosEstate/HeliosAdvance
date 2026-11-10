// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package servicemanager_test

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/servicemanager"
)

const (
	// quietWait is how long a row waits for a datagram that must not come. The child has ended
	// before the row reads, and a datagram on a local socket is queued as it is sent, so anything
	// it sent is already there: the wait is generous, and on a slow machine still not proof of
	// absence.
	quietWait = 500 * time.Millisecond
	// mostDatagram bounds one read: READY=1 is 7 bytes, and anything longer is read whole enough
	// to show.
	mostDatagram = 256
	// mostSocketPath is the longest path a local socket's address holds on Linux.
	mostSocketPath = 107
	// ready is the message the line names, as its bytes.
	ready = "READY=1"
)

func TestLinuxStartedByWindowsServiceManager(t *testing.T) {
	t.Parallel()
	t.Run("On Linux, StartedByWindowsServiceManager shall return false and no error.", func(t *testing.T) {
		t.Parallel()
		started, err := servicemanager.StartedByWindowsServiceManager()
		if started || err != nil {
			t.Fatalf("StartedByWindowsServiceManager returned %t, %v; want false and no error", started, err)
		}
	})
}

func TestLinuxRunWindowsService(t *testing.T) {
	t.Parallel()
	t.Run("On Linux, RunWindowsService shall return ErrServiceManagerConnect without calling run.", func(t *testing.T) {
		t.Parallel()
		runs := 0
		_, err := servicemanager.RunWindowsService(func(context.Context, servicemanager.Ready) int {
			runs++
			return 0
		})
		if !errors.Is(err, servicemanager.ErrServiceManagerConnect) {
			t.Errorf("RunWindowsService returned %v; want ErrServiceManagerConnect", err)
		}
		if runs != 0 {
			t.Errorf("run was called %d times; want none", runs)
		}
	})
}

func TestLinuxNotifySystemdReady(t *testing.T) {
	t.Parallel()
	if calls, isChild := notifyChildCalls(t); isChild {
		sendAsChild(calls)
		return
	}
	const testName = "TestLinuxNotifySystemdReady"
	t.Run(`When NOTIFY_SOCKET names a socket by a path starting with "/", or by an abstract name starting with "@", NotifySystemdReady's first call shall send it READY=1, as one datagram.`, func(t *testing.T) {
		t.Parallel()
		t.Run("a path", func(t *testing.T) {
			t.Parallel()
			path := socketPath(t, "notify.sock")
			socket := listenDatagram(t, path)
			runNotifyChild(t, testName, notifySocket{set: true, value: path}, "", 1)
			expectDatagrams(t, socket, ready)
		})
		t.Run("an abstract name", func(t *testing.T) {
			t.Parallel()
			name := "@hadv-qa-notify-" + rand.Text()
			socket := listenDatagram(t, name)
			runNotifyChild(t, testName, notifySocket{set: true, value: name}, "", 1)
			expectDatagrams(t, socket, ready)
		})
	})
	t.Run("NotifySystemdReady shall send nothing when NOTIFY_SOCKET is unset, empty or names anything else, on Windows, or on any call but the first.", func(t *testing.T) {
		t.Parallel()
		// Each row whose child must send nothing then runs a control child with the socket's
		// path, which must send READY=1 there: a row that ends on a silence alone would pass
		// against code that sends nothing at all.
		t.Run("NOTIFY_SOCKET unset", func(t *testing.T) {
			t.Parallel()
			path := socketPath(t, "notify.sock")
			socket := listenDatagram(t, path)
			runNotifyChild(t, testName, notifySocket{}, "", 1)
			expectDatagrams(t, socket)
			runNotifyChild(t, testName, notifySocket{set: true, value: path}, "", 1)
			expectDatagrams(t, socket, ready)
		})
		t.Run("NOTIFY_SOCKET empty", func(t *testing.T) {
			t.Parallel()
			path := socketPath(t, "notify.sock")
			socket := listenDatagram(t, path)
			runNotifyChild(t, testName, notifySocket{set: true}, "", 1)
			expectDatagrams(t, socket)
			runNotifyChild(t, testName, notifySocket{set: true, value: path}, "", 1)
			expectDatagrams(t, socket, ready)
		})
		t.Run("NOTIFY_SOCKET a relative name, with a socket of that name in the child's working folder", func(t *testing.T) {
			t.Parallel()
			path := socketPath(t, "notify.sock")
			socket := listenDatagram(t, path)
			runNotifyChild(t, testName, notifySocket{set: true, value: "notify.sock"}, filepath.Dir(path), 1)
			expectDatagrams(t, socket)
			runNotifyChild(t, testName, notifySocket{set: true, value: path}, "", 1)
			expectDatagrams(t, socket, ready)
		})
		t.Run("three calls with a path: the second and third send nothing", func(t *testing.T) {
			t.Parallel()
			path := socketPath(t, "notify.sock")
			socket := listenDatagram(t, path)
			runNotifyChild(t, testName, notifySocket{set: true, value: path}, "", 3)
			expectDatagrams(t, socket, ready)
		})
	})
}

// socketPath names a socket in a folder of its own, short enough for a socket's address: a
// subtest's own folder carries its whole name, which is longer.
func socketPath(t *testing.T, name string) string {
	t.Helper()
	folder, err := os.MkdirTemp("", "n") //nolint:usetesting // the subtest's folder is too long for a socket's address
	if err != nil {
		t.Fatalf("making the socket's folder: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(folder); err != nil {
			t.Errorf("removing the socket's folder: %v", err)
		}
	})
	path := filepath.Join(folder, name)
	if len(path) > mostSocketPath {
		t.Fatalf("the socket's path %s is longer than a socket's address holds (%d bytes)", path, mostSocketPath)
	}
	return path
}

// listenDatagram binds a datagram socket at a path, or at an abstract name starting with "@".
func listenDatagram(t *testing.T, name string) *net.UnixConn {
	t.Helper()
	socket, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		t.Fatalf("binding a datagram socket at %s: %v", name, err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	return socket
}

// expectDatagrams reads every datagram the socket holds, until none comes for quietWait, and
// checks they are exactly those wanted, in order, each whole.
func expectDatagrams(t *testing.T, socket *net.UnixConn, want ...string) {
	t.Helper()
	var got []string
	buffer := make([]byte, mostDatagram)
	for {
		if err := socket.SetReadDeadline(time.Now().Add(quietWait)); err != nil {
			t.Fatalf("setting the socket's read deadline: %v", err)
		}
		count, _, err := socket.ReadFromUnix(buffer)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			break
		}
		if err != nil {
			t.Fatalf("reading the socket: %v", err)
		}
		got = append(got, string(buffer[:count]))
	}
	if len(got) != len(want) {
		t.Fatalf("the socket received %q; want %q", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("the socket received %q; want %q", got, want)
		}
	}
}
