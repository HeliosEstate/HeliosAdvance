// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The caller's socket calls the standard library has none for: a receive buffer set before the
// connection opens, and TCP urgent data sent and received (MSG_OOB).
package telnet_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"
)

// smallWindow sets a socket's receive buffer to 4096 bytes before it connects, so the window it
// offers stays small: set after, Linux keeps honouring the larger window it already offered, and
// a caller that never reads lets the engine's writes creep on.
func smallWindow(_, _ string, raw syscall.RawConn) error {
	var setErr error
	err := raw.Control(func(descriptor uintptr) {
		setErr = syscall.SetsockoptInt(int(descriptor), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096)
	})
	if err != nil {
		return err
	}
	return setErr
}

// keepUrgentInLine sets SO_OOBINLINE on the caller's own end, for the rows whose caller never
// reads its urgent data, so it stays in the stream like any other byte.
func keepUrgentInLine(t *testing.T, connection *net.TCPConn) {
	t.Helper()
	raw, err := connection.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var setErr error
	if err := raw.Control(func(descriptor uintptr) {
		setErr = syscall.SetsockoptInt(int(descriptor), syscall.SOL_SOCKET, syscall.SO_OOBINLINE, 1)
	}); err != nil || setErr != nil {
		t.Fatalf("keeping the caller's urgent data in line: %v, %v", err, setErr)
	}
}

// sendUrgent writes data with its last byte as TCP urgent data. A send that would wait hands
// back to Go's poller, so the connection's write deadline still wakes it.
func sendUrgent(connection *net.TCPConn, data []byte) (int, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var sendErr error
	err = raw.Write(func(descriptor uintptr) bool {
		sendErr = syscall.Sendto(int(descriptor), data, syscall.MSG_OOB|syscall.MSG_DONTWAIT, nil)
		return !errors.Is(sendErr, syscall.EAGAIN)
	})
	if err != nil {
		return 0, err
	}
	if sendErr != nil {
		return 0, sendErr
	}
	return len(data), nil
}

// receiveUrgent takes the urgent byte waiting on the connection, out of band, checking again
// every 5 ms until it has come or the deadline passes, the check-again the no-sleep rule allows:
// the system announces urgent data only through select or poll, which the standard library
// offers here only with a limit on descriptors or not at all. Linux keeps the byte only until a
// read passes the mark, so it is taken as soon as the bytes before it are read; under load it
// was never missed between checks.
func receiveUrgent(ctx context.Context, connection *net.TCPConn, deadline time.Time) ([]byte, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return nil, err
	}
	buffer := make([]byte, 16)
	for {
		var got int
		var receiveErr error
		if err := raw.Control(func(descriptor uintptr) {
			got, _, receiveErr = syscall.Recvfrom(int(descriptor), buffer, syscall.MSG_OOB|syscall.MSG_DONTWAIT)
		}); err != nil {
			return nil, err
		}
		if receiveErr == nil {
			return buffer[:got], nil
		}
		if !errors.Is(receiveErr, syscall.EAGAIN) && !errors.Is(receiveErr, syscall.EINVAL) {
			return nil, receiveErr
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("no urgent data by the deadline: %w", receiveErr)
		}
		wait(ctx, time.Now().Add(5*time.Millisecond))
	}
}
