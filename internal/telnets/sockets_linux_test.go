// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The caller's socket call the standard library has none for: TCP urgent data received
// (MSG_OOB), to show none was sent.
package telnets_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

// receiveUrgent takes the urgent byte waiting on the connection, out of band, checking again
// every 5 ms until it has come or the deadline passes, the check-again the no-sleep rule allows:
// the system announces urgent data only through select or poll, which the standard library
// offers here only with a limit on descriptors or not at all.
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
			return nil, fmt.Errorf("%w: %w", errNoUrgentData, receiveErr)
		}
		wait(ctx, time.Now().Add(5*time.Millisecond))
	}
}
