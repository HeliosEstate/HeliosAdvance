// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The caller's socket call the standard library has none for: TCP urgent data received
// (Winsock's MSG_OOB), to show none was sent.
package telnets_test

import (
	"context"
	"net"
	"syscall"
	"time"
)

// Winsock's values, which the syscall package does not name.
const (
	messageOutOfBand = 0x1
	// socketAtMark is SIOCATMARK: with urgent data kept out of line, it reports false while an
	// urgent byte waits.
	socketAtMark = 0x40047307
)

// receiveUrgent takes the urgent byte waiting on the connection, out of band, once SIOCATMARK
// says one waits, checking again every 5 ms until then or until the deadline passes, the
// check-again the no-sleep rule allows: a receive of urgent data with none waiting would block,
// and Winsock announces urgent data only through select, which the standard library lacks.
func receiveUrgent(ctx context.Context, connection *net.TCPConn, deadline time.Time) ([]byte, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return nil, err
	}
	for {
		var atMark [4]byte
		var returned uint32
		var ioctlErr error
		if err := raw.Control(func(handle uintptr) {
			ioctlErr = syscall.WSAIoctl(syscall.Handle(handle), socketAtMark, nil, 0, &atMark[0], uint32(len(atMark)), &returned, nil, 0)
		}); err != nil {
			return nil, err
		}
		if ioctlErr != nil {
			return nil, ioctlErr
		}
		if atMark == [4]byte{} {
			break
		}
		if !time.Now().Before(deadline) {
			return nil, errNoUrgentData
		}
		wait(ctx, time.Now().Add(5*time.Millisecond))
	}
	var data [16]byte
	var got uint32
	var receiveErr error
	if err := raw.Control(func(handle uintptr) {
		buffer := syscall.WSABuf{Len: uint32(len(data)), Buf: &data[0]}
		flags := uint32(messageOutOfBand)
		receiveErr = syscall.WSARecv(syscall.Handle(handle), &buffer, 1, &got, &flags, nil, nil)
	}); err != nil {
		return nil, err
	}
	return data[:got], receiveErr
}
