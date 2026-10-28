// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The caller's socket calls the standard library has none for: urgent data sent, received and kept
// in line, and a receive buffer set before the connection opens.
package listener_test

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

// smallWindow sets a socket's receive buffer to 4096 bytes before it connects, so the window it
// offers stays small.
func smallWindow(_, _ string, raw syscall.RawConn) error {
	var setErr error
	err := raw.Control(func(descriptor uintptr) {
		setErr = syscall.SetsockoptInt(syscall.Handle(descriptor), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096)
	})
	if err != nil {
		return err
	}
	return setErr
}

// Winsock's values, which the syscall package does not name.
const (
	winsockMessageOutOfBand = 0x1
	socketOOBInline         = 0x0100
	// socketAtMark is SIOCATMARK: with urgent data kept out of line, it reports false while an
	// urgent byte waits.
	socketAtMark = 0x40047307
)

func sendUrgent(connection *net.TCPConn, value byte) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	var sendErr error
	err = raw.Write(func(descriptor uintptr) bool {
		data := [1]byte{value}
		buffer := syscall.WSABuf{Len: 1, Buf: &data[0]}
		var sent uint32
		sendErr = syscall.WSASend(syscall.Handle(descriptor), &buffer, 1, &sent, winsockMessageOutOfBand, nil, nil)
		return true
	})
	if err != nil {
		return err
	}
	return sendErr
}

// keepUrgentInLine sets SO_OOBINLINE on the caller's own end, for the rows whose caller never
// reads its urgent data: Windows resets a connection whose receiver keeps urgent data out of line
// and lets it pile up (about 17 Synchs, on Windows 11, 2026-10-26).
func keepUrgentInLine(t *testing.T, connection *net.TCPConn) {
	t.Helper()
	raw, err := connection.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var setErr error
	if err := raw.Control(func(handle uintptr) {
		setErr = syscall.SetsockoptInt(syscall.Handle(handle), syscall.SOL_SOCKET, socketOOBInline, 1)
	}); err != nil || setErr != nil {
		t.Fatalf("keeping the caller's urgent data in line: %v, %v", err, setErr)
	}
}

// receiveUrgent takes the urgent byte waiting on the connection, out of band, once SIOCATMARK
// says one waits, polling until then or until the deadline passes: a receive of urgent data
// with none waiting would block.
func receiveUrgent(t *testing.T, connection *net.TCPConn, deadline time.Time) ([]byte, error) {
	t.Helper()
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
			return nil, errors.New("no urgent data by the deadline")
		}
		wait(t, time.Now().Add(5*time.Millisecond))
	}
	var data [16]byte
	var got uint32
	var receiveErr error
	if err := raw.Control(func(handle uintptr) {
		buffer := syscall.WSABuf{Len: uint32(len(data)), Buf: &data[0]}
		flags := uint32(winsockMessageOutOfBand)
		receiveErr = syscall.WSARecv(syscall.Handle(handle), &buffer, 1, &got, &flags, nil, nil)
	}); err != nil {
		return nil, err
	}
	return data[:got], receiveErr
}
