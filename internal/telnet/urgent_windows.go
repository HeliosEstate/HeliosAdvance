// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package telnet

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// socketOOBInline is Winsock's SO_OOBINLINE, which the syscall package does not name.
const socketOOBInline = 0x0100

func setUrgentInLine(descriptor uintptr) error {
	return syscall.SetsockoptInt(syscall.Handle(descriptor), syscall.SOL_SOCKET, socketOOBInline, 1)
}

// maxWaitMilliseconds is the longest single wait, compared before the conversion to the API's
// unsigned 32 bits so that nothing can overflow it; a longer wait goes round the loop.
const maxWaitMilliseconds = 1 << 30

// errCompletionUnknown is a send whose completion could not be learned: its struct and event are
// kept for the life of the process, since the kernel may still write to them.
var errCompletionUnknown = errors.New(
	"telnet: an urgent send whose completion cannot be known was kept")

// urgentSend is one urgent byte's overlapped send. The OVERLAPPED, the WSABuf and the byte are
// fields of one heap object, pinned from before the send is submitted until it has completed, so
// the kernel never writes to memory Go has moved or reused. The Pinner is a field of the same
// object because a Pinner collected while it holds a pin stops the process.
type urgentSend struct {
	overlapped windows.Overlapped
	buffer     windows.WSABuf
	value      byte
	pinner     runtime.Pinner
	// event is the handle CreateEvent returned; only overlapped.HEvent carries the low-order bit.
	event windows.Handle
}

var (
	keptMutex sync.Mutex
	// keptSends are sends whose completion could not be known, kept so that nothing frees what the
	// kernel may still write to. At most one for each accepted connection.
	keptSends []*urgentSend
)

// urgentState is what the connection keeps for its urgent sends: the write deadline, which Go's
// poller cannot apply to a send it does not run, and the event that wakes a waiting send.
type urgentState struct {
	mutex    sync.Mutex
	deadline time.Time
	// wake is the waiting send's wake event, zero while none waits.
	wake windows.Handle
}

func (state *urgentState) writeDeadline() time.Time {
	state.mutex.Lock()
	defer state.mutex.Unlock()
	return state.deadline
}

func (state *urgentState) setWake(wake windows.Handle) {
	state.mutex.Lock()
	state.wake = wake
	state.mutex.Unlock()
}

// SetWriteDeadline records the deadline before it wakes a waiting urgent send, so that the send,
// which resets the event and then reads the deadline, never misses one set while it waits. The
// forward runs whatever the wake returns: on a connection already closing it fails, and the wait
// must still wake.
func (connection *acceptedConn) SetWriteDeadline(deadline time.Time) error {
	state := &connection.urgentState
	state.mutex.Lock()
	state.deadline = deadline
	var wakeErr error
	if state.wake != 0 {
		wakeErr = windows.SetEvent(state.wake)
	}
	state.mutex.Unlock()
	return errors.Join(connection.TCPConn.SetWriteDeadline(deadline), wakeErr)
}

// write runs the whole send inside one RawConn.Write callback, under Go's write lock,
// which also holds a reference to the socket: the listener's Close waits for the callback, so the
// handle stays valid for every call made on it. The callback always returns true, since Go's
// Windows RawWrite fails at once on false.
func (state *urgentState) write(connection *net.TCPConn, value byte) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	var sendErr error
	err = raw.Write(func(handle uintptr) bool {
		sendErr = state.sendUrgent(windows.Handle(handle), value)
		return true
	})
	if err != nil {
		return err
	}
	return sendErr
}

func (state *urgentState) sendUrgent(socket windows.Handle, value byte) error {
	if deadline := state.writeDeadline(); !deadline.IsZero() && !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	send, err := newUrgentSend(value)
	if err != nil {
		return err
	}
	wake, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return errors.Join(err, send.release())
	}
	state.setWake(wake)

	known, sendErr := state.transmit(socket, send, wake)

	// Nothing the kernel holds names the wake event, and only SetWriteDeadline reaches it, so it
	// is cleared from the connection and closed on every way out, the kept send's included.
	state.setWake(0)
	closeErr := windows.CloseHandle(wake)
	if !known {
		keptMutex.Lock()
		keptSends = append(keptSends, send)
		keptMutex.Unlock()
		return errors.Join(sendErr, closeErr)
	}
	return errors.Join(sendErr, closeErr, send.release())
}

func newUrgentSend(value byte) (*urgentSend, error) {
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	send := new(urgentSend)
	send.value = value
	send.buffer = windows.WSABuf{Len: 1, Buf: &send.value}
	send.event = event
	// The low-order bit keeps this completion off the completion port the socket is tied to: Go's
	// poller reads every packet's OVERLAPPED as one of its own operations.
	send.overlapped.HEvent = event | 1
	send.pinner.Pin(send)
	return send, nil
}

// release is for a send that has completed, or never started.
func (send *urgentSend) release() error {
	send.pinner.Unpin()
	return windows.CloseHandle(send.event)
}

// transmit submits the send and waits for it. Its first result is false when the send's completion
// cannot be known, in which case the caller keeps the send.
func (state *urgentState) transmit(
	socket windows.Handle, send *urgentSend, wake windows.Handle,
) (bool, error) {
	err := windows.WSASend(socket, &send.buffer, 1, nil, windows.MSG_OOB, &send.overlapped, nil)
	if err == nil {
		return true, send.result(socket, false)
	}
	if !errors.Is(err, windows.ERROR_IO_PENDING) {
		return true, err
	}
	var stop error
	for {
		completed, cause := state.waitOnce(send, wake)
		if completed {
			return true, send.result(socket, false)
		}
		if cause != nil {
			stop = cause
			break
		}
	}
	return state.cancel(socket, send, stop)
}

// waitOnce waits for the send's event or the wake event, for the time left to the deadline. It
// resets the wake event and then reads the deadline, the order that loses no deadline set while
// it waits. A non-nil cause means the send must be cancelled.
func (state *urgentState) waitOnce(
	send *urgentSend, wake windows.Handle,
) (completed bool, cause error) {
	if err := windows.ResetEvent(wake); err != nil {
		return false, err
	}
	milliseconds := uint32(windows.INFINITE)
	if deadline := state.writeDeadline(); !deadline.IsZero() {
		left := time.Until(deadline)
		if left <= 0 {
			return false, os.ErrDeadlineExceeded
		}
		milliseconds = waitMilliseconds(left)
	}
	event, err := windows.WaitForMultipleObjects(
		[]windows.Handle{send.event, wake}, false, milliseconds)
	if err != nil {
		return false, err
	}
	return event == windows.WAIT_OBJECT_0, nil
}

// waitMilliseconds rounds up, so a wait never ends before its deadline, and returns no more than
// maxWaitMilliseconds.
func waitMilliseconds(left time.Duration) uint32 {
	rounded := (left + time.Millisecond - 1) / time.Millisecond
	if rounded > 0 && rounded < maxWaitMilliseconds {
		return uint32(rounded)
	}
	return maxWaitMilliseconds
}

// cancel cancels the send alone, never every operation on the socket, and waits for the cancel to
// complete, as Go's poller does. A deadline that passed is the write's own error unless the send
// got its byte out first. Its first result is false when the send's completion cannot be known.
func (state *urgentState) cancel(
	socket windows.Handle, send *urgentSend, stop error,
) (bool, error) {
	if err := windows.CancelIoEx(socket, &send.overlapped); err != nil &&
		!errors.Is(err, windows.ERROR_NOT_FOUND) {
		return false, fmt.Errorf("%w: the cancel failed: %w", errCompletionUnknown, err)
	}
	event, err := windows.WaitForSingleObject(send.event, windows.INFINITE)
	if err == nil && event != windows.WAIT_OBJECT_0 {
		err = fmt.Errorf("the wait returned %d", event)
	}
	if err != nil {
		return false, fmt.Errorf("%w: the wait after the cancel failed: %w", errCompletionUnknown, err)
	}
	if errors.Is(stop, os.ErrDeadlineExceeded) {
		return true, send.result(socket, true)
	}
	return true, stop
}

// result reads the completed send's outcome without waiting, since it is not documented how a
// waiting call treats the bit set on hEvent. A byte the result counts as sent is sent.
func (send *urgentSend) result(socket windows.Handle, cancelled bool) error {
	var transferred, flags uint32
	err := windows.WSAGetOverlappedResult(socket, &send.overlapped, &transferred, false, &flags)
	if err == nil || transferred == 1 {
		return nil
	}
	if cancelled && errors.Is(err, windows.ERROR_OPERATION_ABORTED) {
		return os.ErrDeadlineExceeded
	}
	return err
}
