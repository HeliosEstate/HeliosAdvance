// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The approved tests for issue #113, written by the QA session from the issue's two lines.
// "The far end sends nothing" is the far end here: a line that never answers, or the real rx
// whose answers stop reaching us after its first acknowledgement. The tries are counted on
// the line: what we wrote, and how long we waited.
package transfer_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/transfer"
)

// quietLine is a far end that sends nothing: reads wait until the test ends; what we write is
// kept so the tries can be counted.
type quietLine struct {
	stop    chan struct{}
	mutex   sync.Mutex
	written bytes.Buffer
}

func newQuietLine(t *testing.T) *quietLine {
	t.Helper()
	quiet := &quietLine{stop: make(chan struct{})}
	t.Cleanup(func() { close(quiet.stop) })
	return quiet
}

func (quiet *quietLine) Read([]byte) (int, error) {
	<-quiet.stop
	return 0, io.EOF
}

func (quiet *quietLine) Write(buffer []byte) (int, error) {
	quiet.mutex.Lock()
	defer quiet.mutex.Unlock()
	return quiet.written.Write(buffer)
}

func (quiet *quietLine) Close() error { return nil }

func (quiet *quietLine) count(pattern []byte) int {
	quiet.mutex.Lock()
	defer quiet.mutex.Unlock()
	return bytes.Count(quiet.written.Bytes(), pattern)
}

// goesQuiet passes the far end's bytes until the first acknowledgement (ACK), then passes
// nothing more: the far end has gone quiet from our side. What we write is kept.
type goesQuiet struct {
	far     *line
	stop    chan struct{}
	mutex   sync.Mutex
	quiet   bool
	written bytes.Buffer
}

func (going *goesQuiet) Read(buffer []byte) (int, error) {
	going.mutex.Lock()
	quiet := going.quiet
	going.mutex.Unlock()
	if quiet {
		<-going.stop
		return 0, io.EOF
	}
	n, err := going.far.Read(buffer[:1]) // one byte at a time, so nothing past the ACK slips through
	if n == 1 && buffer[0] == 0x06 {
		going.mutex.Lock()
		going.quiet = true
		going.mutex.Unlock()
	}
	return n, err
}

func (going *goesQuiet) Write(buffer []byte) (int, error) {
	going.mutex.Lock()
	going.written.Write(buffer)
	going.mutex.Unlock()
	return going.far.Write(buffer)
}

func (going *goesQuiet) Close() error { return going.far.Close() }

const retryTimeout = 200 * time.Millisecond

// mustTimeOutAfter fails unless err is ErrTimeout and elapsed covers tries timeouts and not
// another one; the far end's silence is the only thing that ends the wait.
func mustTimeOutAfter(t *testing.T, err error, elapsed time.Duration, tries int, timeout time.Duration) {
	t.Helper()
	if !errors.Is(err, transfer.ErrTimeout) {
		t.Fatalf("gave up with %v, want ErrTimeout", err)
	}
	if low, high := time.Duration(tries)*timeout, time.Duration(tries+1)*timeout; elapsed < low || elapsed >= high {
		t.Fatalf("gave up after %v, want %d timeouts of %v: from %v up to %v", elapsed.Round(time.Millisecond), tries, timeout, low, high)
	}
}

func TestRetriesXYMODEM(t *testing.T) {
	t.Parallel()
	t.Run("If the far end sends nothing, then an XMODEM or YMODEM sender or receiver shall try ten times before it gives up with ErrTimeout.", func(t *testing.T) {
		t.Parallel()
		receivers := []struct {
			name string
			opt  transfer.Options
		}{
			{"an XMODEM receiver opens ten times", transfer.Options{Protocol: transfer.XMODEM, Name: "quiet.bin", Timeout: retryTimeout}},
			{"a YMODEM receiver opens ten times", transfer.Options{Protocol: transfer.YMODEM, Timeout: retryTimeout}},
		}
		for _, row := range receivers {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				quiet := newQuietLine(t)
				start := time.Now()
				_, err := transfer.Receive(t.Context(), quiet, t.TempDir(), row.opt)
				mustTimeOutAfter(t, err, time.Since(start), 10, retryTimeout)
				if opened := quiet.count([]byte("C")); opened != 10 {
					t.Fatalf("opened %d times with C, want 10", opened)
				}
			})
		}
		senders := []struct {
			name string
			opt  transfer.Options
		}{
			{"an XMODEM sender waits ten times for the receiver to open", transfer.Options{Protocol: transfer.XMODEM, Timeout: retryTimeout}},
			{"a YMODEM sender waits ten times for the receiver to open", transfer.Options{Protocol: transfer.YMODEM, Timeout: retryTimeout}},
		}
		for _, row := range senders {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				src := filepath.Join(t.TempDir(), "quiet.bin")
				if err := os.WriteFile(src, make([]byte, 3000), 0o600); err != nil {
					t.Fatal(err)
				}
				start := time.Now()
				err := transfer.Send(t.Context(), newQuietLine(t), []string{src}, row.opt)
				mustTimeOutAfter(t, err, time.Since(start), 10, retryTimeout)
			})
		}
		t.Run("an XMODEM sender sends a block ten times when rx goes quiet after acknowledging the first", func(t *testing.T) {
			t.Parallel()
			ours, far := t.TempDir(), t.TempDir()
			src := filepath.Join(ours, "quiet.bin")
			// Zeros, so a block's start (SOH, its number, the number's complement) cannot
			// appear inside the data and be counted as a try.
			if err := os.WriteFile(src, make([]byte, 3000), 0o600); err != nil {
				t.Fatal(err)
			}
			farEnd, _ := oracle(t, far, "rx", "-c", "-b", "quiet.bin")
			stop := make(chan struct{})
			t.Cleanup(func() { close(stop) })
			going := &goesQuiet{far: farEnd, stop: stop}
			err := transfer.Send(t.Context(), going, []string{src}, transfer.Options{Protocol: transfer.XMODEM, SubpacketSize: 128, Timeout: retryTimeout})
			if !errors.Is(err, transfer.ErrTimeout) {
				t.Fatalf("gave up with %v, want ErrTimeout", err)
			}
			going.mutex.Lock()
			sent := bytes.Count(going.written.Bytes(), []byte{0x01, 0x02, 0xFD})
			going.mutex.Unlock()
			if sent != 10 {
				t.Fatalf("sent block 2 %d times, want 10", sent)
			}
		})
	})
}

func TestRetriesZMODEM(t *testing.T) {
	t.Parallel()
	t.Run("If the far end sends nothing, then the ZMODEM receiver shall send ZRINIT four times, once at each timeout, before it gives up with ErrTimeout.", func(t *testing.T) {
		t.Parallel()
		rows := []struct {
			name    string
			timeout time.Duration // zero: the default, ten seconds
			zrinits int
		}{
			{"at the default timeout, four ZRINITs over 40 seconds", 0, 4},
			{"at a two-second timeout, four ZRINITs over eight seconds", 2 * time.Second, 4},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				quiet := newQuietLine(t)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				start := time.Now()
				_, err := transfer.Receive(ctx, quiet, t.TempDir(), transfer.Options{Timeout: row.timeout})
				timeout := row.timeout
				if timeout == 0 {
					timeout = 10 * time.Second
				}
				mustTimeOutAfter(t, err, time.Since(start), row.zrinits, timeout)
				// A ZRINIT is a hex header of type 01: ZPAD ZPAD ZDLE B, then "01".
				if sent := quiet.count([]byte("**\x18B01")); sent != row.zrinits {
					t.Fatalf("sent ZRINIT %d times, want %d", sent, row.zrinits)
				}
			})
		}
	})
}
