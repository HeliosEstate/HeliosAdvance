// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests of Wake over a real loopback connection: which deadlines it sets, in which order and to
// what time, what a read and a write on the connection then do, and what it returns when the
// connection refuses a deadline.
package timeup_test

import (
	"errors"
	"net"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/timeup"
)

var (
	errReadRefused  = errors.New("the row refuses the read deadline")
	errWriteRefused = errors.New("the row refuses the write deadline")
)

// wakeCase is one kind of connection Wake is called on, and what the connection answers.
type wakeCase struct {
	name      string
	failRead  error
	failWrite error
	closed    bool
}

var wakeCases = []wakeCase{
	{name: "a working connection"},
	{name: "a connection refusing the read deadline", failRead: errReadRefused},
	{name: "a connection refusing the write deadline", failWrite: errWriteRefused},
	{name: "a connection refusing both", failRead: errReadRefused, failWrite: errWriteRefused},
	{name: "a closed connection", closed: true},
}

func (row wakeCase) conn(t *testing.T) *watchedConn {
	t.Helper()
	conn := newWatched(t)
	conn.failRead, conn.failWrite = row.failRead, row.failWrite
	if row.closed {
		_ = conn.real.Close()
	}
	return conn
}

// expectWokenSides fails unless a read and a write on the real connection end in
// os.ErrDeadlineExceeded at once, as a deadline that has passed makes them; read only when its
// deadline was set.
func expectWokenSides(t *testing.T, real net.Conn, read bool) {
	t.Helper()
	if read {
		var buffer [1]byte
		if _, err := real.Read(buffer[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("a read after Wake returned %v, want os.ErrDeadlineExceeded", err)
		}
	}
	if _, err := real.Write([]byte("x")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a write after Wake returned %v, want os.ErrDeadlineExceeded", err)
	}
}

func TestWake(t *testing.T) {
	t.Parallel()

	t.Run("Wake shall set conn's read deadline and then its write deadline to the same fixed time long past, setting the write deadline even when setting the read deadline fails.", func(t *testing.T) {
		t.Parallel()
		for _, row := range wakeCases {
			t.Run(row.name+": the read and then the write deadline, at one time a day or more past", func(t *testing.T) {
				t.Parallel()
				conn := row.conn(t)
				before := time.Now()
				_ = timeup.Wake(conn)
				journal := conn.entries()
				if len(journal) == 0 {
					t.Fatal("Wake set no deadline")
				}
				expectWoken(t, journal, journal[0].deadline)
				if !journal[0].deadline.Before(before.Add(-longPast)) {
					t.Fatalf("Wake set %v, want a time at least %v before %v", journal[0].deadline, longPast, before)
				}
				if row.failWrite == nil && !row.closed {
					expectWokenSides(t, conn.real, row.failRead == nil)
				}
			})
		}
		t.Run("two connections, and a second Wake on the first: the same time each time", func(t *testing.T) {
			t.Parallel()
			first, second := newWatched(t), newWatched(t)
			for _, conn := range []*watchedConn{first, second, first} {
				if err := timeup.Wake(conn); err != nil {
					t.Fatalf("Wake on a working connection returned %v", err)
				}
			}
			journal := append(first.entries(), second.entries()...)
			if len(journal) != 6 {
				t.Fatalf("three Wakes set %s, want six deadlines", described(journal))
			}
			for _, each := range journal {
				if each.deadline != journal[0].deadline {
					t.Fatalf("the Wakes set %s, want one time throughout", described(journal))
				}
			}
		})
	})

	t.Run("Wake shall never set the zero time, which clears a deadline instead of waking a call.", func(t *testing.T) {
		t.Parallel()
		for _, row := range wakeCases {
			t.Run(row.name+": neither deadline zero", func(t *testing.T) {
				t.Parallel()
				conn := row.conn(t)
				_ = timeup.Wake(conn)
				journal := conn.entries()
				if len(journal) != 2 {
					t.Fatalf("Wake set %s, want a read and a write deadline", described(journal))
				}
				for _, each := range journal {
					if each.deadline.IsZero() {
						t.Fatalf("Wake set the %s deadline to the zero time", each.what)
					}
				}
			})
		}
		t.Run("a read already waiting on a working connection: it returns os.ErrDeadlineExceeded", func(t *testing.T) {
			t.Parallel()
			conn := newWatched(t)
			returned := make(chan error, 1)
			go func() {
				var buffer [1]byte
				_, err := conn.real.Read(buffer[:])
				returned <- err
			}()
			if err := timeup.Wake(conn); err != nil {
				t.Fatalf("Wake on a working connection returned %v", err)
			}
			select {
			case err := <-returned:
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("the waiting read returned %v, want os.ErrDeadlineExceeded", err)
				}
			case <-time.After(eventLimit):
				t.Fatalf("the waiting read had not returned %v after Wake", eventLimit)
			}
		})
	})

	t.Run("Wake shall return nil when both are set, and otherwise each failure, joined with errors.Join.", func(t *testing.T) {
		t.Parallel()
		t.Run("a working connection: nil", func(t *testing.T) {
			t.Parallel()
			if err := timeup.Wake(newWatched(t)); err != nil {
				t.Fatalf("Wake returned %v, want nil", err)
			}
		})
		for _, row := range wakeCases[1:] {
			t.Run(row.name+": errors.Join of each failure the connection gave, and nothing else", func(t *testing.T) {
				t.Parallel()
				conn := row.conn(t)
				err := timeup.Wake(conn)
				var failures []error
				for _, each := range conn.entries() {
					if each.err != nil {
						failures = append(failures, each.err)
					}
				}
				if row.closed && (len(failures) != 2 || !errors.Is(failures[0], net.ErrClosed) || !errors.Is(failures[1], net.ErrClosed)) {
					t.Fatalf("the closed connection gave %v, want net.ErrClosed for both deadlines: a fault in the row", failures)
				}
				joined, ok := errorsOf(err)
				if !ok {
					t.Fatalf("Wake returned %#v, want errors.Join's own result", err)
				}
				if len(joined) != len(failures) {
					t.Fatalf("Wake joined %v, want exactly %v", joined, failures)
				}
				for _, failure := range failures {
					if !slices.ContainsFunc(joined, func(each error) bool { return each == failure }) { //nolint:errorlint // the failure itself, as the connection gave it
						t.Fatalf("Wake joined %v, want exactly %v", joined, failures)
					}
				}
			})
		}
	})
}
