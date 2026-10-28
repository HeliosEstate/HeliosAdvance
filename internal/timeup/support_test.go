// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// What the rows watch with: a Conn over a real loopback connection that keeps a journal of each
// deadline set on it, and the goroutines a row started, told apart from every other row's by a
// label, since every row runs in parallel.
package timeup_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/timeup"
)

// eventLimit is how long a row waits for an event that a correct build gives at once. Reaching
// it fails the row as a hang; no row reads how soon within it the event came.
const eventLimit = 10 * time.Second

// longPast is how far before the clock a woken deadline must lie: far enough that no step of the
// clock brings it back into the future.
const longPast = 24 * time.Hour

// The names a journal gives its entries: the two deadlines, and a release's own mark.
const (
	readDeadline  = "read"
	writeDeadline = "write"
	releasedMark  = "released"
)

// entry is one deadline set on a watchedConn, or a mark a row adds to the same journal so the
// order of the two can be read.
type entry struct {
	what      string
	deadline  time.Time
	goroutine int64
	err       error
}

// watchedConn is a Conn over the engine's side of a real loopback connection. It passes each
// deadline through, unless failRead or failWrite stands in for the connection's answer, and when
// holdRead or holdWrite is set it waits for that channel to close before acting.
type watchedConn struct {
	real      net.Conn
	failRead  error
	failWrite error
	holdRead  chan struct{}
	holdWrite chan struct{}

	readEntered  chan struct{}
	writeEntered chan struct{}
	writeSet     chan struct{}
	enterRead    sync.Once
	enterWrite   sync.Once
	setWrite     sync.Once

	mutex   sync.Mutex
	journal []entry
}

// newWatched opens a loopback connection and returns a watchedConn on the engine's side of it.
func newWatched(t *testing.T) *watchedConn {
	t.Helper()
	listening, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listening.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		engine, acceptErr := listening.Accept()
		if acceptErr != nil {
			close(accepted)
			return
		}
		accepted <- engine
	}()
	caller, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", listening.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = caller.Close() })
	engine, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = engine.Close() })
	return &watchedConn{
		real:         engine,
		readEntered:  make(chan struct{}),
		writeEntered: make(chan struct{}),
		writeSet:     make(chan struct{}),
	}
}

// hold makes the named deadline wait until the row lets it go; it is let go at the row's end too,
// so a failed row leaves no wake waiting.
func (conn *watchedConn) hold(t *testing.T, what string) func() {
	t.Helper()
	gate := make(chan struct{})
	switch what {
	case readDeadline:
		conn.holdRead = gate
	case writeDeadline:
		conn.holdWrite = gate
	default:
		t.Fatalf("hold: no deadline %q", what)
	}
	var once sync.Once
	letGo := func() { once.Do(func() { close(gate) }) }
	t.Cleanup(letGo)
	return letGo
}

func (conn *watchedConn) SetReadDeadline(deadline time.Time) error {
	conn.enterRead.Do(func() { close(conn.readEntered) })
	if conn.holdRead != nil {
		<-conn.holdRead
	}
	err := conn.failRead
	if err == nil {
		err = conn.real.SetReadDeadline(deadline)
	}
	conn.add(entry{what: readDeadline, deadline: deadline, goroutine: goroutineID(), err: err})
	return err
}

func (conn *watchedConn) SetWriteDeadline(deadline time.Time) error {
	conn.enterWrite.Do(func() { close(conn.writeEntered) })
	if conn.holdWrite != nil {
		<-conn.holdWrite
	}
	err := conn.failWrite
	if err == nil {
		err = conn.real.SetWriteDeadline(deadline)
	}
	conn.add(entry{what: writeDeadline, deadline: deadline, goroutine: goroutineID(), err: err})
	conn.setWrite.Do(func() { close(conn.writeSet) })
	return err
}

func (conn *watchedConn) add(added entry) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	conn.journal = append(conn.journal, added)
}

// mark adds the row's own event to the journal, after every deadline set before it.
func (conn *watchedConn) mark(what string) {
	conn.add(entry{what: what, goroutine: goroutineID()})
}

func (conn *watchedConn) entries() []entry {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	return append([]entry(nil), conn.journal...)
}

// described is a journal as a row reports it.
func described(journal []entry) string {
	parts := make([]string, 0, len(journal))
	for _, each := range journal {
		parts = append(parts, fmt.Sprintf("%s %v on goroutine %d (%v)", each.what, each.deadline, each.goroutine, each.err))
	}
	return "[" + strings.Join(parts, "; ") + "]"
}

// goroutineID is the number the runtime gives the calling goroutine in its stack trace, or -1
// when the trace cannot be read, which no row accepts.
func goroutineID() int64 {
	var buffer [64]byte
	text := strings.TrimPrefix(string(buffer[:runtime.Stack(buffer[:], false)]), "goroutine ")
	number, _, _ := strings.Cut(text, " ")
	id, err := strconv.ParseInt(number, 10, 64)
	if err != nil {
		return -1
	}
	return id
}

// wokenTime is the time Wake itself sets, read from a Wake on a connection of the row's own.
func wokenTime(t *testing.T) time.Time {
	t.Helper()
	conn := newWatched(t)
	if err := timeup.Wake(conn); err != nil {
		t.Fatalf("Wake on a working connection returned %v", err)
	}
	journal := conn.entries()
	if len(journal) != 2 {
		t.Fatalf("Wake on a working connection set %s, want a read and a write deadline", described(journal))
	}
	return journal[0].deadline
}

// expectWoken fails unless journal is exactly a read deadline and then a write deadline, both at
// woken, each set on a goroutine that is none of notOn.
func expectWoken(t *testing.T, journal []entry, woken time.Time, notOn ...int64) {
	t.Helper()
	if len(journal) != 2 || journal[0].what != readDeadline || journal[1].what != writeDeadline ||
		!journal[0].deadline.Equal(woken) || !journal[1].deadline.Equal(woken) {
		t.Fatalf("the connection has %s, want the read and then the write deadline at %v, once each", described(journal), woken)
	}
	for _, each := range journal {
		if each.goroutine <= 0 {
			t.Fatalf("the %s deadline was set on a goroutine whose number cannot be read", each.what)
		}
		for _, other := range notOn {
			if each.goroutine == other {
				t.Fatalf("the %s deadline was set on goroutine %d, which is the row's own", each.what, other)
			}
		}
	}
}

// waitFor fails the row unless the channel closes within eventLimit.
func waitFor(t *testing.T, event <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(eventLimit):
		t.Fatalf("%s did not happen within %v", what, eventLimit)
	}
}

// rowCount makes each row's label its own.
var rowCount atomic.Int64

// labelled runs work on the row's goroutine under a label of the row's own, which every goroutine
// started there inherits, the goroutine a cancel made there starts included. It returns the
// label, a new one when label is empty.
func labelled(ctx context.Context, label string, work func()) string {
	if label == "" {
		label = "row-" + strconv.FormatInt(rowCount.Add(1), 10)
	}
	pprof.Do(ctx, pprof.Labels("row", label), func(context.Context) { work() })
	return label
}

// countLabelled is how many goroutines carry label, read from the runtime's goroutine profile.
func countLabelled(t *testing.T, label string) int {
	t.Helper()
	var profile bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&profile, 1); err != nil {
		t.Fatalf("the goroutine profile: %v", err)
	}
	want := fmt.Sprintf("# labels: {%q:%q}", "row", label)
	count := 0
	for block := range strings.SplitSeq(profile.String(), "\n\n") {
		lines := strings.Split(block, "\n")
		found := false
		for _, line := range lines {
			if strings.TrimSpace(line) == want {
				found = true
			}
		}
		if !found {
			continue
		}
		first := lines[0]
		if strings.HasPrefix(first, "goroutine profile:") && len(lines) > 1 {
			first = lines[1]
		}
		number, _, _ := strings.Cut(first, " @ ")
		value, err := strconv.Atoi(number)
		if err != nil {
			t.Fatalf("the goroutine profile has a record that does not start with its count: %q", first)
		}
		count += value
	}
	return count
}

// waitNoneLabelled waits until no goroutine carries label: by then every wake the row's own
// goroutine started, or began by a cancel, has run to its end.
func waitNoneLabelled(t *testing.T, label string) {
	t.Helper()
	until := time.Now().Add(eventLimit)
	for countLabelled(t, label) != 0 {
		if time.Now().After(until) {
			t.Fatalf("goroutines the row started were still there after %v", eventLimit)
		}
		runtime.Gosched()
	}
}

// waitParked waits until goroutine id is waiting inside the timeup package, and reports true, or
// until returned closes first, and reports false.
func waitParked(t *testing.T, id int64, returned <-chan struct{}) bool {
	t.Helper()
	header := "goroutine " + strconv.FormatInt(id, 10) + " ["
	until := time.Now().Add(eventLimit)
	for {
		select {
		case <-returned:
			return false
		default:
		}
		for block := range strings.SplitSeq(allStacks(), "\n\n") {
			if !strings.HasPrefix(block, header) {
				continue
			}
			status, _, _ := strings.Cut(strings.TrimPrefix(block, header), "]")
			status, _, _ = strings.Cut(status, ",")
			if status != "running" && status != "runnable" && status != "syscall" &&
				strings.Contains(block, "heliosadvance/internal/timeup.") {
				return true
			}
		}
		if time.Now().After(until) {
			t.Fatalf("goroutine %d neither waited in the timeup package nor returned within %v", id, eventLimit)
		}
		runtime.Gosched()
	}
}

// allStacks is every goroutine's stack trace, in a buffer grown until it holds them all.
func allStacks() string {
	buffer := make([]byte, 1<<16)
	for {
		written := runtime.Stack(buffer, true)
		if written < len(buffer) {
			return string(buffer[:written])
		}
		buffer = make([]byte, 2*len(buffer))
	}
}

// errorsOf is what err joins, when err is itself the join: errors.Join's own result, never one
// wrapped further.
func errorsOf(err error) ([]error, bool) {
	var joined interface{ Unwrap() []error }
	if !errors.As(err, &joined) || any(joined) != any(err) {
		return nil, false
	}
	return joined.Unwrap(), true
}
