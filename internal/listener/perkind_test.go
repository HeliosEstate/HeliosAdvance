// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// A Listener per kind of connection: the count every Listener of one engine shares, and each
// Listener's own New, Start and Stop, driven through the contract's names with the scripted
// Telnet caller and Opens written here, on sockets each row opens for itself.
package listener_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/listener"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// lingerFor is how long a lingering Open or Close goes on after its context ends: far longer
// than a Stop that waits for nothing takes to return, so that one is told at every run.
const lingerFor = 300 * time.Millisecond

// keptAfter is how long after the ceiling row's caller is accepted its kept places are taken:
// longer than its probes take, so they end before any kept place reaches its own ceiling.
const keptAfter = 5 * time.Second

// errRefusedByTest is what the Opens written here return when they serve no call.
var errRefusedByTest = errors.New("the test's Open serves no call")

// kindListener is one Listener a row made, with the addresses of its sockets.
type kindListener struct {
	engine    *listener.Listener
	addresses []string
}

// makeListener opens the given number of listening sockets on 127.0.0.1 and makes a Listener
// from them, not yet started, counted in count; it is stopped when the test ends.
func makeListener(t *testing.T, sockets int, open listener.Open, count *listener.ConnectionCount) kindListener {
	t.Helper()
	var listening []*net.TCPListener
	var addresses []string
	for range sockets {
		opened, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listening on loopback: %v", err)
		}
		socket, isTCP := opened.(*net.TCPListener)
		if !isTCP {
			t.Fatalf("the listening socket is a %T", opened)
		}
		listening = append(listening, socket)
		addresses = append(addresses, socket.Addr().String())
	}
	engine, err := listener.New(listening, open, count)
	if err != nil {
		for _, socket := range listening {
			_ = socket.Close()
		}
		t.Fatalf("New refused: %v", err)
	}
	t.Cleanup(engine.Stop)
	return kindListener{engine: engine, addresses: addresses}
}

// startedListener is makeListener, then Start, which must return by progressLimit, so a Start
// that waits fails its row rather than hanging the test program.
func startedListener(t *testing.T, sockets int, open listener.Open, count *listener.ConnectionCount) kindListener {
	t.Helper()
	made := makeListener(t, sockets, open, count)
	started := make(chan struct{})
	go func() {
		defer close(started)
		made.engine.Start()
	}()
	awaitSignal(t, "Start returning", started)
	return made
}

// countingOpen counts its calls, then is Telnet's.
type countingOpen struct {
	calls atomic.Int64
}

func (counting *countingOpen) open(ctx context.Context, connection *net.TCPConn) (listener.KindConnection, error) {
	counting.calls.Add(1)
	return openTelnet(ctx, connection)
}

func (counting *countingOpen) expectCalls(t *testing.T, want int64) {
	t.Helper()
	if got := counting.calls.Load(); got != want {
		t.Fatalf("the Listener's Open ran %d times, want %d", got, want)
	}
}

// heldStage is an Open, or a KindConnection's Close, that goes on after its context ends: it
// says when it began and when the context ended, then waits until the row lets it go or, with
// linger set, for linger on its own, and says when it returned.
type heldStage struct {
	linger   time.Duration
	begun    chan struct{}
	ended    chan struct{}
	release  chan struct{}
	returned atomic.Bool
	once     sync.Once
	endOnce  sync.Once
	goOnce   sync.Once
}

func newHeldStage(linger time.Duration) *heldStage {
	return &heldStage{linger: linger, begun: make(chan struct{}), ended: make(chan struct{}), release: make(chan struct{})}
}

// letGo lets the held stage return; a second call does nothing. A row that lets its stage go
// also registers letGo as a cleanup after making every Listener of the row, so that it runs
// before any of their Stops, and a row that fails first never leaves a Stop waiting on it.
func (held *heldStage) letGo() {
	held.goOnce.Do(func() { close(held.release) })
}

func (held *heldStage) hold(ctx context.Context) {
	held.once.Do(func() { close(held.begun) })
	<-ctx.Done()
	held.endOnce.Do(func() { close(held.ended) })
	if held.linger > 0 {
		timer := time.NewTimer(held.linger)
		defer timer.Stop()
		<-timer.C
	} else {
		<-held.release
	}
	held.returned.Store(true)
}

// open is the held stage as an Open: it serves no call.
func (held *heldStage) open(ctx context.Context, _ *net.TCPConn) (listener.KindConnection, error) {
	held.hold(ctx)
	return nil, errRefusedByTest
}

// openHeldClose is Telnet's Open whose KindConnection's Close is the held stage.
func (held *heldStage) openHeldClose(ctx context.Context, connection *net.TCPConn) (listener.KindConnection, error) {
	kindConnection, err := openTelnet(ctx, connection)
	if err != nil {
		return nil, err
	}
	return heldClose{KindConnection: kindConnection, held: held}, nil
}

type heldClose struct {
	listener.KindConnection
	held *heldStage
}

func (closing heldClose) Close(ctx context.Context) error {
	closing.held.hold(ctx)
	return ctx.Err()
}

// awaitSignal waits for a stage's signal, which must come by progressLimit.
func awaitSignal(t *testing.T, what string, signal <-chan struct{}) {
	t.Helper()
	timer := time.NewTimer(progressLimit)
	defer timer.Stop()
	select {
	case <-signal:
	case <-timer.C:
		t.Fatalf("%s had not happened after %v", what, progressLimit)
	}
}

// stopInBackground calls Stop on its own goroutine and returns a channel closed when it returns.
func stopInBackground(engine *listener.Listener) <-chan struct{} {
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		engine.Stop()
	}()
	return stopped
}

// expectStopped checks a Stop already called returns by progressLimit.
func expectStopped(t *testing.T, what string, stopped <-chan struct{}) {
	t.Helper()
	awaitSignal(t, what+"'s Stop returning", stopped)
}

// holdSilently dials count silent callers at the address and reads every one's opening by one
// progressLimit from the last dial, so each holds a place.
func holdSilently(t *testing.T, address string, count int) []caller {
	t.Helper()
	callers := make([]caller, count)
	for index := range callers {
		callers[index] = dial(t, address)
	}
	deadline := time.Now().Add(progressLimit)
	for _, call := range callers {
		call.readOpening(t, deadline)
	}
	return callers
}

// expectServed checks a new caller at the address is served now.
func expectServed(t *testing.T, address string) caller {
	t.Helper()
	isServed, call, _ := served(t, address)
	if !isServed {
		t.Fatalf("a caller at %s was closed at once, want it served", address)
	}
	return call
}

// expectQuiet checks nothing reaches the caller for quietFor.
func expectQuiet(t *testing.T, call caller) {
	t.Helper()
	_ = call.connection.SetReadDeadline(time.Now().Add(quietFor))
	received := make([]byte, 1)
	got, err := call.connection.Read(received)
	if got != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a caller before its Listener's Start got % x and %v, want nothing", received[:got], err)
	}
	_ = call.connection.SetReadDeadline(time.Time{})
}

// expectDialRefused checks the system refuses a connection to the address: nothing listens there.
func expectDialRefused(t *testing.T, address string) {
	t.Helper()
	dialer := &net.Dialer{Timeout: progressLimit}
	opened, err := dialer.DialContext(t.Context(), "tcp", address)
	if err == nil {
		_ = opened.Close()
		t.Fatalf("a dial to %s connected, want it refused", address)
	}
	var errno syscall.Errno
	// 10061 is Windows's WSAECONNREFUSED.
	if !errors.As(err, &errno) || (errno != syscall.ECONNREFUSED && errno != 10061) {
		t.Fatalf("a dial to %s failed with %v, want it refused", address, err)
	}
}

// expectEnded reads the caller's connection until it ends, which must happen by progressLimit.
func expectEnded(t *testing.T, call caller) {
	t.Helper()
	_ = call.connection.SetReadDeadline(time.Now().Add(progressLimit))
	_, err := io.Copy(io.Discard, call.connection)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the caller's connection had not ended after %v", progressLimit)
	}
	if err != nil && !isReset(err) {
		t.Fatalf("the caller's connection ended other than by a close: %v", err)
	}
}

// atPrompt is a caller that answered and waits at the prompt, recorded from its connect.
func atPrompt(t *testing.T, address string) (caller, *recording) {
	t.Helper()
	call := dial(t, address)
	stream := call.record(call.connected.Add(nameLimit))
	call.send(t, answers)
	stream.expectReceived(t, join(opening, asked))
	return call, stream
}

// expectReceived checks the caller has received exactly these bytes by progressLimit, so a row
// that sets up a caller at a stage of its call reaches that stage, and not a stream that ended.
func (stream *recording) expectReceived(t *testing.T, want []byte) {
	t.Helper()
	got := stream.waitFor(t, len(want), time.Now().Add(progressLimit))
	if !slices.Equal(got, want) {
		t.Fatalf("the caller got\n% x\nwant\n% x", got, want)
	}
}

// expectHello types the name at the prompt and checks the whole call to the shutdown.
func expectHello(t *testing.T, call caller, stream *recording) {
	t.Helper()
	call.send(t, []byte("n\r"))
	_ = call.connection.SetReadDeadline(time.Now().Add(progressLimit))
	stream.expectStream(t, join(opening, asked, echoed("n")))
}

// silentStream is a silent caller, recorded from its connect.
func silentStream(t *testing.T, address string) *recording {
	t.Helper()
	call := dial(t, address)
	return call.record(call.connected.Add(negotiationLimit + progressLimit))
}

// expectAsked checks a silent caller got the opening, then the greeting and the prompt.
func (stream *recording) expectAsked(t *testing.T) {
	t.Helper()
	want := join(opening, asked)
	got := stream.waitFor(t, len(want), time.Now().Add(negotiationLimit+progressLimit))
	if !slices.Equal(got, want) {
		t.Fatalf("a silent caller got\n% x\nwant\n% x", got, want)
	}
}

// fillAcross holds the given number of silent callers at each address.
func fillAcross(t *testing.T, addresses []string, counts []int) {
	t.Helper()
	for index, address := range addresses {
		holdSilently(t, address, counts[index])
	}
}

// pathCall is one way a kept connection ends. It dials one caller at the address, and reports
// whether the Listener kept it; when it did, the call has ended by its path.
type pathCall func(t *testing.T, address string) bool

// throughTelnet is a path on Telnet's Open: kept when the opening arrives, then run to its end.
func throughTelnet(finish func(t *testing.T, call caller, stream *recording)) pathCall {
	return func(t *testing.T, address string) bool {
		t.Helper()
		call := dial(t, address)
		stream := call.record(call.connected.Add(nameLimit + progressLimit))
		got := stream.waitFor(t, len(opening), call.connected.Add(testrun.Patient(wideMargin)))
		if len(got) == 0 {
			<-stream.done
			if errors.Is(stream.end, io.EOF) || isReset(stream.end) {
				return false
			}
			t.Fatalf("a caller was neither served nor closed at once: %v", stream.end)
		}
		finish(t, call, stream)
		return true
	}
}

// throughOpen is a path on an Open written here: kept when the Open ran for it.
func throughOpen(open *countingOpen, deadline time.Duration) pathCall {
	return func(t *testing.T, address string) bool {
		t.Helper()
		before := open.calls.Load()
		call := dial(t, address)
		_ = call.connection.SetReadDeadline(call.connected.Add(deadline))
		received, err := io.ReadAll(call.connection)
		if len(received) != 0 || (err != nil && !isReset(err)) {
			t.Fatalf("a caller whose Open serves no call got % x and %v, want a close with nothing written", received, err)
		}
		return open.calls.Load() > before
	}
}

// keptPath runs the path until the Listener has kept one caller, which must happen by
// progressLimit: a caller over the cap, while the last path's place is still being freed, is
// tried again.
func keptPath(t *testing.T, address string, path pathCall) {
	t.Helper()
	deadline := time.Now().Add(progressLimit)
	for !path(t, address) {
		if time.Now().After(deadline) {
			t.Fatalf("no caller was kept by the path's Listener after %v: its place was never freed", progressLimit)
		}
		wait(t, time.Now().Add(20*time.Millisecond))
	}
}

// keepingOpen holds every place it is given until the row ends, past the name's 60 seconds and
// the ceiling's 70, which would end a Telnet caller held as long: it waits for the row's end,
// not its context's, so the shared execution path keeps the place while it runs.
type keepingOpen struct {
	calls  atomic.Int64
	rowEnd chan struct{}
}

// keepPlaces makes a Listener on count whose Open keeps its places, and holds the given number
// of them, each one's Open seen running.
func keepPlaces(t *testing.T, count *listener.ConnectionCount, places int) {
	t.Helper()
	keeping := &keepingOpen{rowEnd: make(chan struct{})}
	made := startedListener(t, 1, func(_ context.Context, _ *net.TCPConn) (listener.KindConnection, error) {
		keeping.calls.Add(1)
		<-keeping.rowEnd
		return nil, errRefusedByTest
	}, count)
	// Registered after the Listener's Stop, so it runs first.
	t.Cleanup(func() { close(keeping.rowEnd) })
	for range places {
		dial(t, made.addresses[0])
	}
	deadline := time.Now().Add(progressLimit)
	for keeping.calls.Load() < int64(places) {
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d kept places were taken after %v", keeping.calls.Load(), places, progressLimit)
		}
		wait(t, time.Now().Add(5*time.Millisecond))
	}
}

// expectFreedOnce checks, with 99 places kept, that a place came back for one caller at the
// address and for no more.
func expectFreedOnce(t *testing.T, address string) {
	t.Helper()
	expectServedBy(t, address, time.Now().Add(wideMargin))
	expectRefused(t, address)
}

func TestListenerPerKind(t *testing.T) {
	t.Parallel()
	t.Run("The listener package shall keep open, across every Listener made with one ConnectionCount, at most ConnectionCap connections at once.", func(t *testing.T) {
		t.Parallel()
		t.Run("51 silent callers at one Listener and 49 at another, one count: the next at each closed at once", func(t *testing.T) {
			t.Parallel()
			count := listener.NewCount()
			first := startedListener(t, 1, openTelnet, count)
			second := startedListener(t, 1, openTelnet, count)
			fillAcross(t, []string{first.addresses[0], second.addresses[0]}, []int{51, 49})
			expectRefused(t, first.addresses[0])
			expectRefused(t, second.addresses[0])
		})
		t.Run("34, 33 and 33 at three Listeners, one count: the next at each closed at once", func(t *testing.T) {
			t.Parallel()
			count := listener.NewCount()
			var addresses []string
			for range 3 {
				addresses = append(addresses, startedListener(t, 1, openTelnet, count).addresses[0])
			}
			fillAcross(t, addresses, []int{34, 33, 33})
			for _, address := range addresses {
				expectRefused(t, address)
			}
		})
		t.Run("99 across two Listeners, one count: the hundredth served at the second, then the next at each closed at once", func(t *testing.T) {
			t.Parallel()
			count := listener.NewCount()
			first := startedListener(t, 1, openTelnet, count)
			second := startedListener(t, 1, openTelnet, count)
			fillAcross(t, []string{first.addresses[0], second.addresses[0]}, []int{50, 49})
			expectServed(t, second.addresses[0])
			expectRefused(t, first.addresses[0])
			expectRefused(t, second.addresses[0])
		})
		t.Run("two hundred callers at once, a hundred at each of two Listeners, one count: exactly a hundred served", func(t *testing.T) {
			t.Parallel()
			count := listener.NewCount()
			addresses := []string{startedListener(t, 1, openTelnet, count).addresses[0], startedListener(t, 1, openTelnet, count).addresses[0]}
			var mutex sync.Mutex
			outcomes := map[string]int{}
			var calling sync.WaitGroup
			for index := range 2 * connectionCap {
				calling.Go(func() {
					outcome := callOnce(t, addresses[index%2])
					mutex.Lock()
					outcomes[outcome]++
					mutex.Unlock()
				})
			}
			calling.Wait()
			if outcomes["served"] != connectionCap || outcomes["refused"] != connectionCap {
				t.Fatalf("of two hundred callers at once: %v", outcomes)
			}
		})
	})

	t.Run("When a Listener accepts a connection while its ConnectionCount already holds ConnectionCap open connections, the listener package shall close that connection at once without writing to it.", func(t *testing.T) {
		t.Parallel()
		t.Run("a hundred silent callers at one Listener: a caller at another on the count closed at once, its Open never run, until one of the hundred leaves", func(t *testing.T) {
			t.Parallel()
			count := listener.NewCount()
			full := startedListener(t, 1, openTelnet, count)
			counting := &countingOpen{}
			other := startedListener(t, 1, counting.open, count)
			callers := holdSilently(t, full.addresses[0], connectionCap)
			expectRefused(t, other.addresses[0])
			expectRefused(t, other.addresses[0])
			counting.expectCalls(t, 0)
			leaving := callers[len(callers)-1]
			_ = leaving.connection.Close()
			expectServedBy(t, other.addresses[0], windowEnd(t, time.Now(), leaving.dialed.Add(negotiationLimit)))
			counting.expectCalls(t, 1)
		})
		t.Run("a hundred callers at the prompt at one Listener: a caller at another on the count closed at once, its Open never run", func(t *testing.T) {
			t.Parallel()
			count := listener.NewCount()
			full := startedListener(t, 1, openTelnet, count)
			counting := &countingOpen{}
			other := startedListener(t, 1, counting.open, count)
			fillAtPrompt(t, full.addresses[0])
			expectRefused(t, other.addresses[0])
			counting.expectCalls(t, 0)
		})
	})

	t.Run("When a connection a Listener kept closes, by any path, the listener package shall free its place in the ConnectionCount.", func(t *testing.T) {
		t.Parallel()
		answered := throughTelnet(func(t *testing.T, call caller, stream *recording) {
			t.Helper()
			call.send(t, answers)
			stream.expectReceived(t, join(opening, asked))
			expectHello(t, call, stream)
			_ = call.connection.Close()
		})
		leftMidName := throughTelnet(func(t *testing.T, call caller, stream *recording) {
			t.Helper()
			call.send(t, answers)
			stream.expectReceived(t, join(opening, asked))
			call.send(t, []byte("n"))
			// The echo of the one character, before the name has ended.
			stream.expectReceived(t, join(opening, asked, []byte("n")))
			_ = call.connection.Close()
		})
		noName := throughTelnet(func(t *testing.T, call caller, stream *recording) {
			t.Helper()
			call.send(t, answers)
			stream.expectStream(t, join(opening, asked))
		})
		openFails := &countingOpen{}
		failing := func(_ context.Context, _ *net.TCPConn) (listener.KindConnection, error) {
			openFails.calls.Add(1)
			return nil, errRefusedByTest
		}
		openGivesNil := &countingOpen{}
		givingNil := func(_ context.Context, _ *net.TCPConn) (listener.KindConnection, error) {
			openGivesNil.calls.Add(1)
			return nil, nil
		}
		rows := []struct {
			name  string
			open  listener.Open
			path  pathCall
			times int
		}{
			{"the call answered, then the caller's close, three times", openTelnet, answered, 3},
			{"the caller's close mid-name, three times", openTelnet, leftMidName, 3},
			{"Open returning an error, three times", failing, throughOpen(openFails, progressLimit), 3},
			{"Open returning a nil KindConnection and no error, three times", givingNil, throughOpen(openGivesNil, progressLimit), 3},
			{"NoName at 60 seconds, once", openTelnet, noName, 1},
		}
		for _, row := range rows {
			t.Run(row.name+": with 99 places kept at another Listener on the count, one place back at a third, and no more", func(t *testing.T) {
				t.Parallel()
				count := listener.NewCount()
				probe := startedListener(t, 1, openTelnet, count)
				ending := startedListener(t, 1, row.open, count)
				keepPlaces(t, count, connectionCap-1)
				for range row.times {
					keptPath(t, ending.addresses[0], row.path)
				}
				expectFreedOnce(t, probe.addresses[0])
			})
		}
		t.Run("the ceiling at 70 seconds, with Open still running, once: with 99 places kept at another Listener on the count, one place back at a third, and no more", func(t *testing.T) {
			t.Parallel()
			count := listener.NewCount()
			probe := startedListener(t, 1, openTelnet, count)
			holding := &countingOpen{}
			ending := startedListener(t, 1, func(ctx context.Context, _ *net.TCPConn) (listener.KindConnection, error) {
				holding.calls.Add(1)
				<-ctx.Done()
				return nil, errRefusedByTest
			}, count)
			call := dial(t, ending.addresses[0])
			deadline := time.Now().Add(progressLimit)
			for holding.calls.Load() == 0 {
				if time.Now().After(deadline) {
					t.Fatalf("the caller's Open had not run after %v", progressLimit)
				}
				wait(t, time.Now().Add(5*time.Millisecond))
			}
			// The kept places are taken a few seconds after this caller's accept, so that their
			// own ceilings come after the probes: a place may be freed when its connection
			// closes or when the work on it returns, and the line does not say which.
			wait(t, call.connected.Add(keptAfter))
			kept := time.Now()
			keepPlaces(t, count, connectionCap-1)
			_ = call.connection.SetReadDeadline(call.dialed.Add(ceilingLimit + progressLimit))
			received, err := io.ReadAll(call.connection)
			if len(received) != 0 || (err != nil && !isReset(err)) {
				t.Fatalf("a caller whose Open serves no call got % x and %v, want a close at the ceiling with nothing written", received, err)
			}
			expectFreedOnce(t, probe.addresses[0])
			if !time.Now().Before(kept.Add(ceilingLimit - early)) {
				if testrun.Race {
					t.Logf("under the race detector, timing is not judged: the probes ended %v after the kept places could reach their own ceiling", time.Since(kept.Add(ceilingLimit-early)))
				} else {
					t.Fatalf("test fault: the probes ended %v after the kept places could reach their own ceiling", time.Since(kept.Add(ceilingLimit-early)))
				}
			}
		})
		t.Run("its Listener's Stop, once: with 99 places kept at another Listener on the count, one place back at a third, and no more", func(t *testing.T) {
			t.Parallel()
			count := listener.NewCount()
			probe := startedListener(t, 1, openTelnet, count)
			ending := startedListener(t, 1, openTelnet, count)
			keepPlaces(t, count, connectionCap-1)
			call := dial(t, ending.addresses[0])
			call.readOpening(t, call.connected.Add(progressLimit))
			ending.engine.Stop()
			expectEnded(t, call)
			expectFreedOnce(t, probe.addresses[0])
		})
	})

	t.Run("The listener package shall count only in the ConnectionCount New was given: Listeners made with different ConnectionCounts shall not count each other's connections.", func(t *testing.T) {
		t.Parallel()
		t.Run("a hundred at a Listener on one count: a hundred more served at one on another, then the next at each closed at once", func(t *testing.T) {
			t.Parallel()
			first := startedListener(t, 1, openTelnet, listener.NewCount())
			second := startedListener(t, 1, openTelnet, listener.NewCount())
			holdSilently(t, first.addresses[0], connectionCap)
			holdSilently(t, second.addresses[0], connectionCap)
			expectRefused(t, first.addresses[0])
			expectRefused(t, second.addresses[0])
		})
		t.Run("both full, one of the first's callers leaves: the first serves one more, the second still closes its next", func(t *testing.T) {
			t.Parallel()
			first := startedListener(t, 1, openTelnet, listener.NewCount())
			second := startedListener(t, 1, openTelnet, listener.NewCount())
			callers := holdSilently(t, first.addresses[0], connectionCap)
			holdSilently(t, second.addresses[0], connectionCap)
			leaving := callers[len(callers)-1]
			_ = leaving.connection.Close()
			expectServedBy(t, first.addresses[0], windowEnd(t, time.Now(), leaving.dialed.Add(negotiationLimit)))
			expectRefused(t, second.addresses[0])
			expectRefused(t, first.addresses[0])
		})
	})

	t.Run("New shall serve no caller, at any of the sockets it was given, before Start: no Open runs and nothing is written.", func(t *testing.T) {
		t.Parallel()
		t.Run("a caller at each of two sockets before Start: nothing, and no Open; after Start, a new caller at each served", func(t *testing.T) {
			t.Parallel()
			counting := &countingOpen{}
			made := makeListener(t, 2, counting.open, listener.NewCount())
			for _, address := range made.addresses {
				expectQuiet(t, dial(t, address))
			}
			counting.expectCalls(t, 0)
			made.engine.Start()
			for _, address := range made.addresses {
				expectServed(t, address)
			}
		})
		t.Run("a caller at each of two sockets, then Stop before Start: nothing reaches either, no Open has run, and the sockets refuse a dial", func(t *testing.T) {
			t.Parallel()
			counting := &countingOpen{}
			made := makeListener(t, 2, counting.open, listener.NewCount())
			var waiting []caller
			for _, address := range made.addresses {
				call := dial(t, address)
				expectQuiet(t, call)
				waiting = append(waiting, call)
			}
			made.engine.Stop()
			counting.expectCalls(t, 0)
			for _, call := range waiting {
				_ = call.connection.SetReadDeadline(time.Now().Add(quietFor))
				// How the queued caller's connection ends is the system's, not pinned: only
				// that nothing reaches it.
				received, err := io.ReadAll(call.connection)
				if len(received) != 0 {
					t.Fatalf("a caller queued before Start got % x, then %v, want nothing", received, err)
				}
			}
			for _, address := range made.addresses {
				expectDialRefused(t, address)
			}
		})
	})

	t.Run("Start shall return at once, without waiting for a caller.", func(t *testing.T) {
		t.Parallel()
		t.Run("no caller yet, two sockets: Start returns, then a caller at each is served", func(t *testing.T) {
			t.Parallel()
			made := makeListener(t, 2, openTelnet, listener.NewCount())
			started := make(chan struct{})
			go func() {
				defer close(started)
				made.engine.Start()
			}()
			awaitSignal(t, "Start returning with no caller", started)
			for _, address := range made.addresses {
				expectServed(t, address)
			}
		})
	})

	t.Run("Start shall start only this Listener: a Listener not yet started shall serve no caller after another's Start, and one already started shall go on accepting and serving.", func(t *testing.T) {
		t.Parallel()
		for _, shared := range []bool{true, false} {
			counts := "one count"
			if !shared {
				counts = "two counts"
			}
			t.Run(fmt.Sprintf("%s: after one Listener's Start, a caller at the other gets nothing and no Open runs there, while the first serves; then the other's Start serves", counts), func(t *testing.T) {
				t.Parallel()
				count := listener.NewCount()
				first := makeListener(t, 1, openTelnet, count)
				if !shared {
					count = listener.NewCount()
				}
				counting := &countingOpen{}
				second := makeListener(t, 1, counting.open, count)
				first.engine.Start()
				expectQuiet(t, dial(t, second.addresses[0]))
				counting.expectCalls(t, 0)
				expectServed(t, first.addresses[0])
				second.engine.Start()
				expectServed(t, second.addresses[0])
			})
		}
		t.Run("one started with a caller at the prompt and one silent: the other's Start; the first's callers served on, Hello and the shutdown, the greeting and the prompt, and its next served", func(t *testing.T) {
			t.Parallel()
			count := listener.NewCount()
			first := startedListener(t, 1, openTelnet, count)
			second := makeListener(t, 1, openTelnet, count)
			call, stream := atPrompt(t, first.addresses[0])
			silent := silentStream(t, first.addresses[0])
			second.engine.Start()
			expectHello(t, call, stream)
			silent.expectAsked(t)
			expectServed(t, first.addresses[0])
			expectServed(t, second.addresses[0])
		})
	})

	t.Run("Once Start has returned, this Listener shall accept at every one of its sockets.", func(t *testing.T) {
		t.Parallel()
		for _, sockets := range []int{1, 3} {
			t.Run(fmt.Sprintf("%d sockets: a caller at each, dialed as Start returns, served", sockets), func(t *testing.T) {
				t.Parallel()
				made := startedListener(t, sockets, openTelnet, listener.NewCount())
				for _, address := range made.addresses {
					expectServed(t, address)
				}
			})
		}
		t.Run("two Listeners of two sockets each on one count, both started: a caller at each of the four served", func(t *testing.T) {
			t.Parallel()
			count := listener.NewCount()
			first := startedListener(t, 2, openTelnet, count)
			second := startedListener(t, 2, openTelnet, count)
			for _, address := range slices.Concat(first.addresses, second.addresses) {
				expectServed(t, address)
			}
		})
	})

	t.Run("Start after Stop shall accept nothing: a stopped Listener stays stopped, and its kind is started again by a new Listener on new sockets.", func(t *testing.T) {
		t.Parallel()
		t.Run("New, Start, Stop, Start: each socket refuses a dial", func(t *testing.T) {
			t.Parallel()
			made := startedListener(t, 2, openTelnet, listener.NewCount())
			made.engine.Stop()
			made.engine.Start()
			for _, address := range made.addresses {
				expectDialRefused(t, address)
			}
		})
		t.Run("New, Stop, Start: each socket refuses a dial, and no Open has run", func(t *testing.T) {
			t.Parallel()
			counting := &countingOpen{}
			made := makeListener(t, 2, counting.open, listener.NewCount())
			made.engine.Stop()
			made.engine.Start()
			for _, address := range made.addresses {
				expectDialRefused(t, address)
			}
			counting.expectCalls(t, 0)
		})
		t.Run("a hundred held, Stop, then a new Listener on new sockets and the same count, started: a hundred served there, the next closed at once", func(t *testing.T) {
			t.Parallel()
			count := listener.NewCount()
			stopped := startedListener(t, 1, openTelnet, count)
			holdSilently(t, stopped.addresses[0], connectionCap)
			stopped.engine.Stop()
			again := startedListener(t, 1, openTelnet, count)
			holdSilently(t, again.addresses[0], connectionCap)
			expectRefused(t, again.addresses[0])
		})
	})

	t.Run("Stop shall close this Listener's listening sockets and every connection it kept, and return only when nothing of this Listener's is running and every place its connections held in the ConnectionCount is free.", func(t *testing.T) {
		t.Parallel()
		t.Run("a hundred callers, silent, at the prompt and in Close's wait: once Stop returns each has ended, the socket refuses a dial, and a hundred are served at another Listener on the count, the next closed", func(t *testing.T) {
			t.Parallel()
			count := listener.NewCount()
			stopping := startedListener(t, 1, openTelnet, count)
			other := startedListener(t, 1, openTelnet, count)
			silent := holdSilently(t, stopping.addresses[0], connectionCap-2)
			prompted, _ := atPrompt(t, stopping.addresses[0])
			closing := dial(t, stopping.addresses[0])
			closingStream := closing.record(closing.connected.Add(progressLimit))
			closing.send(t, join(answers, []byte("n\r")))
			// End of stream is the shutdown: the closing caller is now in Close's wait.
			closingStream.expectStream(t, join(opening, asked, echoed("n")))
			stopping.engine.Stop()
			closing.awaitReset(t, time.Now().Add(progressLimit))
			expectEnded(t, prompted)
			for _, call := range silent {
				expectEnded(t, call)
			}
			expectDialRefused(t, stopping.addresses[0])
			holdSilently(t, other.addresses[0], connectionCap)
			expectRefused(t, other.addresses[0])
		})
		stages := []struct {
			name string
			open func(*heldStage) listener.Open
			// reach brings one caller to the held stage.
			reach func(t *testing.T, address string)
		}{
			{
				"an Open going on 300 ms after its context ends",
				func(held *heldStage) listener.Open { return held.open },
				func(t *testing.T, address string) { t.Helper(); dial(t, address) },
			},
			{
				"a Close going on 300 ms after its context ends",
				func(held *heldStage) listener.Open { return held.openHeldClose },
				func(t *testing.T, address string) {
					t.Helper()
					call, stream := atPrompt(t, address)
					call.send(t, []byte("n\r"))
					stream.expectReceived(t, join(opening, asked, echoed("n")))
				},
			},
		}
		for _, stage := range stages {
			t.Run(stage.name+": Stop returns only once it has, and its place is then free for another Listener on the count, and no more", func(t *testing.T) {
				t.Parallel()
				count := listener.NewCount()
				other := startedListener(t, 1, openTelnet, count)
				held := newHeldStage(lingerFor)
				stopping := startedListener(t, 1, stage.open(held), count)
				holdSilently(t, other.addresses[0], connectionCap-1)
				stage.reach(t, stopping.addresses[0])
				awaitSignal(t, "the held stage beginning", held.begun)
				stopping.engine.Stop()
				if !held.returned.Load() {
					t.Fatalf("Stop returned while the held stage was still running")
				}
				expectServed(t, other.addresses[0])
				expectRefused(t, other.addresses[0])
			})
		}
		t.Run("before Start: each socket refuses a dial", func(t *testing.T) {
			t.Parallel()
			made := makeListener(t, 2, openTelnet, listener.NewCount())
			made.engine.Stop()
			for _, address := range made.addresses {
				expectDialRefused(t, address)
			}
		})
	})

	t.Run("When Stop is called on several Listeners at once, each shall close its sockets and connections without waiting for another's.", func(t *testing.T) {
		t.Parallel()
		for _, shared := range []bool{true, false} {
			counts := "one count"
			if !shared {
				counts = "two counts"
			}
			t.Run(fmt.Sprintf("%s: one Listener's Stop held in its Open, the other's Stop returns, its callers ended and its socket refusing, before the first is let go", counts), func(t *testing.T) {
				t.Parallel()
				count := listener.NewCount()
				held := newHeldStage(0)
				first := startedListener(t, 1, held.open, count)
				if !shared {
					count = listener.NewCount()
				}
				second := startedListener(t, 1, openTelnet, count)
				// Registered after both Listeners, so it runs before either one's Stop.
				t.Cleanup(held.letGo)
				dial(t, first.addresses[0])
				awaitSignal(t, "the first Listener's Open beginning", held.begun)
				silent := holdSilently(t, second.addresses[0], 1)[0]
				prompted, _ := atPrompt(t, second.addresses[0])
				firstStopped := stopInBackground(first.engine)
				awaitSignal(t, "the first Listener's Open seeing its context end", held.ended)
				expectStopped(t, "the second Listener", stopInBackground(second.engine))
				expectEnded(t, silent)
				expectEnded(t, prompted)
				expectDialRefused(t, second.addresses[0])
				select {
				case <-firstStopped:
					t.Fatalf("the first Listener's Stop returned while its Open was still running")
				default:
				}
				held.letGo()
				expectStopped(t, "the first Listener", firstStopped)
				expectDialRefused(t, first.addresses[0])
			})
		}
	})

	t.Run("Stop shall leave every other Listener, whether or not it shares this Listener's ConnectionCount, accepting and serving as before.", func(t *testing.T) {
		t.Parallel()
		t.Run("three Listeners, two on one count and one on another: the first stopped; at the other two, the callers at the prompt get Hello and the shutdown, the silent ones the greeting and the prompt, and new callers are served", func(t *testing.T) {
			t.Parallel()
			count := listener.NewCount()
			stopping := startedListener(t, 1, openTelnet, count)
			sharing := startedListener(t, 1, openTelnet, count)
			apart := startedListener(t, 1, openTelnet, listener.NewCount())
			atPrompt(t, stopping.addresses[0])
			type held struct {
				call   caller
				stream *recording
				silent *recording
			}
			var others []held
			for _, made := range []kindListener{sharing, apart} {
				call, stream := atPrompt(t, made.addresses[0])
				others = append(others, held{call: call, stream: stream, silent: silentStream(t, made.addresses[0])})
			}
			stopping.engine.Stop()
			expectDialRefused(t, stopping.addresses[0])
			for _, other := range others {
				expectHello(t, other.call, other.stream)
				other.silent.expectAsked(t)
			}
			expectServed(t, sharing.addresses[0])
			expectServed(t, apart.addresses[0])
		})
	})
}
