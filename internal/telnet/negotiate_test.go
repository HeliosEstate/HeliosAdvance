// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests of Negotiate over real loopback sockets, driven by the scripted caller: the opening
// requests, the replies and when they are written, how negotiation ends, each kind of failure,
// the context's deadline and cancellation, and the deadlines the connection is left with.
package telnet_test

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/telnet"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// early is how far before its deadline a runner's clock may wake a wait: a deadline is never
// met sooner than this.
const early = 20 * time.Millisecond

// negotiated is what one Negotiate call returned, and when.
type negotiated struct {
	outcome  telnet.Outcome
	err      error
	returned time.Time
}

// negotiating is a Negotiate call running on the server end.
type negotiating struct {
	// called is a moment before Negotiate was called, so before its opening write began.
	called time.Time
	// done holds Negotiate's result; a check that takes it early hands it back for the row.
	done chan negotiated
}

// negotiate calls Negotiate on its own goroutine, as the Listener does, and returns at once.
func negotiate(ctx context.Context, connection telnet.Conn) negotiating {
	done := make(chan negotiated, 1)
	called := time.Now()
	go func() {
		outcome, err := telnet.Negotiate(ctx, connection)
		done <- negotiated{outcome: outcome, err: err, returned: time.Now()}
	}()
	return negotiating{called: called, done: done}
}

// result waits for Negotiate to return, failing the test if it has not by the deadline.
func (call negotiating) result(t *testing.T, deadline time.Time) negotiated {
	t.Helper()
	// A result already in wins over a give-up already run out: a test that came late to wait
	// would otherwise get either, by chance.
	select {
	case got := <-call.done:
		return got
	default:
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case got := <-call.done:
		return got
	case <-timer.C:
		t.Fatalf("Negotiate had not returned %v after it was called", time.Since(call.called))
		return negotiated{}
	}
}

// patientResult waits for Negotiate to return as result does, the time from the call to the
// deadline stretched under the race detector: a row that only gives up there judges no time.
func (call negotiating) patientResult(t *testing.T, deadline time.Time) negotiated {
	t.Helper()
	return call.result(t, call.called.Add(testrun.Patient(deadline.Sub(call.called))))
}

// expectOutcome fails the row unless Negotiate gave the outcome its setup was for: a setup that
// came late gives another, and where the deadlines are left would then judge a case not reached.
func expectOutcome(t *testing.T, got negotiated, outcome telnet.Outcome) {
	t.Helper()
	if got.err != nil || got.outcome != outcome {
		t.Fatalf("did not reach its case: Negotiate returned (%v, %v), want (%v, no error)", got.outcome, got.err, outcome)
	}
}

// expectReturn checks what Negotiate returned and that it came within its window.
func expectReturn(t *testing.T, got negotiated, outcome telnet.Outcome, errs []error, notBefore, notAfter time.Time) {
	t.Helper()
	if len(errs) == 0 {
		if got.err != nil || got.outcome != outcome {
			t.Fatalf("Negotiate returned (%v, %v), want (%v, no error)", got.outcome, got.err, outcome)
		}
	}
	for _, want := range errs {
		if !errors.Is(got.err, want) {
			t.Fatalf("Negotiate returned %v, which is not %v", got.err, want)
		}
	}
	expectWithin(t, "Negotiate's return", got.returned, notBefore, notAfter)
}

// expectWithin checks a moment falls in its window, and logs how late past the window's start
// it came, so the runners' margins show in the test log.
func expectWithin(t *testing.T, what string, moment, notBefore, notAfter time.Time) {
	t.Helper()
	t.Logf("%s came %v into its window of %v", what, moment.Sub(notBefore), notAfter.Sub(notBefore))
	if moment.Before(notBefore.Add(-early)) {
		t.Fatalf("%s came %v too soon", what, notBefore.Sub(moment))
	}
	if moment.After(notAfter) {
		if testrun.Race {
			t.Logf("under the race detector, timing is not judged: %s came %v late", what, moment.Sub(notAfter))
		} else {
			t.Fatalf("%s came %v too late", what, moment.Sub(notAfter))
		}
	}
}

// expectNothingWritten checks the client receives no byte, once the test has closed the server
// end.
func expectNothingWritten(t *testing.T, pair connected) {
	t.Helper()
	_ = pair.server.Close()
	expectStream(t, pair.client, nil, time.Now().Add(testrun.Patient(margin)))
}

// withDeadline is a context ending at the deadline, cancelled when the test ends.
func withDeadline(t *testing.T, deadline time.Time) context.Context {
	t.Helper()
	ctx, cancel := context.WithDeadline(t.Context(), deadline)
	t.Cleanup(cancel)
	return ctx
}

// endsLate is a context whose deadline passes well before it reports its end, as any context may:
// it ends after the window a row allows for Negotiate's return, so only the clock can tell in time
// that the deadline passed. A context's own timer and the connection's deadline, set to the same
// moment, wake in either order, so without this a row tells the clock's part only by chance.
func endsLate(t *testing.T, deadline time.Time) context.Context {
	t.Helper()
	ctx, cancel := context.WithDeadline(t.Context(), deadline.Add(2*margin))
	t.Cleanup(cancel)
	return lateEnd{Context: ctx, deadline: deadline}
}

type lateEnd struct {
	context.Context
	deadline time.Time
}

func (ctx lateEnd) Deadline() (time.Time, bool) {
	return ctx.deadline, true
}

// endsOnFailure is the real server end, with the context cancelled at the moment a read or a
// reply's write fails, so the failure and the end of the context meet. A reply is any write
// after a read has returned bytes; the opening comes before any read.
type endsOnFailure struct {
	urgentConn
	cancel          context.CancelFunc
	failReply       bool
	failUrgent      bool
	hasRead         bool
	cancelReadOnEOF bool
}

// WriteUrgent fails the Synch's write on a closed connection, the context cancelled first.
func (connection *endsOnFailure) WriteUrgent(buffer []byte) (int, error) {
	if connection.failUrgent {
		connection.cancel()
		_ = connection.Close()
	}
	return connection.urgentConn.WriteUrgent(buffer)
}

func (connection *endsOnFailure) Read(buffer []byte) (int, error) {
	got, err := connection.TCPConn.Read(buffer)
	if got > 0 {
		connection.hasRead = true
	}
	if err != nil && connection.cancelReadOnEOF {
		connection.cancel()
	}
	return got, err
}

func (connection *endsOnFailure) Write(buffer []byte) (int, error) {
	if connection.failReply && connection.hasRead {
		connection.cancel()
		_ = connection.Close()
	}
	return connection.TCPConn.Write(buffer)
}

// holdPast is how far past the moment it must follow a held read or write returns: past
// NegotiationSeconds, or past the context's deadline, by more than a runner's clock may stray.
const holdPast = 300 * time.Millisecond

// heldCall is the real server end, with one read or write held until a chosen moment, so that it
// ends after NegotiationSeconds or after the context's deadline, which no outside caller can time.
// The held call does its real work first and returns at the moment, the context cancelled just
// before; one that breaks instead closes the connection at the moment and then writes. The moment
// is measured from when the opening write began, so a call that starts late cannot end the hold
// inside its 3 seconds.
type heldCall struct {
	urgentConn
	testEnds context.Context
	// holdWrite is the write held, counted from 1 for the opening; 0 holds the first read that
	// returns bytes or an error.
	holdWrite int
	// after is how long after the opening write began the held call returns, and until a moment
	// it does not return before.
	after time.Duration
	until time.Time
	stop  context.CancelFunc
	// breaks has the held write fail on a closed connection instead of going through.
	breaks bool
	// ignoreWriteDeadline lets every write through whatever deadline it was given, so a write
	// made after the context has ended shows: on a real socket the deadline would hide it.
	ignoreWriteDeadline bool

	openingBegan time.Time
	writes       int
	readHeld     bool
	// released is when the held call returned; it is read once Negotiate has returned.
	released time.Time
}

func (connection *heldCall) SetWriteDeadline(deadline time.Time) error {
	if connection.ignoreWriteDeadline {
		return nil
	}
	return connection.urgentConn.SetWriteDeadline(deadline)
}

func (connection *heldCall) hold() {
	moment := connection.openingBegan.Add(connection.after)
	if connection.until.After(moment) {
		moment = connection.until
	}
	wait(connection.testEnds, moment)
	if connection.stop != nil {
		connection.stop()
	}
	connection.released = time.Now()
}

func (connection *heldCall) Read(buffer []byte) (int, error) {
	got, err := connection.TCPConn.Read(buffer)
	if connection.holdWrite == 0 && !connection.readHeld && (got > 0 || err != nil) {
		connection.readHeld = true
		connection.hold()
	}
	return got, err
}

func (connection *heldCall) Write(buffer []byte) (int, error) {
	return connection.written(buffer, connection.TCPConn.Write)
}

// WriteUrgent is counted among the writes, so a row can hold the Synch's.
func (connection *heldCall) WriteUrgent(buffer []byte) (int, error) {
	return connection.written(buffer, connection.urgentConn.WriteUrgent)
}

func (connection *heldCall) written(buffer []byte, send func([]byte) (int, error)) (int, error) {
	connection.writes++
	if connection.writes == 1 {
		connection.openingBegan = time.Now()
	}
	if connection.writes != connection.holdWrite {
		return send(buffer)
	}
	if connection.breaks {
		connection.hold()
		_ = connection.Close()
		return send(buffer)
	}
	written, err := send(buffer)
	connection.hold()
	return written, err
}

// sweep is every option request but the answers, then the answers: WILL and WONT for every
// option, the caller's side included, and DO and DONT for every option but the engine's side.
func sweep() []byte {
	var requests []byte
	for _, verb := range []byte{will, wont, doVerb, dont} {
		for code := range 256 {
			option := byte(code)
			if (verb == doVerb || verb == dont) && isOn(engineSide)(option) {
				continue
			}
			requests = append(requests, request(verb, option)...)
		}
	}
	return join(requests, answers)
}

// expectDeadlineAt checks a read on the server end, the client silent, waits until the deadline.
// closeAfter closes the server end a stretched margin after the deadline, or after now if that
// is later: under the race detector Negotiate may return past the deadline, and a watchdog
// already run out would close the connection before the check reads it.
func closeAfter(server *net.TCPConn, deadline time.Time) *time.Timer {
	from := deadline
	if now := time.Now(); now.After(from) {
		from = now
	}
	return time.AfterFunc(time.Until(from.Add(testrun.Patient(margin))), func() { _ = server.Close() })
}

func expectReadDeadlineAt(t *testing.T, server *net.TCPConn, deadline time.Time) {
	t.Helper()
	defer closeAfter(server, deadline).Stop()
	got, err := server.Read(make([]byte, 16))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a read after Negotiate returned gave %d bytes and %v, want a passed deadline", got, err)
	}
	expectWithin(t, "the read's deadline", time.Now(), deadline, deadline.Add(margin))
}

// expectWriteDeadlineAt checks a write on the server end, the client not reading, waits until the
// deadline.
func expectWriteDeadlineAt(t *testing.T, server *net.TCPConn, deadline time.Time) {
	t.Helper()
	defer closeAfter(server, deadline).Stop()
	// Windows takes a large write whole into its own buffers, so the write is repeated until one
	// has to wait.
	chunk := make([]byte, 1<<20)
	var err error
	for written := 0; err == nil && written < 1<<30; written += len(chunk) {
		_, err = server.Write(chunk)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a write after Negotiate returned gave %v, want a passed deadline", err)
	}
	expectWithin(t, "the write's deadline", time.Now(), deadline, deadline.Add(margin))
}

func TestNegotiate(t *testing.T) {
	t.Parallel()
	t.Run("If the context has ended when Negotiate is called, judged by the clock, then Negotiate shall return ErrDeadlineEnded without writing to the connection.", func(t *testing.T) {
		t.Parallel()
		t.Run("a deadline passed a second ago that the context reports ended only later", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(endsLate(t, time.Now().Add(-time.Second)), &heldCall{urgentConn: pair.server, testEnds: t.Context(), holdWrite: -1, ignoreWriteDeadline: true})
			got := call.result(t, call.called.Add(testrun.Patient(margin)))
			expectReturn(t, got, 0, []error{telnet.ErrDeadlineEnded, context.DeadlineExceeded}, call.called, call.called.Add(margin))
			expectNothingWritten(t, pair)
		})
		t.Run("a cancelled context", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			call := negotiate(ctx, pair.server)
			got := call.result(t, call.called.Add(testrun.Patient(margin)))
			expectReturn(t, got, 0, []error{telnet.ErrDeadlineEnded, context.Canceled}, call.called, call.called.Add(margin))
			expectNothingWritten(t, pair)
		})
		t.Run("a deadline already passed", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			ctx := withDeadline(t, time.Now().Add(-time.Second))
			call := negotiate(ctx, pair.server)
			got := call.result(t, call.called.Add(testrun.Patient(margin)))
			expectReturn(t, got, 0, []error{telnet.ErrDeadlineEnded, context.DeadlineExceeded}, call.called, call.called.Add(margin))
			expectNothingWritten(t, pair)
		})
	})
	t.Run("When it is called, Negotiate shall write the opening requests New returns before it reads from the connection.", func(t *testing.T) {
		t.Parallel()
		t.Run("a silent caller gets the opening at once", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(testrun.Patient(10*time.Second))), pair.server)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
		})
		t.Run("a caller that answers before it reads still gets the opening first", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			write(t, pair.client, answers)
			call := negotiate(withDeadline(t, time.Now().Add(testrun.Patient(10*time.Second))), pair.server)
			got := call.result(t, call.called.Add(testrun.Patient(margin)))
			expectReturn(t, got, telnet.Answered, nil, call.called, call.called.Add(margin))
			_ = pair.server.CloseWrite()
			expectStream(t, pair.client, opening, time.Now().Add(testrun.Patient(margin)))
		})
	})
	t.Run("When Receive appends replies and returns false, Negotiate shall write those replies before its next read.", func(t *testing.T) {
		t.Parallel()
		t.Run("a caller that waits for each reply before it sends more", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(testrun.Patient(10*time.Second))), pair.server)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			oracle := freshReading()
			for _, ask := range [][]byte{request(doVerb, telnetTypeOption), request(will, telnetTypeOption), request(dont, echo), request(doVerb, echo), command(ayt)} {
				sent := write(t, pair.client, ask)
				want, _ := oracle.readAll(ask)
				got := readExactly(t, pair.client, len(want), sent.done.Add(testrun.Patient(margin)))
				if string(got) != string(want) {
					t.Fatalf("the reply to % x was % x, want % x", ask, got, want)
				}
			}
			sent := write(t, pair.client, join(request(doVerb, sga), request(doVerb, binary), request(will, binary), request(wont, windowSizeOption), request(wont, environOption), request(wont, speedOption)))
			expectReturn(t, call.result(t, sent.done.Add(testrun.Patient(margin))), telnet.Answered, nil, sent.began, sent.done.Add(margin))
		})
	})
	t.Run("When Receive returns true on a read that returned no error, Negotiate shall write that call's replies and the Synchs owed and, if those writes returned no error, return Answered with no error.", func(t *testing.T) {
		t.Parallel()
		t.Run("a refusal and the eight answers in one write, then requests after the end", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(testrun.Patient(10*time.Second))), pair.server)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			sent := write(t, pair.client, join(request(doVerb, telnetTypeOption), answers, request(doVerb, 25), request(will, 25), command(abortOutput)))
			expectReturn(t, call.result(t, sent.done.Add(testrun.Patient(margin))), telnet.Answered, nil, sent.began, sent.done.Add(margin))
			_ = pair.server.CloseWrite()
			expectStream(t, pair.client, request(wont, telnetTypeOption), time.Now().Add(testrun.Patient(margin)))
		})
		t.Run("every one refused, ECHO and SGA last", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(testrun.Patient(10*time.Second))), pair.server)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			sent := write(t, pair.client, join(refuseAll[6:], refuseAll[:6]))
			expectReturn(t, call.result(t, sent.done.Add(testrun.Patient(margin))), telnet.Answered, nil, sent.began, sent.done.Add(margin))
		})
		t.Run("ECHO and SGA first, then a refusal, then the other six: the refusal answered and Answered after the last", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(testrun.Patient(10*time.Second))), pair.server)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			write(t, pair.client, join(firstAnswers, request(doVerb, telnetTypeOption)))
			expectReceived(t, pair.client, request(wont, telnetTypeOption))
			expectNotReturned(t, call, time.Now().Add(quiet))
			sent := write(t, pair.client, restAnswers)
			expectReturn(t, call.result(t, sent.done.Add(testrun.Patient(margin))), telnet.Answered, nil, sent.began, sent.done.Add(margin))
		})
		t.Run("AO and the eighth answer in one read: the Synch written, then Answered", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			recorded := &recordingConn{urgentConn: pair.server}
			call := negotiate(withDeadline(t, time.Now().Add(testrun.Patient(10*time.Second))), recorded)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			write(t, pair.client, answers[:21])
			expectNotReturned(t, call, time.Now().Add(quiet))
			sent := write(t, pair.client, join(request(doVerb, telnetTypeOption), command(abortOutput), answers[21:]))
			expectReturn(t, call.result(t, sent.done.Add(testrun.Patient(margin))), telnet.Answered, nil, sent.began, sent.done.Add(margin))
			expectSynchs(t, pair.client, request(wont, telnetTypeOption), 1, time.Now().Add(testrun.Patient(margin)))
			expectWrites(t, recorded, []writeRecord{{data: request(wont, telnetTypeOption)}, synchWrite(1)})
		})
	})
	t.Run("When TakeSynch returns more than zero after a read that returned no error, Negotiate shall write that read's replies, then IAC DM repeated that many times in one WriteUrgent, before its next read.", func(t *testing.T) {
		t.Parallel()
		rows := []struct {
			name    string
			sent    []byte
			replies []byte
			synchs  int
		}{
			{name: "AO alone: one IAC DM, urgent", sent: command(abortOutput), synchs: 1},
			{name: "IP alone: one IAC DM, urgent", sent: command(interruptProcess), synchs: 1},
			{name: "DO 24, AO, IP and AO in one write: WONT 24, then IAC DM three times in one urgent write", sent: join(request(doVerb, telnetTypeOption), command(abortOutput), command(interruptProcess), command(abortOutput)), replies: request(wont, telnetTypeOption), synchs: 3},
			{name: "AO, then DO 24 in the same write: WONT 24 before the Synch", sent: join(command(abortOutput), request(doVerb, telnetTypeOption)), replies: request(wont, telnetTypeOption), synchs: 1},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				pair := connect(t)
				recorded := &recordingConn{urgentConn: pair.server}
				call := negotiate(withDeadline(t, time.Now().Add(testrun.Patient(10*time.Second))), recorded)
				expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
				write(t, pair.client, row.sent)
				expectSynchs(t, pair.client, row.replies, row.synchs, time.Now().Add(testrun.Patient(margin)))
				// The read after the Synch's began only once the urgent write was made.
				writes := 2
				if row.replies != nil {
					writes = 3
				}
				if before := recorded.readsBefore(writes); before != 1 {
					t.Fatalf("%d reads began before the Synch was written, want the one that brought the AO or IP", before)
				}
				sent := write(t, pair.client, answers)
				expectReturn(t, call.result(t, sent.done.Add(testrun.Patient(margin))), telnet.Answered, nil, sent.began, sent.done.Add(margin))
				want := []writeRecord{synchWrite(row.synchs)}
				if row.replies != nil {
					want = append([]writeRecord{{data: row.replies}}, want...)
				}
				expectWrites(t, recorded, want)
			})
		}
	})
	t.Run("Negotiate shall return Answered or TimedOut only while the context has not ended, judged by the clock; once it has ended, Negotiate shall write nothing more and return ErrDeadlineEnded.", func(t *testing.T) {
		t.Parallel()
		t.Run("the read that brings all eight answers returns after the context's deadline, which the context reports only later: ErrDeadlineEnded, not Answered", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := time.Now().Add(time.Second)
			held := &heldCall{urgentConn: pair.server, testEnds: t.Context(), until: deadline.Add(holdPast)}
			call := negotiate(endsLate(t, deadline), held)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			write(t, pair.client, answers)
			got := call.result(t, deadline.Add(holdPast+testrun.Patient(margin)))
			expectReturn(t, got, 0, []error{telnet.ErrDeadlineEnded, context.DeadlineExceeded}, held.released, held.released.Add(margin))
		})
		t.Run("the read that brings DO 24 and AO returns after the context's deadline: no WONT 24 and no Synch written", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := time.Now().Add(time.Second)
			held := &heldCall{urgentConn: pair.server, testEnds: t.Context(), until: deadline.Add(holdPast), ignoreWriteDeadline: true}
			call := negotiate(endsLate(t, deadline), held)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			write(t, pair.client, join(request(doVerb, telnetTypeOption), command(abortOutput)))
			got := call.result(t, deadline.Add(holdPast+testrun.Patient(margin)))
			expectReturn(t, got, 0, []error{telnet.ErrDeadlineEnded, context.DeadlineExceeded}, held.released, held.released.Add(margin))
			expectNothingWritten(t, pair)
		})
		t.Run("the read the 3 seconds end returns after the context's deadline, which the context reports only later: ErrDeadlineEnded, not TimedOut", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := time.Now().Add(negotiationLimit + holdPast)
			held := &heldCall{urgentConn: pair.server, testEnds: t.Context(), until: deadline.Add(holdPast)}
			call := negotiate(endsLate(t, deadline), held)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			got := call.result(t, deadline.Add(holdPast+testrun.Patient(margin)))
			expectReturn(t, got, 0, []error{telnet.ErrDeadlineEnded, context.DeadlineExceeded}, held.released, held.released.Add(margin))
		})
		t.Run("its edge: the same hold with the context's deadline an hour away: TimedOut", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			released := time.Now().Add(negotiationLimit + 2*holdPast)
			held := &heldCall{urgentConn: pair.server, testEnds: t.Context(), until: released}
			call := negotiate(endsLate(t, time.Now().Add(time.Hour)), held)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			got := call.result(t, released.Add(testrun.Patient(margin)))
			expectReturn(t, got, telnet.TimedOut, nil, held.released, held.released.Add(margin))
		})
	})
	t.Run("If NegotiationSeconds pass after Negotiate begins the opening write, while a read is waiting, and the context has not ended, then Negotiate shall return TimedOut with no error.", func(t *testing.T) {
		t.Parallel()
		t.Run("a silent caller, a read waiting", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(testrun.Patient(10*time.Second))), pair.server)
			limit := call.called.Add(negotiationLimit)
			expectReturn(t, call.result(t, limit.Add(testrun.Patient(margin))), telnet.TimedOut, nil, limit, limit.Add(margin))
		})
		t.Run("a context with no deadline", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(t.Context(), pair.server)
			limit := call.called.Add(negotiationLimit)
			expectReturn(t, call.result(t, limit.Add(testrun.Patient(margin))), telnet.TimedOut, nil, limit, limit.Add(margin))
		})
		t.Run("a caller that sends a data byte every 200 ms does not restart the 3 seconds", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(testrun.Patient(10*time.Second))), pair.server)
			limit := call.called.Add(negotiationLimit)
			for next := time.Now(); next.Before(limit.Add(-300 * time.Millisecond)); next = next.Add(200 * time.Millisecond) {
				wait(t.Context(), next)
				write(t, pair.client, []byte("x"))
			}
			expectReturn(t, call.result(t, limit.Add(testrun.Patient(margin))), telnet.TimedOut, nil, limit, limit.Add(margin))
		})
		t.Run("one answer only", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(testrun.Patient(10*time.Second))), pair.server)
			write(t, pair.client, request(doVerb, echo))
			limit := call.called.Add(negotiationLimit)
			expectReturn(t, call.result(t, limit.Add(testrun.Patient(margin))), telnet.TimedOut, nil, limit, limit.Add(margin))
		})
		t.Run("just outside: a deadline 3.5 seconds after the call", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			before := time.Now()
			call := negotiate(withDeadline(t, before.Add(3500*time.Millisecond)), pair.server)
			limit := call.called.Add(negotiationLimit)
			got := call.result(t, limit.Add(testrun.Patient(margin)))
			// Which ends first, the 3 seconds or the context 500 ms after them, is two timers'
			// race; under the race detector either may be late, so either outcome is only logged.
			if testrun.Race && errors.Is(got.err, telnet.ErrDeadlineEnded) {
				// Too soon still fails: the race detector cannot make a return early, and
				// ErrDeadlineEnded cannot come before the context's deadline.
				if ended := before.Add(3500 * time.Millisecond); got.returned.Before(ended.Add(-early)) {
					t.Fatalf("Negotiate returned %v, %v before the context's deadline", got.err, ended.Sub(got.returned))
				}
				t.Logf("under the race detector, the outcome is not judged: Negotiate returned %v, %v after the call", got.err, got.returned.Sub(call.called))
				return
			}
			expectReturn(t, got, telnet.TimedOut, nil, limit, before.Add(3500*time.Millisecond))
		})
	})
	t.Run("If NegotiationSeconds have passed when a read or a write ends, Receive has not returned true, and the context has ended, then Negotiate shall return ErrDeadlineEnded.", func(t *testing.T) {
		t.Parallel()
		t.Run("the opening write ends after the 3 seconds, the call cancelled while it was under way", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			held := &heldCall{urgentConn: pair.server, testEnds: t.Context(), holdWrite: 1, after: negotiationLimit + holdPast, stop: cancel}
			call := negotiate(ctx, held)
			got := call.result(t, call.called.Add(negotiationLimit+holdPast+testrun.Patient(margin)))
			expectReturn(t, got, 0, []error{telnet.ErrDeadlineEnded, context.Canceled}, held.released, held.released.Add(margin))
		})
		t.Run("the Synch's urgent write ends after the 3 seconds, the call cancelled while it was under way", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			held := &heldCall{urgentConn: pair.server, testEnds: t.Context(), holdWrite: 2, after: negotiationLimit + holdPast, stop: cancel}
			call := negotiate(ctx, held)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			write(t, pair.client, command(abortOutput))
			got := call.result(t, call.called.Add(negotiationLimit+holdPast+testrun.Patient(margin)))
			expectReturn(t, got, 0, []error{telnet.ErrDeadlineEnded, context.Canceled}, held.released, held.released.Add(margin))
		})
		t.Run("a reply's write ends after the 3 seconds, the call cancelled while it was under way", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			held := &heldCall{urgentConn: pair.server, testEnds: t.Context(), holdWrite: 2, after: negotiationLimit + holdPast, stop: cancel}
			call := negotiate(ctx, held)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			write(t, pair.client, request(doVerb, telnetTypeOption))
			got := call.result(t, call.called.Add(negotiationLimit+holdPast+testrun.Patient(margin)))
			expectReturn(t, got, 0, []error{telnet.ErrDeadlineEnded, context.Canceled}, held.released, held.released.Add(margin))
		})
		t.Run("a read that returned a data byte ends after the 3 seconds, the call cancelled while it was under way", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			held := &heldCall{urgentConn: pair.server, testEnds: t.Context(), after: negotiationLimit + holdPast, stop: cancel}
			call := negotiate(ctx, held)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			write(t, pair.client, []byte("x"))
			got := call.result(t, call.called.Add(negotiationLimit+holdPast+testrun.Patient(margin)))
			expectReturn(t, got, 0, []error{telnet.ErrDeadlineEnded, context.Canceled}, held.released, held.released.Add(margin))
		})
		t.Run("the opening write ends after the 3 seconds and after the context's deadline, which the context reports only later", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := time.Now().Add(negotiationLimit + holdPast)
			held := &heldCall{urgentConn: pair.server, testEnds: t.Context(), holdWrite: 1, after: negotiationLimit + holdPast, until: deadline.Add(holdPast)}
			call := negotiate(endsLate(t, deadline), held)
			got := call.result(t, deadline.Add(holdPast+testrun.Patient(margin)))
			expectReturn(t, got, 0, []error{telnet.ErrDeadlineEnded, context.DeadlineExceeded}, held.released, held.released.Add(margin))
		})
	})
	t.Run("If the context's deadline passes while a write is waiting, or at or before NegotiationSeconds after the opening write began while a read is waiting, then Negotiate shall return ErrDeadlineEnded.", func(t *testing.T) {
		t.Parallel()
		t.Run("a deadline at 1 second, a read waiting", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := time.Now().Add(time.Second)
			call := negotiate(withDeadline(t, deadline), pair.server)
			expectReturn(t, call.result(t, deadline.Add(testrun.Patient(margin))), 0, []error{telnet.ErrDeadlineEnded, context.DeadlineExceeded}, deadline, deadline.Add(margin))
		})
		t.Run("at the edge: a deadline 3 seconds after a moment before the call", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := time.Now().Add(negotiationLimit)
			call := negotiate(withDeadline(t, deadline), pair.server)
			expectReturn(t, call.result(t, deadline.Add(testrun.Patient(margin))), 0, []error{telnet.ErrDeadlineEnded, context.DeadlineExceeded}, deadline, deadline.Add(margin))
		})
		t.Run("a deadline at 1 second that the context reports ended only later, a read waiting", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := time.Now().Add(time.Second)
			call := negotiate(endsLate(t, deadline), pair.server)
			expectReturn(t, call.result(t, deadline.Add(testrun.Patient(margin))), 0, []error{telnet.ErrDeadlineEnded, context.DeadlineExceeded}, deadline, deadline.Add(margin))
		})
	})
	t.Run("If the context is cancelled while a read or a write is waiting, then Negotiate shall stop waiting and return ErrDeadlineEnded.", func(t *testing.T) {
		t.Parallel()
		t.Run("cancelled at 500 ms, a read waiting", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(testrun.Patient(10*time.Second)))
			defer cancel()
			call := negotiate(ctx, pair.server)
			wait(t.Context(), call.called.Add(500*time.Millisecond))
			cancelled := time.Now()
			cancel()
			expectReturn(t, call.result(t, cancelled.Add(testrun.Patient(margin))), 0, []error{telnet.ErrDeadlineEnded, context.Canceled}, cancelled, cancelled.Add(margin))
		})
		t.Run("cancelled at 500 ms, a write waiting", func(t *testing.T) {
			t.Parallel()
			// A small window, so the write the flood leaves waiting stays waiting.
			pair := connectSmall(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			call := negotiate(ctx, pair.server)
			if !stallNegotiation(t, pair, call) {
				return
			}
			wait(t.Context(), call.called.Add(500*time.Millisecond))
			cancelled := time.Now()
			cancel()
			expectReturn(t, call.result(t, cancelled.Add(testrun.Patient(margin))), 0, []error{telnet.ErrDeadlineEnded, context.Canceled}, cancelled, cancelled.Add(margin))
		})
	})
	t.Run("Negotiate shall return ErrDeadlineEnded wrapping context.DeadlineExceeded when the context's deadline passed, and context.Canceled when it was cancelled, so that errors.Is matches both.", func(t *testing.T) {
		t.Parallel()
		t.Run("a deadline while waiting matches the deadline and not a cancel", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := time.Now().Add(500 * time.Millisecond)
			call := negotiate(withDeadline(t, deadline), pair.server)
			got := call.result(t, deadline.Add(testrun.Patient(margin)))
			if !errors.Is(got.err, telnet.ErrDeadlineEnded) || !errors.Is(got.err, context.DeadlineExceeded) || errors.Is(got.err, context.Canceled) {
				t.Fatalf("Negotiate returned %v", got.err)
			}
		})
		t.Run("a cancel while waiting matches the cancel and not a deadline", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(testrun.Patient(10*time.Second)))
			defer cancel()
			call := negotiate(ctx, pair.server)
			wait(t.Context(), call.called.Add(300*time.Millisecond))
			cancel()
			got := call.result(t, time.Now().Add(testrun.Patient(margin)))
			if !errors.Is(got.err, telnet.ErrDeadlineEnded) || !errors.Is(got.err, context.Canceled) || errors.Is(got.err, context.DeadlineExceeded) {
				t.Fatalf("Negotiate returned %v", got.err)
			}
		})
		t.Run("ended before the call, each kind", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			got := negotiate(ctx, pair.server).result(t, time.Now().Add(testrun.Patient(margin)))
			if !errors.Is(got.err, telnet.ErrDeadlineEnded) || !errors.Is(got.err, context.Canceled) || errors.Is(got.err, context.DeadlineExceeded) {
				t.Fatalf("Negotiate returned %v for a cancelled context", got.err)
			}
			got = negotiate(withDeadline(t, time.Now().Add(-time.Second)), pair.server).result(t, time.Now().Add(testrun.Patient(margin)))
			if !errors.Is(got.err, telnet.ErrDeadlineEnded) || !errors.Is(got.err, context.DeadlineExceeded) || errors.Is(got.err, context.Canceled) {
				t.Fatalf("Negotiate returned %v for a passed deadline", got.err)
			}
		})
	})
	t.Run("If the context has ended when a read or a write fails, then Negotiate shall return ErrDeadlineEnded, whatever the failure.", func(t *testing.T) {
		t.Parallel()
		t.Run("the caller closes, and the context ends as the read meets end of file", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(testrun.Patient(10*time.Second)))
			defer cancel()
			call := negotiate(ctx, &endsOnFailure{urgentConn: pair.server, cancel: cancel, cancelReadOnEOF: true})
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			closed := time.Now()
			_ = pair.client.CloseWrite()
			expectReturn(t, call.result(t, closed.Add(testrun.Patient(margin))), 0, []error{telnet.ErrDeadlineEnded, context.Canceled}, closed, closed.Add(margin))
		})
		t.Run("the context ends as a reply's write fails on a closed connection", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(testrun.Patient(10*time.Second)))
			defer cancel()
			call := negotiate(ctx, &endsOnFailure{urgentConn: pair.server, cancel: cancel, failReply: true})
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			sent := write(t, pair.client, request(doVerb, telnetTypeOption))
			expectReturn(t, call.result(t, sent.done.Add(testrun.Patient(margin))), 0, []error{telnet.ErrDeadlineEnded, context.Canceled}, sent.began, sent.done.Add(margin))
		})
		t.Run("the context ends as the Synch's urgent write fails on a closed connection", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(testrun.Patient(10*time.Second)))
			defer cancel()
			call := negotiate(ctx, &endsOnFailure{urgentConn: pair.server, cancel: cancel, failUrgent: true})
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			sent := write(t, pair.client, command(abortOutput))
			expectReturn(t, call.result(t, sent.done.Add(testrun.Patient(margin))), 0, []error{telnet.ErrDeadlineEnded, context.Canceled}, sent.began, sent.done.Add(margin))
		})
		t.Run("the read meets end of file after the context's deadline, which the context reports only later", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := time.Now().Add(time.Second)
			held := &heldCall{urgentConn: pair.server, testEnds: t.Context(), until: deadline.Add(holdPast)}
			call := negotiate(endsLate(t, deadline), held)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			_ = pair.client.CloseWrite()
			got := call.result(t, deadline.Add(holdPast+testrun.Patient(margin)))
			expectReturn(t, got, 0, []error{telnet.ErrDeadlineEnded, context.DeadlineExceeded}, held.released, held.released.Add(margin))
		})
		t.Run("the read meets a reset after the context's deadline, which the context reports only later", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := time.Now().Add(time.Second)
			held := &heldCall{urgentConn: pair.server, testEnds: t.Context(), until: deadline.Add(holdPast)}
			call := negotiate(endsLate(t, deadline), held)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			reset(t, pair.client)
			got := call.result(t, deadline.Add(holdPast+testrun.Patient(margin)))
			expectReturn(t, got, 0, []error{telnet.ErrDeadlineEnded, context.DeadlineExceeded}, held.released, held.released.Add(margin))
		})
		t.Run("a reply's write fails on a closed connection after the context's deadline, which the context reports only later", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := time.Now().Add(time.Second)
			held := &heldCall{urgentConn: pair.server, testEnds: t.Context(), holdWrite: 2, until: deadline.Add(holdPast), breaks: true}
			call := negotiate(endsLate(t, deadline), held)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			write(t, pair.client, request(doVerb, telnetTypeOption))
			got := call.result(t, deadline.Add(holdPast+testrun.Patient(margin)))
			expectReturn(t, got, 0, []error{telnet.ErrDeadlineEnded, context.DeadlineExceeded}, held.released, held.released.Add(margin))
		})
	})
	t.Run("If a read returns end of file, then Negotiate shall return ErrCallerClosed without writing that read's replies.", func(t *testing.T) {
		t.Parallel()
		t.Run("the caller shuts down its sending side at once", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(testrun.Patient(10*time.Second))), pair.server)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			closed := time.Now()
			_ = pair.client.CloseWrite()
			expectReturn(t, call.result(t, closed.Add(testrun.Patient(margin))), 0, []error{telnet.ErrCallerClosed}, closed, closed.Add(margin))
			expectNothingWritten(t, pair)
		})
		t.Run("the caller closes in order after half a request", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(testrun.Patient(10*time.Second))), pair.server)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			write(t, pair.client, []byte{iac, doVerb})
			closed := time.Now()
			_ = pair.client.CloseWrite()
			expectReturn(t, call.result(t, closed.Add(testrun.Patient(margin))), 0, []error{telnet.ErrCallerClosed}, closed, closed.Add(margin))
			expectNothingWritten(t, pair)
		})
		t.Run("the caller answers once, then closes whole", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(testrun.Patient(10*time.Second))), pair.server)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			write(t, pair.client, request(doVerb, echo))
			closed := time.Now()
			_ = pair.client.Close()
			expectReturn(t, call.result(t, closed.Add(testrun.Patient(margin))), 0, []error{telnet.ErrCallerClosed}, closed, closed.Add(margin))
		})
	})
	t.Run("If a read or a write fails other than by end of file or a passed deadline, then Negotiate shall return ErrConnectionFailed.", func(t *testing.T) {
		t.Parallel()
		t.Run("the caller resets the connection while a read waits", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(testrun.Patient(10*time.Second))), pair.server)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			broken := time.Now()
			reset(t, pair.client)
			expectReturn(t, call.result(t, broken.Add(testrun.Patient(margin))), 0, []error{telnet.ErrConnectionFailed}, broken, broken.Add(margin))
		})
		t.Run("the caller resets the connection while a write waits", func(t *testing.T) {
			t.Parallel()
			// A small window, so the write the flood leaves waiting stays waiting.
			pair := connectSmall(t)
			call := negotiate(withDeadline(t, time.Now().Add(testrun.Patient(10*time.Second))), pair.server)
			if !stallNegotiation(t, pair, call) {
				return
			}
			broken := time.Now()
			reset(t, pair.client)
			expectReturn(t, call.result(t, broken.Add(testrun.Patient(margin))), 0, []error{telnet.ErrConnectionFailed}, broken, broken.Add(margin))
		})
		t.Run("the server end is closed under a waiting read", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(testrun.Patient(10*time.Second))), pair.server)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			wait(t.Context(), time.Now().Add(200*time.Millisecond))
			closed := time.Now()
			_ = pair.server.Close()
			expectReturn(t, call.result(t, closed.Add(testrun.Patient(margin))), 0, []error{telnet.ErrConnectionFailed}, closed, closed.Add(margin))
		})
		t.Run("the Synch's urgent write fails on a closed connection", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			held := &heldCall{urgentConn: pair.server, testEnds: t.Context(), holdWrite: 2, breaks: true}
			call := negotiate(withDeadline(t, time.Now().Add(testrun.Patient(10*time.Second))), held)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			sent := write(t, pair.client, command(interruptProcess))
			expectReturn(t, call.result(t, sent.done.Add(testrun.Patient(margin))), 0, []error{telnet.ErrConnectionFailed}, sent.began, sent.done.Add(margin))
		})
	})
	t.Run("The telnet package shall send the caller no option request other than the opening requests and the replies the tables on Receive give.", func(t *testing.T) {
		t.Parallel()
		t.Run("every option request in one write", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(testrun.Patient(10*time.Second))), pair.server)
			requests := sweep()
			sent := write(t, pair.client, requests)
			expectReturn(t, call.result(t, sent.done.Add(testrun.Patient(margin))), telnet.Answered, nil, call.called, sent.done.Add(margin))
			_ = pair.server.CloseWrite()
			expectStream(t, pair.client, join(opening, expectedReplies(requests)), time.Now().Add(testrun.Patient(margin)))
		})
	})
	t.Run("Negotiate shall write nothing to the connection but the opening requests, the replies Receive appends, and IAC DM written with WriteUrgent once for each Synch TakeSynch returns.", func(t *testing.T) {
		t.Parallel()
		t.Run("requests, commands, AYT and AO a byte at a time", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			recorded := &recordingConn{urgentConn: pair.server}
			call := negotiate(withDeadline(t, time.Now().Add(testrun.Patient(10*time.Second))), recorded)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			requests := join(request(doVerb, telnetTypeOption), request(will, 25), []byte{iac, nop, 'x'}, request(dont, echo), request(doVerb, echo),
				command(ayt), command(eraseLine), command(dataMark), command(abortOutput))
			for index := range requests {
				write(t, pair.client, requests[index:index+1])
			}
			expectSynchs(t, pair.client, join(request(wont, telnetTypeOption), request(dont, 25), request(will, echo), []byte(aytAnswerBytes)), 1, time.Now().Add(testrun.Patient(margin)))
			sent := write(t, pair.client, answers[3:])
			expectReturn(t, call.result(t, sent.done.Add(testrun.Patient(margin))), telnet.Answered, nil, call.called, sent.done.Add(margin))
			_ = pair.server.CloseWrite()
			expectStream(t, pair.client, nil, time.Now().Add(testrun.Patient(margin)))
			urgent := 0
			for _, record := range recorded.written() {
				if record.urgent {
					urgent++
				}
			}
			if urgent != 1 {
				t.Fatalf("%d urgent writes, want 1", urgent)
			}
		})
		t.Run("a request split by the 256-byte read", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			call := negotiate(withDeadline(t, time.Now().Add(testrun.Patient(10*time.Second))), pair.server)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			count := readBufferBytes/3 + 1
			sent := write(t, pair.client, join(repeated(request(doVerb, telnetTypeOption), count), answers))
			expectReturn(t, call.result(t, sent.done.Add(testrun.Patient(margin))), telnet.Answered, nil, call.called, sent.done.Add(margin))
			_ = pair.server.CloseWrite()
			expectStream(t, pair.client, repeated(request(wont, telnetTypeOption), count), time.Now().Add(testrun.Patient(margin)))
		})
	})
	t.Run("When it returns, Negotiate shall leave the connection's read and write deadlines at the context's deadline.", func(t *testing.T) {
		t.Parallel()
		t.Run("answered: a read then waits until the context's deadline", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := testrun.CaseDeadline()
			call := negotiate(withDeadline(t, deadline), pair.server)
			write(t, pair.client, answers)
			expectOutcome(t, call.patientResult(t, deadline), telnet.Answered)
			expectReadDeadlineAt(t, pair.server.TCPConn, deadline)
		})
		t.Run("answered: a write to a caller that does not read waits until the context's deadline", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			_ = pair.client.SetReadBuffer(4096)
			deadline := testrun.CaseDeadline()
			call := negotiate(withDeadline(t, deadline), pair.server)
			write(t, pair.client, answers)
			expectOutcome(t, call.patientResult(t, deadline), telnet.Answered)
			expectWriteDeadlineAt(t, pair.server.TCPConn, deadline)
		})
		t.Run("timed out at 3 seconds: a read waits until the deadline at 5", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			// Stretched under the race detector: a 3 seconds that ends late would otherwise meet
			// the context's deadline and turn TimedOut into ErrDeadlineEnded.
			deadline := time.Now().Add(testrun.Patient(5 * time.Second))
			call := negotiate(withDeadline(t, deadline), pair.server)
			got := call.patientResult(t, deadline)
			if got.outcome != telnet.TimedOut {
				t.Fatalf("Negotiate returned (%v, %v), want TimedOut", got.outcome, got.err)
			}
			expectReadDeadlineAt(t, pair.server.TCPConn, deadline)
		})
		t.Run("cancelled at 500 ms: a read waits until the context's deadline", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			deadline := testrun.CaseDeadline()
			ctx, cancel := context.WithDeadline(t.Context(), deadline)
			defer cancel()
			call := negotiate(ctx, pair.server)
			wait(t.Context(), call.called.Add(500*time.Millisecond))
			cancel()
			if got := call.patientResult(t, deadline); !errors.Is(got.err, telnet.ErrDeadlineEnded) || !errors.Is(got.err, context.Canceled) {
				t.Fatalf("did not reach its case: Negotiate returned (%v, %v), want ErrDeadlineEnded for the cancel", got.outcome, got.err)
			}
			expectReadDeadlineAt(t, pair.server.TCPConn, deadline)
		})
		t.Run("the caller closed: a write to it waits until the context's deadline", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			_ = pair.client.SetReadBuffer(4096)
			// Stretched under the race detector: an opening and a close that come late would
			// otherwise meet the context's deadline and turn ErrCallerClosed into ErrDeadlineEnded.
			deadline := time.Now().Add(testrun.Patient(2 * time.Second))
			call := negotiate(withDeadline(t, deadline), pair.server)
			expectOpening(t, pair.client, call.called.Add(testrun.Patient(margin)))
			_ = pair.client.CloseWrite()
			got := call.patientResult(t, deadline)
			// Under the race detector the engine's 3 seconds, counted from its opening, may end
			// before the close reaches it: which comes first is its timing, so TimedOut is only
			// logged there. Where the write deadline is left is judged either way.
			if testrun.Race && got.err == nil && got.outcome == telnet.TimedOut {
				t.Logf("under the race detector, the outcome is not judged: Negotiate returned TimedOut, %v after the call", got.returned.Sub(call.called))
			} else if !errors.Is(got.err, telnet.ErrCallerClosed) {
				t.Fatalf("Negotiate returned %v, want ErrCallerClosed", got.err)
			}
			expectWriteDeadlineAt(t, pair.server.TCPConn, deadline)
		})
	})
	t.Run("If any failure not named above occurs, then Negotiate shall return ErrConnectionFailed and leave nothing behind.", func(t *testing.T) {
		t.Parallel()
		t.Run("a connection already closed", func(t *testing.T) {
			t.Parallel()
			pair := connect(t)
			_ = pair.server.Close()
			call := negotiate(withDeadline(t, time.Now().Add(testrun.Patient(10*time.Second))), pair.server)
			expectReturn(t, call.result(t, call.called.Add(testrun.Patient(margin))), 0, []error{telnet.ErrConnectionFailed}, call.called, call.called.Add(margin))
			_, err := readToEnd(pair.client, time.Now().Add(testrun.Patient(margin)))
			if !errors.Is(err, io.EOF) {
				t.Fatalf("the caller's end saw %v, want end of stream", err)
			}
		})
	})
}
