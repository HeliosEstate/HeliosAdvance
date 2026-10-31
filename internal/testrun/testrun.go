// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package testrun is what every test binary shares about its own run: whether it runs under the
// race detector and how long a wait may take there, and the run's own folder, which nothing the
// run makes outlives. Only test files import it, and it is the developer's, as the approved tests
// are: a change to how patient a test is changes every timed row at once.
package testrun

import (
	"testing"
	"time"
)

// HangBound is how long a test waits for what has no time of its own in the row, such as bytes,
// a result or an end, before it calls the wait a hang. One value for every package, generous,
// since it costs time only when something is already broken; a row stretches it with Patient. It
// is never a window or a deadline the row judges.
const HangBound = 10 * time.Second

// CaseDeadline is the deadline a row sets up for when its setup must be done before it: the
// setup's hang bound, stretched. A deadline a fixed second or two away was met before a slow
// machine's setup ended, and found the call where the row did not mean it to.
func CaseDeadline() time.Time {
	return time.Now().Add(Patient(HangBound))
}

// ExpectCaseReached fails the row when its setup ended less than its margin before the deadline
// it set up for: the deadline would find the call somewhere other than where the row needs it,
// and the row would pass, or fail, without reaching its case. With CaseDeadline, only a setup
// that hung fails here.
func ExpectCaseReached(t *testing.T, deadline time.Time, margin time.Duration) {
	t.Helper()
	if left := time.Until(deadline); left < margin {
		t.Fatalf("the setup ended %v before the deadline, under a margin: the row cannot reach its case", left)
	}
}

// raceStretch is how much longer a wait may take under the race detector, which slows the engine
// and the test by an amount nobody controls: generous, since a stretched wait still fails a
// hang, and no upper bound on time is judged there.
const raceStretch = 4

// Patient stretches a wait under the race detector; without it the wait is unchanged.
func Patient(wait time.Duration) time.Duration {
	if Race {
		return raceStretch * wait
	}
	return wait
}
