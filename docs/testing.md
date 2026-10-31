# Testing

How the engine's approved tests are written. They are written apart from the code, before it is
built, and locked by the QA commit: a build changes code until they pass, never the tests.

## What a test drives

- The engine from outside wherever a line can be reached that way: the built program, real
  sockets on loopback, real files, the operating system's own tools. No fakes and no mocks.
- A package through its `contract.go`'s exported names only where a line cannot be reached from
  outside, such as the byte-level reading of a caller's input.
- A wrapper around a real connection is used only to make two things meet at a chosen moment,
  such as a context ending as a read fails, which no outside caller can time.

## The oracle

- Each test package carries its own copy of what it checks against: byte values from the RFCs,
  the greeting and the limits as the lines state them, and its own reading of the RFC tables. It
  never uses the package's constants or code, so a fault there cannot hide in the oracle too.
- A row whose expectation disagrees with the test's own reading fails as a fault in the test.

## Rows

- A line is quoted word for word, once, as the name of the subtest that holds its rows; each row
  is named for its case. `check.sh --trace` in the design repository reads these names.
- Every row asserts an exact outcome: the exact bytes to end of stream, the exact error, a time
  inside its window. A row that rightly expects no reply ends with a probe that must be answered,
  so it is red against code that does nothing.
- A time limit is proved with a window: it opens at a moment provably before the engine's own
  clock started, such as before the dial or the call, and closes at the limit plus the margin
  measured on every runner. Each timed row logs how far into its window the event came.
- A lower bound is read from when the caller's write began, an upper bound from when it
  returned: a write can return well after the engine has read it. The same holds for a cancel, a
  close or a reset the row makes: the moment is read before it, never after, since a test paused
  between the two sees the engine as early.
- Under the race detector, which slows the engine and the test by an amount nobody controls, no
  upper bound on time is judged: it is logged. A lower bound still is, since a slow engine cannot
  be early. `testrun.Race` says which build runs, and `testrun.Patient` stretches a wait there.
- How far a window may reach is set by its nearest fault: the broken copy, actually planted, that
  would land closest to the limit. A window stays under half the gap to it. The Listener's tests
  close a window at `margin` (750 ms) where that fault is near, such as a limit 900 ms too long;
  at `wideMargin` (1.5 s) where it is 3 seconds or more away; and at `windowEnd` where the fault's
  own clock started before the window opened.
- A margin is measured at the load CI itself runs. A row that fails only under a load made up for
  the measurement is named, and its margin is not widened for it.
- A wait whose line claims no time, such as for the bytes a row needs before its next step, is
  bounded by the one hang bound every package uses, `testrun.HangBound` (10 seconds), stretched
  with `testrun.Patient`: generous, since it costs time only when something is already broken,
  and never a verdict on time. A deadline handed to the engine that only must lie beyond the
  row's own bound keeps its own value and name.
- A test waits on the clock only where the clock is what the line is about; otherwise it waits
  on an event. `time.Sleep` is refused by the linter, in `testrun` too. A wait for an event
  nothing announces checks again at a short interval on a timer, up to the hang bound, and says
  why the event cannot be waited on.
- A setup waits on an event, never a fixed time: a lease another run holds is held long and ended
  once the program's own line shows it waiting. Where the row must set a deadline at a call that
  its setup has to beat, the deadline is `testrun.CaseDeadline()`, the setup's hang bound, and
  `testrun.ExpectCaseReached` fails the row when the setup ended under a margin before it, so a
  slow machine neither fails the engine nor passes without reaching the row's case.
- A row whose own check must land inside an engine window, such as a probe between two of the
  engine's moments, cannot hold on an arbitrarily slow machine: when the test came late it fails
  as a test fault or "cannot tell", naming neither the engine nor a pass.
- A row that checks nothing happens waits a stated time, so on a slow machine it can miss a late
  fault but never fail a sound engine: it is not proof of absence on every machine.
- Every test and subtest runs in parallel, each with its own sockets and its own Listener, except
  a test that must run alone (below).

## Waits and hangs

- Every wait a test makes has a bound: each read and write, each Start and Stop, each result a
  goroutine hands back. A fault in the engine then fails its row by name; it never runs the
  package into Go's test timeout, where every other row's verdict is lost with it.
- A goroutine a row starts hands its result back over a channel, and only the row's own goroutine
  reports. A goroutine that reports after its subtest has ended panics the whole package.
- A cleanup that waits on the engine, such as a Stop, is registered so that it runs after the
  row has let go of anything it holds back, such as a held Open; otherwise a fault that fails
  the row first leaves the cleanup waiting for good.

## Ports and tests that run alone

- A test that checks the engine does not listen on a port, and skips a port the machine already
  holds, runs alone, not in parallel: under a fault every parallel row's engine holds that port
  too, and the check would skip it or see the fault only by chance. It carries
  `//nolint:paralleltest` with its reason, on the test's line and on each row's.
- A row never assumes a port it freed stays free: a parallel row's engine may take it. A row that
  frees a port for the engine to take tries a fresh port only when the engine names that freed
  address as in use; any other first line is judged as before. A check that the program listens
  nowhere reads the program's own sockets from the system's table (on Linux from /proc, on
  Windows from netstat, by its process and a foreign address of 0.0.0.0:0 or [::]:0), never a
  dial to a freed port; a table that cannot be read fails the row.

## Reading a run

- `check.sh` runs one package at a time, the condition the margins are measured under, and runs
  `go test` without `-v`, so a passing row's `t.Logf`, such as a timed row's place in its window
  or a skipped port, never shows in its log, nor does what a passing test binary writes to
  standard error. Run with `-v` or `-json` to read them.
- A branch that changes a locked test without a signed QA commit is refused at the first gates,
  so no test runs on it. A probe that needs changed tests carries them as data under `testdata`
  and copies them into a scratch worktree on the runner.
- An unbracketed `|` in `go test -run` splits the whole pattern: `TestTake/^A|^B` runs
  `TestTake/^A` and a top-level test `^B`, so B's rows never run and a broken copy passes for the
  wrong reason. Bracket it: `TestTake/^(A|B)`.
- Go's coverage starts a block at a case's body, so mutation testing reads a mutant in a `case`
  expression as not covered even when rows run through it, and one in `internal/` that only
  `cmd/`'s rows catch as lived, since `cmd/` is left out of it. Plant such a mutant before calling
  it a gap.

## Runners

Linux x86-64, Linux ARM64 and Windows x86-64, as an ordinary user. A test that can run on Linux
alone is named `TestLinux…`, and one that needs a Linux container oracle `TestOracle…`: Windows
CI skips both. Green is `bash check.sh`, never `go test` alone.

## A run's own folder

- A test binary that starts servers or programs calls `testrun.Enter` first in its TestMain and
  `testrun.Leave` last: everything it makes lands in its own folder, and nothing outlives the run.
  A run killed or timed out leaves its folder, servers and programs, and the next run takes them.
- A failure to make the folder stops the run; what a dead run left that cannot be taken, and a
  removal that fails, are written to standard error and do not fail it, since whether Windows has
  let go of a file yet is its timing.

## A database the tests make

- The tests make their own PostgreSQL with its programs, never a service: a template cluster
  made once, copied per server, each with its own certificate authority and sign-in rules.
- A program that starts a server writes to a file, not a pipe: the server inherits its handles
  and would hold a pipe open. A cleanup that stops a server runs on a context of its own, since
  the test's has ended by then.
- A test that sets the process's environment runs alone, before the parallel tests resume.
- A client that gives up does not end PostgreSQL's wait on a lock: the server notices a closed
  client only when it next writes to it. A client's give-up is read from the server's statement
  log, not from the server's list of what waits.
- Windows hands a new process an ended one's ID at once, so a server's connection is told apart
  by its process and its start time together.
- A window for what follows a retry holds only the retry: the try's own time is read from the
  server's log and judged against the cadence, and what the try leads to against its own bound.
- A copy of a server by `pg_basebackup` asks for its checkpoint at once: the default spreads it
  out, and on a loaded runner it ran close to two minutes.
- A refusal row asserts the exact refusal, so the unbuilt code's own error cannot pass it.
- On Windows a server reads `pg_hba.conf` again for each new connection, and one that reads it
  while it is written in place refuses the connection. A test writes the file elsewhere and
  renames it over.
