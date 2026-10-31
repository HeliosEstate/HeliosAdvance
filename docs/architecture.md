# Architecture

This page lists the engine's units: what each one owns, the Go package it lives in, and what it
uses. A unit uses only what its row names; each unit on this page has an import rule in
`.golangci.yml`, read from its Uses column. Words on this page have the meanings given in the estate's
[glossary](https://github.com/HeliosEstate/.github/blob/main/GLOSSARY.md). What each unit does
is in its package's `contract.go`; what the engine does as a whole is in
[behavior.md](behavior.md).

## hadv-service

| Unit | Package | Owns | Uses |
|---|---|---|---|
| Telnet | `internal/telnet` | Telnet negotiation over one accepted connection, from the engine's first option requests to the end of negotiation; then the Line, the Telnet side of textio's character calls: the caller's bytes read in stream order, option requests answered by the same rules and tables and every other Telnet command removed, a send buffer with 255 doubled, and whether the board echoes; Accept, Telnet's way in for the shared execution path, which keeps urgent data in line, and the Line's own close, on a Line Open or Accept made: the shutdown through the connection's CloseWrite, and the closing wait | Timeup; golang.org/x/sys/windows, in the Windows urgent write alone; the Go standard library |
| SSH | `internal/ssh` | The SSH handshake over one accepted connection, from the version line to the caller's shell: the host key file, the algorithms, sign-in with none, the answer to every channel and request, and whether the board echoes; then the Channel, the SSH side of textio's character calls, and SSH's own close: exit status, end of file, the channel's close and the closing wait | golang.org/x/crypto/ssh; Timeup; the Go standard library |
| Listener | `internal/listener` | What every kind's listener is built on, and the shared execution path: a listener per kind of connection, made from that kind's sockets and its Open, with its own start and stop, and from its start one accept loop per socket that only accepts; then, for every kind alike, the cap of 100 open connections, counted in one count per engine that every listener shares, the 70-second ceiling on the whole call, making the connection its kind's object, the call through Text I/O and the Session, the kind's own close once the call is answered, and the close | Text I/O, Session; the Go standard library |
| Session | `internal/session` | A caller's call once the connection is ready, whichever way the caller came in: the greeting, the prompt, the 60 seconds and 30 characters for the name, and writing Hello and the name, through a Connection of four calls (SendChar, RecvChar, SendString, RecvString) | the Go standard library only |
| Text I/O | `internal/textio` | A caller's string calls built on a connection's character calls, once for every kind of connection: SendString, RecvString and the line editor that reads a line, with its echo; a Conn offering all four calls to the session | Timeup; the Go standard library |
| Timeup | `internal/timeup` | Once, for every unit that reads or writes a caller's connection: the rule for whether a call's time has run out, judged by the clock as well as by the context; the time a call must stop by, the earlier of its own deadline and its context's; and the wake that sets a connection's deadlines long past so a waiting read or write returns when it has | the Go standard library only |
| Database | `internal/database` | The engine's side of the board's database: reading the connection file; connecting over TLS and signing in by SCRAM-SHA-256 with channel binding; refusing a login that could change the schema; the schema version and the server's row; and the lease, taken, renewed every 10 seconds, lost or ended. The schema and a server's login's rights are its `schema.sql` | github.com/jackc/pgx/v5 and its pgconn and pgproto3 packages; the Go standard library |
| The program | `cmd/hadv-service` | Starting and stopping: the command line, the refusal as root, waiting for the database and its lease before it listens and closing everything when the lease is lost, reading the SSH host key, one listener function per kind, each in its own file, holding that kind's port, its addresses (127.0.0.1 and ::1 for now), its key and its way in, which opens its sockets with one shared helper and makes its listener; making the engine's one count of open connections, making every kind's listener before starting any, and stopping them all together; the local log, and the stop signals | Listener, Telnet, SSH, Database; the Go standard library |

## Test support

Not part of the engine: no engine code imports it, only the tests do. It is the developer's, as the
approved tests are, since a change to it changes every timed row at once.

| Unit | Package | Owns | Uses |
|---|---|---|---|
| Testrun | `internal/testrun` | What every test binary shares about its own run: whether it runs under the race detector, and how much longer a wait may take there; and the run's own folder, made first in a TestMain, where everything the run makes lands, servers and programs included, removed last, and taken by the next run when a run ends without removing it: its servers stopped with pg_ctl, its programs ended by where their executable lives, and the folder removed | golang.org/x/sys/windows, in its Windows files alone; the Go standard library |
