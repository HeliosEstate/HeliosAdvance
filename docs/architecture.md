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
| Telnet | `internal/telnet` | Telnet negotiation over one accepted connection, from the engine's first option requests to the end of negotiation; then the Line, the Telnet side of textio's character calls: the caller's bytes read in stream order, option requests answered by the same rules and tables and every other Telnet command removed, a send buffer with 255 doubled, and whether the board echoes; Accept, Telnet's way in for the shared execution path, which keeps urgent data in line, and the Line's own close, the shutdown and the closing wait | golang.org/x/sys/windows, in the Windows urgent write alone; the Go standard library |
| SSH | `internal/ssh` | The SSH handshake over one accepted connection, from the version line to the caller's shell: the host key file, the algorithms, sign-in with none, the answer to every channel and request, and whether the board echoes; then the Channel, the SSH side of textio's character calls, and SSH's own close: exit status, end of file, the channel's close and the closing wait | golang.org/x/crypto/ssh; the Go standard library |
| Listener | `internal/listener` | The listeners and the shared execution path: one accept loop per listening socket, each kind's sockets with its Open, that only accepts; then, for every kind alike, the cap of 100 open connections, the 70-second ceiling on the whole call, making the connection its kind's object, the call through Text I/O and the Session, the kind's own close once the call is answered, and the close | Text I/O, Session; the Go standard library |
| Session | `internal/session` | A caller's call once the connection is ready, whichever way the caller came in: the greeting, the prompt, the 60 seconds and 30 characters for the name, and writing Hello and the name, through a Connection of four calls (SendChar, RecvChar, SendString, RecvString) | the Go standard library only |
| Text I/O | `internal/textio` | A caller's string calls built on a connection's character calls, once for every kind of connection: SendString, RecvString and the line editor that reads a line, with its echo; a Conn offering all four calls to the session | the Go standard library only |
| Database | `internal/database` | The engine's side of the board's database: reading the connection file; connecting over TLS and signing in by SCRAM-SHA-256 with channel binding; refusing a login that could change the schema; the schema version and the server's row; and the lease, taken, renewed every 10 seconds, lost or ended. The schema and a server's login's rights are its `schema.sql` | github.com/jackc/pgx/v5 and its pgconn package; the Go standard library |
| The program | `cmd/hadv-service` | Starting and stopping: the command line, the refusal as root, waiting for the database and its lease before it listens and closing everything when the lease is lost, listening at 127.0.0.1 and ::1, reading the SSH host key, pairing each kind's listening sockets with its way in, the local log, and the stop signals | Listener, Telnet, SSH, Database; the Go standard library |
