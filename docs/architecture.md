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
| Telnet | `internal/telnet` | Telnet negotiation over one accepted connection, from the engine's first option requests to the end of negotiation; then the Line, the Telnet side of textio's character calls: the caller's bytes read in stream order, option requests answered by the same rules and tables and every other Telnet command removed, a send buffer with 255 doubled, and whether the board echoes | the Go standard library only |
| Listener | `internal/listener` | Accepting callers on the listening sockets the program opened and serving each one from accept to close: the cap of 100 open connections, the 10-second hard deadline, the greeting and the close | Telnet; the Go standard library |
| Session | `internal/session` | A caller's call once the connection is ready, whichever way the caller came in: the greeting, the prompt, the 60 seconds and 30 characters for the name, and writing Hello and the name, through a Connection of four calls (SendChar, RecvChar, SendString, RecvString) | the Go standard library only |
| Text I/O | `internal/textio` | A caller's string calls built on a connection's character calls, once for every kind of connection: SendString, RecvString and the line editor that reads a line, with its echo; a Conn offering all four calls to the session | the Go standard library only |
| The program | `cmd/hadv-service` | Starting and stopping: the command line, the refusal as root, listening at 127.0.0.1 and ::1, the local log, and the stop signals | Listener; the Go standard library |
