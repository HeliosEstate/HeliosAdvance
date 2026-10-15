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
| Telnet | `internal/telnet` | Telnet negotiation over one accepted connection, from the engine's first option requests to the end of negotiation | the Go standard library only |
| Listener | `internal/listener` | Accepting callers on the listening sockets the Service opened and serving each one from accept to close: the cap of 100 open connections, connection floods, the connection ID, the 10-second hard deadline, the greeting, the close, and its own lines in the local log | Telnet; the Go standard library |
