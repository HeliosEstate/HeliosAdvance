# Behavior

This page describes what Helios Advance BBS does, as a sysop, a caller or a test on the real
system sees it. Each line says what the engine shall do; how it does it is left out. Words in
these lines have the meanings given in the estate's
[glossary](https://github.com/HeliosEstate/.github/blob/main/GLOSSARY.md).

## hadv-service

The engine, the board's server program.

### Part 1: Hello Helios Advance BBS

The engine's first layer accepts a Telnet caller, answers the caller's option requests, writes a
greeting and hangs up.

#### Starting

- When it starts, the engine shall listen for callers on the port and at the addresses the
  table below gives for the command-line options the sysop passed.
- When it is listening at every address, the engine shall write one `started` line to the local
  log naming the address and port of every listener.
- If a command-line option is malformed or the engine fails to listen at any address, then the
  engine shall write one line to the local log saying what failed and why, and exit with a
  non-zero code.
- If the engine fails to listen at an address or port, then the engine shall not listen at any
  other address or port in its place.
- If the engine is started as root on Linux, then the engine shall write one line to the local
  log saying so, and exit with a non-zero code.

| Command-line options passed | The engine listens on |
|---|---|
| none | port 23, at 127.0.0.1 and at ::1 |
| a port | that port |
| port 0 | a free port the operating system picks |
| one or more addresses | each address given, and no other |
| 0.0.0.0 and :: | every address of the server |

#### Negotiating with a caller

- When it accepts a caller, the engine shall offer the ECHO and SGA Telnet options on its side,
  and request no other Telnet option.
- When the caller has answered both requests with DO or DONT, or 3 seconds after sending them,
  whichever comes first, the engine shall end negotiation.
- If the caller asks, during negotiation, for a Telnet option the engine does not offer, then the
  engine shall refuse it as the table below gives.
- If the caller sends an option request, then the engine shall send at most one reply to it.
- If the caller sends a byte that is not part of an option request, such as typed text or a
  subnegotiation, then the engine shall discard it without reply.

| Caller sends | The engine replies |
|---|---|
| WILL, for any Telnet option | DONT, for that option |
| DO, for a Telnet option other than ECHO and SGA | WONT, for that option |

#### Greeting and closing

- When negotiation ends, the engine shall write `Hello Helios Advance BBS!` in ASCII followed by
  CR LF, whatever the caller answered, and no other text.
- When the greeting is written, the engine shall shut down its sending side of the connection.
- When the caller closes the connection, or 3 seconds after the engine shut down its sending
  side, whichever comes first, the engine shall close the connection.
- If the caller sends anything after negotiation ends, then the engine shall discard it without
  reply.
- If the caller drops the connection before the engine closes it, then the engine shall close its
  end of the connection and shall not write to it again.

#### Refusing a connection over the cap

- While 100 connections are open, the engine shall close each new connection at once, without
  writing to it.
- When a connection flood starts, the engine shall write one `refused` line to the local log.
- While a connection flood lasts, the engine shall write one line to the local log every 10
  seconds with the count of connections it refused in those 10 seconds.
- When a connection flood ends, the engine shall write one line to the local log saying so.

#### When accepting fails

- If accepting a caller at a listener fails, then the engine shall keep accepting callers at that
  listener.
- When accepting a caller at a listener fails, and no accept there has failed since the engine
  began listening there or since an accept there last worked, the engine shall write one
  `accept_failed` line to the local log naming the listener and the error.
- When accepting a caller at a listener succeeds after a failure there, the engine shall write one
  `accept_resumed` line to the local log naming the listener.

#### Stopping

- When it receives a stop signal the table below names, the engine shall stop accepting callers.
- When every open connection has closed after a stop signal other than closing the console
  window, or 10 seconds after that signal, whichever comes first, the engine shall exit with
  code 0.
- If it receives a second stop signal before it exits, then the engine shall close every open
  connection at once and exit with code 1.
- If the sysop closes its console window on Windows, then the engine shall close every open
  connection at once and exit.
- When it stops, the engine shall write one `stopped` line to the local log saying whether the
  stop was forced and how many connections it closed before they finished.

| Platform | Stop signals |
|---|---|
| Linux | Ctrl-C, terminate |
| Windows | Ctrl-C, terminate, Ctrl-Break, closing the console window |

#### What applies to all

- While one caller is silent or slow, the engine shall serve every other caller without waiting
  on that one.
- If 10 seconds pass since it accepted a connection, then the engine shall close that connection
  in whatever state it is in.
- The engine shall write its local log to standard output as `key=value` text, one line per
  event.
- When a connection event the table below names happens, the engine shall write its line to the
  local log with the fields the table gives.
- The engine shall not write anything a caller sent to the local log.

| Event | Line | Fields |
|---|---|---|
| a connection accepted | `accepted` | the source address, a connection ID |
| negotiation ended | `negotiated` | answered or timed out, the connection ID |
| a connection closed | `closed` | how it closed, the connection ID |

