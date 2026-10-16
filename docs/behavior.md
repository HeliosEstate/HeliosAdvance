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

#### Greeting a caller

- When it starts with no command-line option, the engine shall listen for callers on port 23.
- When it accepts a caller, the engine shall send WILL ECHO and WILL SGA, and no other option
  request.
- If the caller asks for a Telnet option other than ECHO and SGA, then the engine shall refuse it.
- The engine shall send at most one reply to each option request.
- If the caller sends anything that is not an option request, then the engine shall discard it
  without reply.

#### Ending the call

- When the caller has answered both option requests, or 3 seconds after the engine sent them,
  whichever comes first, the engine shall write `Hello Helios Advance BBS!` followed by CR LF,
  and no other text.
- When the greeting is written, the engine shall shut down its sending side of the connection.
- When the caller closes the connection, or 3 seconds after the engine shut down its sending
  side, whichever comes first, the engine shall close the connection.
- If 10 seconds pass since it accepted a connection, then the engine shall close that connection.

#### Callers at once

- While 100 connections are open, the engine shall close each new connection at once, without
  writing to it.
- While one caller is silent or slow, the engine shall serve every other caller without waiting
  on that one.

#### Where it listens

- The engine shall listen for callers at 127.0.0.1 and at ::1, and at no other address.
- When the sysop passes a port on the command line, the engine shall listen on that port in place
  of port 23.
- When the sysop passes port 0, the engine shall listen at each address on a free port the
  operating system picks.

#### Starting and stopping

- If the engine is started as root on Linux, then the engine shall write one `start_failed` line
  to the local log saying so, and exit with a non-zero code.
- When it receives a stop signal, the engine shall close every open connection at once and exit.

#### The local log

- When it is listening at every address, the engine shall write one `started` line to the local
  log naming the address and port of every listener.
- If a command-line option is malformed or the engine fails to listen at an address, then the
  engine shall write one `start_failed` line to the local log saying why, and exit with a
  non-zero code.
- The engine shall write no line to the local log other than `started` and `start_failed`.
- The engine shall write each line of the local log as one key and its value, `key=value`.
- The engine shall not write anything a caller sent to the local log.

