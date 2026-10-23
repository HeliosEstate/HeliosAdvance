# Behavior

This page describes what Helios Advance BBS does, as a sysop, a caller or a test on the real
system sees it. Each line says what the engine shall do; how it does it is left out. Words in
these lines have the meanings given in the estate's
[glossary](https://github.com/HeliosEstate/.github/blob/main/GLOSSARY.md).

## hadv-service

The engine, the board's server program.

### Part 1: Hello Helios Advance BBS

The engine's first layer accepts a Telnet caller, answers the caller's option requests, writes a
greeting and hangs up. Part 2 replaces how it ends a call.

#### Greeting a caller

- When it starts with no command-line option, the engine shall listen for callers on port 23.
- When it accepts a caller, the engine shall send WILL ECHO and WILL SGA, and no other option
  request.
- If, during negotiation, the caller asks for a Telnet option other than ECHO and SGA, then the
  engine shall refuse it.
- The engine shall send at most one reply to each option request.
- If, during negotiation, the caller sends anything that is not an option request, then the
  engine shall discard it without reply.

#### Ending the call

What the engine writes after negotiation, and when it gives up on a call, are Part 2's lines.

- When the caller closes the connection, or 3 seconds after the engine shut down its sending
  side, whichever comes first, the engine shall close the connection.

#### Callers at once

- While 100 connections are open, the engine shall close each new connection at once, without
  writing to it.
- While one caller is silent or slow, the engine shall serve every other caller without waiting
  on that one.
- If accepting a caller fails, then the engine shall keep serving its open connections and accept
  again within 1 second.
- If accepting a caller fails, then the engine shall wait at least 5 milliseconds before it
  accepts again.

#### Where it listens

- The engine shall listen for callers at 127.0.0.1 and at ::1, and at no other address.
- If the engine fails to listen at one of 127.0.0.1 and ::1, then the engine shall listen at the
  other alone.
- When the sysop passes a port on the command line, the engine shall listen on that port in place
  of port 23.
- When the sysop passes port 0, the engine shall listen at each address on a free port the
  operating system picks.

#### Starting and stopping

- If the engine is started as root on Linux, then the engine shall write one `start_failed` line
  to the local log saying so, and exit with a non-zero code.
- When it receives a stop signal, the engine shall close every open connection at once and exit.

#### The local log

- When it has started listening, the engine shall write one `started` line to the local log
  naming the address and port of every listener.
- If a command-line option is malformed or the engine fails to listen at both addresses, then the
  engine shall write one `start_failed` line to the local log saying why, and exit with a
  non-zero code.
- The engine shall write no line to the local log other than `started` and `start_failed`.
- The engine shall write each line of the local log as one key and its value, `key=value`.
- The engine shall not write anything a caller sent to the local log.

### Part 2: What is your name?

After negotiation the engine greets the caller, asks their name, reads it and answers with it,
then hangs up. The layer that asks and answers is the one SSH will share.

#### Asking the name

- When the caller has answered both option requests, or 3 seconds after the engine sent them,
  whichever comes first, the engine shall write `Hello Helios Advance BBS!` and CR LF, then
  `What is your name? `.
- When the caller ends the name with CR or LF, the engine shall write `Hello `, the name and
  CR LF.
- If the caller sends anything after the name ends, then the engine shall discard it without
  reply.
- When `Hello <name>` is written, the engine shall shut down its sending side of the connection.
- If the caller has not ended the name 60 seconds after the engine wrote `What is your name? `,
  then the engine shall close the connection without writing more.

#### What a name may hold

- When the caller sends a character from space to tilde (0x20 to 0x7E) and the name holds fewer
  than 30, the engine shall add it to the name.
- Apart from BS, DEL, CR and LF, the engine shall drop every other byte the caller sends after
  negotiation, and every character past the 30th.
- If the caller sends a Telnet command after negotiation ends, then the engine shall discard it
  without reply.

#### The echo

- While the caller has agreed to ECHO, the engine shall echo each character it adds to the name,
  write BS, space, BS for each it removes, and write CR LF when the name ends.
- If the caller did not agree to ECHO during negotiation, then the engine shall echo nothing.

#### Correcting a name

- When the caller sends BS or DEL while the name holds a character, the engine shall remove the
  last character.
- If the caller sends BS, DEL, CR or LF while the name is empty, then the engine shall write
  nothing and keep waiting.

#### The whole call

- If 70 seconds pass since it accepted a connection, then the engine shall close that connection.
