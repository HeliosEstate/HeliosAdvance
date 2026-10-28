# Behavior

This page describes what Helios Advance BBS does, as a sysop, a caller or a test on the real
system sees it. Each line says what the engine shall do; how it does it is left out. Words in
these lines have the meanings given in the estate's
[glossary](https://github.com/HeliosEstate/.github/blob/main/GLOSSARY.md).

## hadv-service

The engine, the board's server program.

### Part 1: Hello Helios Advance BBS

The engine's first layer accepts a Telnet caller, answers the caller's option requests, writes a
greeting and hangs up. Part 2 replaces how it ends a call, and Part 4 what it sends at accept and
which options it takes.

#### Greeting a caller

What the engine sends at accept, and which option requests it takes or refuses, are Part 4's
lines.

- When it starts with no command-line option, the engine shall listen for Telnet callers on port
  23, and for no SSH or Telnet over TLS caller.
- The engine shall send at most one reply to each option request.
- If, during negotiation, the caller sends anything that is not an option request, AYT, AO or IP,
  then the engine shall discard it without reply.

#### Ending the call

What the engine writes after negotiation, and when it gives up on a call, are Part 2's lines.

- When a Telnet caller closes the connection, or 3 seconds after the engine shut down its
  sending side, whichever comes first, the engine shall close the connection.

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
- When the sysop passes a Telnet port on the command line, the engine shall listen on that port
  in place of port 23.
- When the sysop passes port 0, the engine shall listen at each address on a free port the
  operating system picks.

#### Starting and stopping

- If the engine is started as root on Linux, then the engine shall write one `start_failed` line
  to the local log saying so, and exit with a non-zero code.
- When it receives a stop signal, the engine shall close every open connection at once and exit.

#### The local log

- When it has started listening, the engine shall write one `started` line to the local log
  naming the kind, address and port of everywhere it listens.
- If a command-line option is malformed, or the engine fails to listen at both addresses for
  Telnet or, when SSH or Telnet over TLS is on, for that kind, then the engine shall write one
  `start_failed` line to the local log saying why, and exit with a non-zero code.
- The engine shall write no line to the local log other than `started` and `start_failed`.
- The engine shall write each line of the local log as one key and its value, `key=value`.
- The engine shall not write anything a caller sent to the local log.

### Part 2: What is your name?

After negotiation the engine greets the caller, asks their name, reads it and answers with it,
then hangs up. The layer that asks and answers is the one SSH shares, from Part 3.

#### Asking the name

- When a Telnet caller has answered all eight opening requests, or 3 seconds after the engine
  sent them, whichever comes first, the engine shall write `Hello Helios Advance BBS!` and CR LF,
  then `What is your name? `.
- When the caller ends the name with CR or LF, the engine shall write `Hello `, the name and
  CR LF.
- If the caller sends anything after the name ends, then the engine shall discard it without
  reply.
- When `Hello <name>` is written to a Telnet caller, the engine shall shut down its sending side
  of the connection.
- If the caller has not ended the name 60 seconds after the engine wrote `What is your name? `,
  then the engine shall close the connection without writing more.

#### What a name may hold

- When the caller sends a character from space to tilde (0x20 to 0x7E) and the name holds fewer
  than 30, the engine shall add it to the name.
- Apart from BS, DEL, Ctrl-U, CR and LF, the engine shall drop every other byte the caller sends
  after negotiation or, over SSH, after `shell`, and every character past the 30th.
- After negotiation ends and until a Telnet caller's name ends, the engine shall answer each
  option request as it did during negotiation, and each other Telnet command as Part 4's lines
  under "Commands" say.

#### The echo

- While a Telnet caller has agreed to ECHO, the engine shall echo each character it adds to the
  name, write BS, space, BS for each it removes, and write CR LF when the name ends.
- While a Telnet caller has not agreed to ECHO, the engine shall echo nothing.

#### Correcting a name

- When the caller sends BS or DEL while the name holds a character, the engine shall remove the
  last character.
- If the caller sends BS, DEL, Ctrl-U, CR or LF while the name is empty, then the engine shall
  write nothing and keep waiting.

#### The whole call

- If 70 seconds pass since it accepted a connection, then the engine shall close that connection.

### Part 3: SSH on the shared session layer

The engine also takes SSH callers, when the sysop gives it a host key, and serves them the same
call as Telnet callers: the greeting, the name and the answer. Part 3 narrows the earlier lines
that only a Telnet caller meets to a Telnet caller.

#### Turning SSH on

- When the sysop passes an SSH host key file on the command line, the engine shall listen for SSH
  callers at 127.0.0.1 and ::1 on port 22, beside its Telnet listener.
- When the sysop passes an SSH port on the command line as well, the engine shall listen for SSH
  callers on that port in place of port 22.
- If the host key file is missing, unreadable, not in OpenSSH's format, protected by a passphrase
  or not an Ed25519 key, then the engine shall write one `start_failed` line saying which, and
  exit with a non-zero code.
- If, on Linux, the host key file's mode lets its group or others read it, then the engine shall
  write one `start_failed` line saying so, and exit with a non-zero code.

#### The same call over SSH

- When an SSH caller has signed in and asked for a shell, the engine shall write
  `Hello Helios Advance BBS!` and CR LF, then `What is your name? `.
- While an SSH caller has asked for a terminal, the engine shall echo as it does for a Telnet
  caller that agreed to ECHO.
- While an SSH caller has not asked for a terminal, the engine shall echo nothing.
- When `Hello <name>` is written to an SSH caller, the engine shall send exit status 0 and end of
  file, and close the channel.
- When an SSH caller closes the connection, or 3 seconds after the engine closed the channel,
  whichever comes first, the engine shall close the connection.

#### Before the shell

- The engine shall send the version line `SSH-2.0-HeliosAdvance` and CR LF.
- The engine shall offer only the key exchanges `mlkem768x25519-sha256`, `curve25519-sha256` and
  `curve25519-sha256@libssh.org` with the marker `kex-strict-s-v00@openssh.com`, the ciphers
  `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com` and `aes128-gcm@openssh.com`, the MAC
  `hmac-sha2-256-etm@openssh.com`, compression `none` and an `ssh-ed25519` host key.
- When an SSH caller offers strict key exchange, the engine shall use it.
- The engine shall accept the sign-in method `none` under any username.
- If an SSH caller tries any sign-in method but `none`, then the engine shall close the
  connection.

#### On the connection

- The engine shall accept the first `session` channel on a connection, and refuse every other
  channel.
- The engine shall accept `pty-req` and `shell` on the session channel until the first `shell`,
  and refuse every other channel request and every global request.
- The engine shall discard everything an SSH caller sends as extended data.
- If an SSH caller closes the channel before the name ends, then the engine shall close the
  connection, writing nothing more but the channel close SSH requires in reply.

#### Nothing kept

- The engine shall not store, log or show the SSH username, nor anything a `pty-req` carries.
- The engine shall not write any part of the host key to the local log.

### Part 4: The rest of the Telnet server

The engine negotiates the rest of the Telnet options a caller's terminal uses, BINARY in both
directions and the options that describe the terminal, and answers the Telnet commands the
standard requires. It keeps nothing a caller's terminal reports.

#### Opening

- When it accepts a Telnet caller, the engine shall send IAC WILL ECHO, IAC WILL SGA, IAC WILL
  BINARY, IAC DO BINARY, IAC DO TTYPE, IAC DO NAWS, IAC DO NEW-ENVIRON and IAC DO TSPEED, in that
  order, and no other option request.
- The engine shall answer requests about ECHO, SGA and BINARY on its own side, and about SGA,
  BINARY, TTYPE, NAWS, NEW-ENVIRON and TSPEED on the caller's side, by RFC 1143's rules.
- If the caller sends WILL for a Telnet option other than SGA, BINARY, TTYPE, NAWS, NEW-ENVIRON
  and TSPEED, or DO for one other than ECHO, SGA and BINARY, then the engine shall refuse it, WILL
  with DONT and DO with WONT.
- When the caller agrees to TTYPE or TSPEED, the engine shall send that option's SEND, at most
  once in the call.
- When the caller agrees to NEW-ENVIRON, the engine shall send SEND for the variable USER alone,
  at most once in the call.

#### Commands

- When a Telnet caller sends AYT before its name ends, the engine shall write CR LF, `[Yes]` and
  CR LF.
- When a Telnet caller sends AO or IP before its name ends, the engine shall send IAC DM, with DM
  as TCP urgent data.
- When a Telnet caller sends EC after negotiation and before its name ends, the engine shall do
  as it does for BS.
- When a Telnet caller sends EL after negotiation and before its name ends, the engine shall
  remove every character of the name, writing BS, space, BS for each while it echoes.
- When a Telnet caller sends DM, NOP, GA, BRK, EOR or any other command, the engine shall discard
  it without reply, and discard none of the data before it.

#### Erasing a name

- When the caller sends Ctrl-U (0x15) while the name holds a character, the engine shall remove
  every character of the name.

#### Nothing kept

- The engine shall not store, log or show anything a caller sends inside a subnegotiation.
- The engine shall write the same to a caller, whatever it sends inside a subnegotiation.

### Part 7: End of file before the shell

An SSH caller that sends end of file before it asks for a shell is still answered when it asks:
what it sent before the end of file is read in order, and when the name has not ended by then, the
call ends at the end of file. Part 7 changes one of Part 3's lines, on the connection.

#### End of file

- If an SSH caller's data ends, by end of file, before the name ends, then, once the caller has
  asked for a shell and the greeting and name prompt are written, the engine shall close the
  connection when it reaches the end of file, writing nothing more but the channel close SSH
  requires in reply.
