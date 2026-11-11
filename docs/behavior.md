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
which options it takes. The database's Part 1 makes it take its server's lease before it listens,
and adds two lines to the local log. The bootstrap's Part 1 names the bootstrap folder in place of
the connection file. The database's Part 2 reads which services it runs, and on which ports, from
its server's settings in place of the port option.

#### Greeting a caller

What the engine sends at accept, and which option requests it takes or refuses, are Part 4's
lines.

- When it takes its server's lease, the engine shall listen for Telnet callers only if its
  server's `telnet_on` is true, for SSH callers only if its `ssh_on` is true, and for Telnet over
  TLS callers only if its `telnets_on` is true.
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
- The engine shall listen for Telnet callers on its server's `telnet_port`.
- When a port setting is 0, the engine shall listen at each address on a free port the
  operating system picks.

#### Starting and stopping

- If the engine is started as root on Linux, then the engine shall write one `start_failed` line
  to the local log saying so, and exit with a non-zero code.
- When it receives a stop signal, the engine shall close every open connection at once and exit.

#### The local log

- When it has started listening, the engine shall write one `started` line to the local log
  naming the kind, address and port of everywhere it listens.
- If a command-line option is malformed, or the engine fails to listen at both addresses for a
  kind its server's settings turn on, then the engine shall write one `start_failed` line to the
  local log saying why, and exit with a non-zero code.
- The engine shall write no line to the local log other than `started`, `start_failed`,
  `waiting` and `lease_lost`.
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
that only a Telnet caller meets to a Telnet caller. Part 8 changes its line on the host key file's
mode. The database's Part 2 turns SSH on, and sets its port, from its server's settings.

#### Turning SSH on

- The engine shall listen for SSH callers at 127.0.0.1 and ::1 on its server's `ssh_port`,
  beside its other listeners.
- If the host key file is missing, unreadable, not in OpenSSH's format, protected by a passphrase
  or not an Ed25519 key, then the engine shall write one `start_failed` line saying which, and
  exit with a non-zero code.
- If, on Linux, the host key file's mode lets its group or others read or write it, then the
  engine shall write one `start_failed` line saying so, and exit with a non-zero code.

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
standard requires. It keeps nothing a caller's terminal reports. Part 8 changes its line on the
Synch, for a caller over TLS.

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
  as TCP urgent data on a plain Telnet connection and as an ordinary byte over TLS.
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

### Part 6: A Windows service and a Linux daemon

The engine runs as a Windows service and as a Linux daemon under systemd, and tells each service
manager when it is ready. Its local log goes to standard output, or to a log file the sysop names
on the command line. Every earlier line holds when a service manager runs the engine. The
database's Part 2 makes its two lines on port 23 hold when its server's settings turn Telnet on
there.

#### Under Windows' service manager

- When Windows' service manager starts it as the service `hadv-service`, the engine shall report
  running once every listener it was asked for is listening, or once it first writes a `waiting`
  line, and not before.
- When the service manager sends stop or shutdown, the engine shall close every open connection
  at once, report stopped and exit.
- If the engine writes a `start_failed` line while running as a service, then the engine shall
  report stopped with a non-zero exit code.
- If Windows' service manager starts it with no log file on the command line, then the engine
  shall report stopped with a non-zero exit code, listening nowhere.
- When Windows' service manager starts it as `NT SERVICE\hadv-service` and its server's
  settings turn Telnet on at port 23, the engine shall listen for Telnet callers on port 23.

#### Under systemd

- When systemd starts it and names a socket for readiness (`NOTIFY_SOCKET`), the engine shall
  send `READY=1` there once every listener it was asked for is listening, or once it first writes
  a `waiting` line, and not before.
- When systemd starts it as an ordinary user holding no capability but the right to bind ports
  below 1024, and its server's settings turn Telnet on at port 23, the engine shall listen for
  Telnet callers on port 23.

#### The local log

- The engine shall write the local log to standard output or, when the sysop passes a log file on
  the command line, appended to that file.
- If opening the log file for appending fails, then the engine shall write one `start_failed`
  line to standard output saying so, and exit with a non-zero code.
- When, on Linux, the engine creates the log file, the engine shall create it readable and
  writable by its own account alone.

### Part 7: End of file before the shell

An SSH caller that sends end of file before it asks for a shell is still answered when it asks:
what it sent before the end of file is read in order, and when the name has not ended by then, the
call ends at the end of file. Part 7 changes one of Part 3's lines, on the connection.

#### End of file

- If an SSH caller's data ends, by end of file, before the name ends, then, once the caller has
  asked for a shell and the greeting and name prompt are written, the engine shall close the
  connection when it reaches the end of file, writing nothing more but the channel close SSH
  requires in reply.

### Part 8: Telnet over TLS

The engine also takes Telnet callers over TLS, on a listener of its own, when the sysop gives it a
certificate and its key, and serves them inside the encrypted channel as it serves a Telnet
caller. Every earlier line that names a Telnet caller stands for a Telnet over TLS caller, inside
the channel. Part 8 changes one of Part 4's lines, on the Synch, and one of Part 3's, on the host
key file's mode. The database's Part 2 turns Telnet over TLS on, and sets its port, from its
server's settings.

#### Turning Telnet over TLS on

- The engine shall listen for Telnet over TLS callers at 127.0.0.1 and ::1 on its server's
  `telnets_port`, beside its other listeners.
- If either file is missing, unreadable or not PEM, or the key is protected by a passphrase, does
  not match the certificate, or is not RSA of 2048 bits or more, ECDSA P-256 or P-384, or Ed25519,
  then the engine shall write one `start_failed` line saying which, and exit with a non-zero code.
- If, on Linux, the key file's mode lets its group or others read or write it, then the engine
  shall write one `start_failed` line saying so, and exit with a non-zero code.

#### The two files' checks

- If a certificate block in the certificate file holds no certificate, the chain's later blocks
  included, then the engine shall write one `start_failed` line saying so, and exit with a
  non-zero code.
- If the certificate file holds a private key, then the engine shall write one `start_failed`
  line saying so, and exit with a non-zero code.
- If either file's path names anything but a regular file, or the file is longer than 65,536
  bytes, then the engine shall write one `start_failed` line saying so, and exit with a non-zero
  code.

#### The handshake

- The engine shall offer TLS 1.3 and TLS 1.2, and no other version.
- The engine shall offer, in TLS 1.3, only `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384` and
  `TLS_CHACHA20_POLY1305_SHA256`, and in TLS 1.2 only ECDHE with an ECDSA or RSA certificate and
  `AES_128_GCM_SHA256`, `AES_256_GCM_SHA384` or `CHACHA20_POLY1305_SHA256`.
- The engine shall offer only the key exchanges X25519MLKEM768, SecP256r1MLKEM768,
  SecP384r1MLKEM1024, X25519, P-256, P-384 and P-521.
- The engine shall send the certificate file's whole chain, ask for no client certificate, and
  refuse renegotiation and session resumption.
- If a Telnet over TLS caller's handshake fails, then the engine shall close the connection,
  writing no Telnet byte to it.

#### The same call over TLS

- When a Telnet over TLS caller's handshake completes, the engine shall serve it inside the
  encrypted channel as it serves a Telnet caller it has just accepted.
- When `Hello <name>` is written to a Telnet over TLS caller, the engine shall send TLS's
  close_notify before it shuts down its sending side of the connection.
- If a write to a Telnet over TLS caller has failed before its call is closed, then the engine
  shall send that caller no close_notify, and shall still shut down its sending side of the
  connection.
- If a Telnet over TLS caller sends close_notify or a damaged record, then the engine shall close
  the connection.
- The engine shall count Telnet over TLS callers among the 100 open connections, with its Telnet
  and SSH callers.

#### Nothing kept

- The engine shall not store, log or show anything a caller sends in its handshake, the server
  name it asks for among them.
- The engine shall not write any part of the private key to the local log.

## database

The board's database, PostgreSQL: the single source of truth every server shares, and where the
servers meet.

### Part 1: Connecting and the lease

The engine connects to its database, signs in, checks the schema version and its server's row,
and holds its server's lease while it listens. Where the database is and how to sign in come from
the bootstrap file, in the bootstrap folder named on the command line (the bootstrap's Part 1).
Part 1 changes two of hadv-service Part 1's lines, on starting and on the local log. Part 2
changes two of its lines, on the schema version and on waiting.

#### The connection settings

- If it starts without a bootstrap folder on the command line, then the engine shall write one
  `start_failed` line saying so, and exit with a non-zero code.
- If the JSON object the bootstrap file seals is not in its format, or is missing a field or holds
  one the format does not name, then the engine shall write one `start_failed` line saying which,
  and exit with a non-zero code.
- The engine shall take where it connects, its login and its password from the bootstrap file
  alone.
- The engine shall not write the bootstrap file's password, or the key in the key file, to the
  local log.

#### Signing in

- The engine shall connect to the database only over TLS, and sign in only by SCRAM-SHA-256 with
  channel binding, under the login the bootstrap file names.
- If the database's certificate does not chain to the certificate authority in the bootstrap file
  or does not name the file's host, the database asks for any other way of signing in, or it
  refuses the sign-in, then the engine shall write one `start_failed` line saying which, and exit
  with a non-zero code.
- If its login holds any right on the database beyond those each part grants a server's login,
  or the power to take one, then the engine shall write one `start_failed` line saying so, and
  exit with a non-zero code.
- If the database refuses for any other reason, then the engine shall write one `start_failed`
  line saying so, and exit with a non-zero code.

#### The schema version and the server's row

- If `hadv.schema_version` is missing or holds a version other than 2 or 3, then the engine
  shall write one `start_failed` line naming the version it found, and exit with a non-zero code.
- If `hadv.servers` holds no row for the bootstrap file's server ID, then the engine shall write
  one `start_failed` line saying so, and exit with a non-zero code.

#### Waiting for the database

- If the database does not answer, or answers that it is starting up, shutting down or
  recovering, that it has no connection free, that it is read-only, that it cancelled the
  statement, that a lock was not available, that a clash with another transaction stopped it, or
  that its disk or memory ran out, then the engine shall write one `waiting` line saying which,
  listen nowhere, and try again every 10 seconds.
- If its server's lease has not ended and its lease holder is not this run's own, then the engine
  shall write one `waiting` line saying so, listen nowhere, and try again every 10 seconds.
- The engine shall listen for callers only while it holds its server's lease.

#### The lease

- When it takes its server's lease, the engine shall write a new random lease holder and a lease
  end 30 seconds after the database's current time to its server's row, only if that row's lease
  has ended or its lease holder is this run's own.
- While it holds its server's lease, the engine shall renew it every 10 seconds, writing a lease
  end 30 seconds after the database's current time, only while the row's lease holder is its own.
- If 25 seconds pass after it sent its last take or renewal that succeeded, or a renewal finds the
  lease holder is not its own, then the engine shall close every open connection and every
  listener, write one `lease_lost` line, and try to take the lease again every 10 seconds.
- When it receives a stop signal while it holds its server's lease, the engine shall set the
  lease end to the database's current time before it exits, unless the database does not answer.

### Part 2: Per-server settings

Each server's settings, which of Telnet, SSH and Telnet over TLS it runs and on which ports, are
stored in its row of `hadv.servers` and read each time it takes its lease, in place of the port
options on the command line. A new row takes the defaults: every service off, each on its usual
port. Part 2 also ends the lease at a stop after the database ended the lease's connection, and at
a refusal to start after the lease is taken. It changes lines of hadv-service Parts 1, 3, 6 and 8
and of the database's Part 1, and removes Part 3's line on an SSH port option and Part 8's on a
Telnet over TLS port option.

#### Which services run

- When it takes its server's lease, the engine shall listen as its server's settings stand at that
  moment, until it next takes the lease.
- If a setting it reads is empty, not of its kind, or a port outside 0 to 65535, then the engine
  shall write one `start_failed` line naming the setting, and exit with a non-zero code.
- If its server's `ssh_on` is true and the command line names no SSH host key file, or its
  `telnets_on` is true and the command line does not name both a TLS certificate file and its key
  file, then the engine shall write one `start_failed` line saying which, and exit with a non-zero
  code.
- When it takes its server's lease and its server's settings turn no service on, the engine shall
  write one `started` line saying it listens nowhere.

#### Ending the lease

- When it receives a stop signal while it holds its server's lease, after the database has ended
  the connection the lease was taken or last renewed over, the engine shall still set the lease end
  to the database's current time before it exits, unless the database does not answer.
- If it writes a `start_failed` line after it has taken its server's lease, then the engine shall
  set the lease end to the database's current time before it exits, unless the database does not
  answer.

## bootstrap

The bootstrap folder: the encrypted bootstrap file that tells the engine where its database is and
how to sign in, and the key file holding the key it is sealed under.

### Part 1: The bootstrap file and its key file

The engine opens the bootstrap folder named on its command line, checks the key file's owner and
permissions, and unseals the bootstrap file with the key in the key file. Part 1 changes one of
hadv-service Part 1's lines and several of the database's Part 1, on where the connection
settings come from.

#### The bootstrap folder

- If the bootstrap folder is missing or unreadable, or the bootstrap file or the key file in it
  is missing, unreadable or a link leading out of the bootstrap folder, then the engine shall
  write one `start_failed` line saying which, and exit with a non-zero code.
- If the bootstrap file is over 64 KiB, then the engine shall write one `start_failed` line
  saying so, and exit with a non-zero code.

#### The key file's checks

- If, on Linux, the key file's mode gives its group or others any access, then the engine shall
  write one `start_failed` line saying so, and exit with a non-zero code.
- If, on Windows, the key file's owner, or any entry of its access list that allows access, names
  anyone but SYSTEM, Administrators or the account the engine runs as, or the key file has no
  access list, then the engine shall write one `start_failed` line saying so, and exit with a
  non-zero code.
- If the engine is unable to confirm that no account but those above has access to the key
  file, such as on Windows an access-list entry of a kind it does not judge, then the engine shall
  write one `start_failed` line saying so, and exit with a non-zero code.
- If the key file is not in the key file's form, or holds a key of 32 zero bytes, then the engine
  shall write one `start_failed` line saying so, and exit with a non-zero code.

#### The bootstrap file

- If the bootstrap file's header is not format version 1's for the key file, or the bootstrap
  file is too short for its header, nonce and tag, then the engine shall write one `start_failed`
  line saying so, without reading the key file, and exit with a non-zero code.
- If the bootstrap file does not unseal under the key in the key file, then the engine shall
  write one `start_failed` line saying so, and exit with a non-zero code.
