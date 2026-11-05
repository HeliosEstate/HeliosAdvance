# Helios Advance BBS

A modern bulletin board system in the spirit of Virtual BBS and Virtual Advance. Go engine,
Lua scripting layer, Free Pascal tools. AGPL-3.0-only with the Scripting API Exception in
`LICENSE.exception`.

Nothing runs yet. `bash check.sh` is the only definition of green; see `CLAUDE.md`.

Questions about the project, and about how AI is used in it: [docs/faq.md](docs/faq.md).

## Running the tests

`bash check.sh` runs every check and every test, as CI does, in a clone whose `origin` remote has
`development` fetched (or with `BASE` naming the commit to judge from). It needs these on the
`PATH`:

- **Go**: the version in `go.mod`, or an older Go that downloads it.
- **PostgreSQL 16 or later**: its `initdb`, `pg_ctl`, `postgres` and `psql`. The tests make their
  own throwaway servers from these programs, so no PostgreSQL service needs to run. On Linux, a
  distribution's own package may be older than 16; PostgreSQL's own package repository has every
  supported version. On Windows, use the PostgreSQL project's signed installer for Windows; its
  service can stay stopped. On either, add the folder holding `initdb` to the `PATH`.
- **An OpenSSH client** (`ssh` and `ssh-keygen`) and **Plink**, from PuTTY: the outside clients
  the SSH and Telnet tests connect with.
- **On Linux, a `telnet` client**, for the Telnet test only Linux runs.
- **Free Pascal 3.2.2** (`fpc`), which builds the bootstrap file oracle the tests make every
  bootstrap file with. On Windows, put its folder after the one holding the system's C compiler on
  the `PATH`: it carries an old `gcc` of its own, which ahead of the system's breaks race builds.
- **On Linux, `setfacl`** (the `acl` package), for the key file's access-list rows.
- **The gate tools**, each by `go install` at the version pinned in `.github/tool-versions`, as CI
  installs them: `golangci-lint`, `govulncheck` and `go-licenses`.

The machine needs the IPv6 loopback address (`::1`) working, since the engine listens on it. On
Linux, run as an ordinary user, not root, where `sudo` needs no password (the rows named
`TestLinuxRoot…` use it) and ports below 1024 stay closed to ordinary users, as they are by
default.

On Windows, run `bash check.sh` from Git for Windows' bash, which brings the `ssh` and
`ssh-keygen` the tests run; the tests that need Linux are skipped there, and so are the rows named
`TestWindowsElevated…` unless bash runs elevated (as administrator), with a line saying so.

`bash check.sh --mutation` also runs mutation testing on what changed since `origin/development`.
It needs `gremlins`, at the version in `.github/tool-versions`, and runs on Linux only.
