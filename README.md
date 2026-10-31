# Helios Advance BBS

A modern bulletin board system in the spirit of Virtual BBS and Virtual Advance. Go engine,
Lua scripting layer, Free Pascal tools. AGPL-3.0-only with the Scripting API Exception in
`LICENSE.exception`.

Nothing runs yet. `bash check.sh` is the only definition of green; see `CLAUDE.md`.

Questions about the project, and about how AI is used in it: [docs/faq.md](docs/faq.md).

## Running the tests

`bash check.sh` runs every check and every test, as CI does. It needs these on the `PATH`:

- **Go**, at the version in `go.mod`.
- **PostgreSQL 16 or later**: its `initdb`, `pg_ctl`, `postgres` and `psql`. The tests make their
  own throwaway servers from these programs, so no PostgreSQL service needs to run. On Linux,
  install it from your distribution's packages. On Windows, use the PostgreSQL project's signed
  installer for Windows; its service can stay stopped. Add its `bin` folder to the `PATH`.
- **An OpenSSH client** (`ssh`) and **Plink**, the outside clients the SSH and Telnet tests
  connect with. Plink comes with PuTTY: on Linux its tools package, on Windows its installer.
- **On Linux, a `telnet` client**, for the Telnet test only Linux runs.
- **The gate tools**, at the versions pinned in `.github/tool-versions`: `golangci-lint` (its
  released binary), `govulncheck` and `go-licenses`. `check.sh` names how to install any that is
  missing.

On Windows, run `bash check.sh` from Git for Windows' bash. Its own `ssh` is the one the tests
expect, and the tests that need Linux are skipped there.

`bash check.sh --mutation` also runs mutation testing on what changed since `origin/development`.
It needs `gremlins`, at the version in `.github/tool-versions`, and runs on Linux only.
