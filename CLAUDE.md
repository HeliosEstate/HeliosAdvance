# CLAUDE.md

Helios Advance BBS: a modern BBS in the spirit of VBBS and VADV. Go engine, Lua scripting,
Free Pascal tools. One developer; the design record is the private `HeliosEstate/HeliosDesign`
(its `handoff.md` holds the six invariants; `records/research/` the evidence behind them).

## Commands

- `bash check.sh` is the only definition of green. CI, the Stop hook and the loop all run it.
  `bash check.sh --mutation` adds mutation testing of the diff against `$BASE`
  (default `origin/development`). `RACE=-race` needs a C compiler; CI sets it.
- Branches: `main` holds the skeleton and releases; `development` is integration; work is
  `feature/issue-<n>-<slug>` off `development`, one worktree each; every change is a PR.

## Roles, mechanically

- A QA session commits approved tests with the trailer `Helios-Role: qa`. From that commit on,
  `check.sh` refuses any change or deletion to a `*_test.go` that existed then, and refuses a
  later test file that declares `TestMain`, `init` or a build tag.
- `docs/spec/`, `docs/architecture.md`, `features/`, `automation/`, `.github/` and every `contract.go` are developer-owned: a
  commit authored as a `[bot]` may not touch them. `docs/spec/` names no language, path or library.
- A loop session (`HELIOS_LOOP=1`) is denied those edits by a hook and is ended by the Stop
  hook after three red runs of `check.sh`, leaving `.helios-stop-red` for the loop.
- A loop claims an issue with `claimed:<its name>`; two loops racing are settled by label
  event order, the earlier wins. Each loop is its own App and its own name.

## The PR body

Decisions first, one line each. What changed, in three or four lines. One line per check with
its result; anything that failed, in full. A "Noticed, not touched" list for anything seen
outside the task. A change outside the task is listed under its own heading with a reason,
or the PR is wrong.

## Out of road

Locked tests still red, a spec gap, or a question: push the branch, comment on the issue
with the failing output in full and the question, add `human-action-required`, stop. Never
edit a test to make it pass; never guess at a spec gap; never file new work.

## Conventions a linter cannot see

- Every goroutine has an owner and stops when its context ends; shutdown drains.
- An error is returned or logged, never both; no panic crosses a package boundary.
- An interface is declared where it is consumed and has the methods its consumer calls.
- Anything read from a network or a file has a size bound.
- A comment says why (a constraint, a unit, a gotcha, a magic value's source); never what,
  never a step number, never a line number, never a bare pointer to a spec.
- Public text, code to comments, describes another program only by its documentation and its
  observed behaviour, never its code, file names or internal names.
- Names read without knowing abbreviations, Pascal-verbose: `sessionID`, not `sid`. An
  abbreviation passes only if everyone knows it, not only Go developers (`rw`, `tx`, `fd`); `tools/namecheck` fails
  anything under three characters off its list. Flag names on a command line may be short.
- A method is a verb: PowerShell's approved-verb list is the first place to look for a
  pair; reads follow Go style, no `Get`; `Acquire`/`Release` are ours.
- Tests are table-driven, real sockets and temp files, no mocks, no sleeps; each row names the
  spec line it proves.
- A defect met inside a task is fixed only if the file is already in the task, with its own
  test, and listed in the PR body; anything else is a "Noticed, not touched" line.

Everything else that is a rule is a check in `check.sh` or `.golangci.yml`, or it is not a rule.
