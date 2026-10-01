---
name: design-unit
description: Design one unit of the skeleton with the developer, one question at a time, into a Pascal interface section they approve and a locked Go contract. Use when the developer says /design-unit <Name> or asks to design, interview or draft a unit, contract or package.
---

# Design a unit

The process that produced the skeleton on 2026-09-30. The developer decides; you draft,
ask, and transliterate. One unit per session.

## Before the first question

Read, in this order: `docs/architecture.md`; every `internal/*/contract.go`; the brief
under HeliosDesign `features/` the unit serves, if one exists; the backlog entry if not.
Say in one line what you read. Do not read either failed attempt's code or specs.

## The interview

- One question per turn. Each question carries your draft answer, so a "yes" is enough.
  The developer corrects the draft; you never argue past one stated reason.
- Question 1 is always the boundary: what the unit owns, and what it does not, named by
  the units that own it instead.
- Then, in whatever order the unit needs: identity and the types that cross its edge; the
  operations, by who calls them; failure, including a database failure, which is never a
  default; collisions and idempotence; what other units read from it.
- Where the developer's own rule decides something (board-wide unless it describes the
  server's hardware; the model originates no work), cite the rule and apply it.
- A question the developer answers with a new fact about the design is recorded in the
  draft's comment, with their words where the phrasing is theirs.

## The draft

A Pascal unit, interface section only, `implementation end.` closing it: a unit comment
that says what it owns and does not, a `uses` list of other units with one comment each,
types, and one `interface` type whose methods carry the why. Verbs from PowerShell's
approved list where a pair exists; reads with no `Get`; `Acquire`/`Release` are ours.
Name every decision you made without a ruling under the draft, each reversible. Show it
whole and wait for "approved".

## After approval

1. `internal/<unit>/contract.go`: the Go, comment for comment, `context.Context` for
   `IDeadline`, `error` for exceptions, `database.ErrUnavailable` named in the package
   comment. Shared identifiers go in `internal/board`, never imported from a peer.
2. The Pascal to HeliosDesign `records/skeleton/<Unit>.pas` with the approval date and
   the question count at the top; commit and push there.
3. `docs/architecture.md`: the unit's row and any new arrow in words.
4. `.golangci.yml`: the unit's `depguard` rule from what the Go actually imports.
5. `bash check.sh` on its own exit code, never through a pipe. Green or it does not go up.
6. Branch `skeleton/<unit>` off `development`, commit as the developer, PR with the body
   shape from `CLAUDE.md`, wait for CI, hand over `gh signoff <pr> HeliosAdvance`, and
   start a watcher that pulls and cleans up when it merges.

A transliteration that exposes a cycle or a missing type is a finding, not a workaround:
say what it exposed, fix it in the same PR, and name the fix as yours.
