# CLAUDE.md

Helios Advance BBS: a modern BBS. Go engine, Lua scripting, Free Pascal tools. One developer.
These rules bind every session in this repository, the loop's included. The six invariants they
rest on are the developer's record, `records/invariants.md` in HeliosDesign, and outrank them.

## Correctness before merge

The developer's words, from his own rules:
These rules outrank finishing the task, keeping work moving and reaching a merge. A green check,
an approved plan or a passing test never excuses breaking one. When a rule here conflicts with
getting the task done, the rule wins and you stop.

- A rule, label or check means what it was written for, not what a tool happens to enforce. When
  the enforcement is narrower than the rule, the rule still holds in full: never use the gap.
  Report the gap to the developer in the same turn you find it.
- `needs-developer` on an issue or its PR stops all coding on it (no build, no review round, no
  push to its branch or pull request) until the developer has decided what it flags. Reviews,
  comments, change requests and throwaway probe branches that only gather facts for his decision
  may go on; a probe branch is deleted afterwards and reported to him. The label comes off only on
  his approval.
- Dismiss a finding ("harmless", "impossible", "never") only on evidence checked for this exact
  case. "Nobody has seen it", "the library does the same" and "unlikely" are not evidence. If it
  can be probed, probe it before the verdict; if it cannot, the verdict is "unknown", with a
  record and a trigger.
- Never ask the developer to approve something he has not had explained. Name every issue, PR,
  commit or change by what it is, in plain words, before any number. A yes to an unexplained
  number is not approval.
- Say what you will change before you change it: his repositories, his machines, his key stores,
  the loops' work. Anything changed without that is reported to him at once, as a mistake, in
  plain words.
- When a quick way past a check, a label, a review finding or a question appears, treat it as the
  signal to stop and ask.

## Commands

- `bash check.sh` is the only definition of green; CI, the loop's stop hook and a session before
  it hands work over all run it. It needs its base: `BASE` names the commit to judge from
  (default `origin/development`). A gate that cannot run fails. `bash check.sh --mutation` adds
  mutation testing of the diff. `RACE=-race` needs a C compiler; CI sets it.
- `development` is the default branch and integration; `main` holds releases. Work is
  `feature/issue-<n>-<slug>` off `development`, and every change is a pull request.

## Roles, mechanically

- A session opens issues, comments and reviews as the estate's App, `helios-aegle`, never as the
  developer: the loop takes his account's words as his. A design session may commit specs, docs
  and CI from his account, each commit and pull request saying a Claude session wrote it; the
  loop's code never comes from his account. His approval is the review and merge he gives on
  GitHub, and only he gives it.
- The paths in `developer-owned-paths` change only by pull request on his review. A loop session
  is refused those edits by its own hooks, and `check.sh` refuses a commit to them by any login in
  `loop-identities`. A QA session's commit carries the trailer `Helios-Role: qa`; from it on,
  `check.sh` refuses a change to a test file that existed then, and a later test file that
  declares `TestMain`, `init` or a build tag.
- An issue comes from the developer or from a design session as the App; `ready` counts only
  when the developer added it. The loop claims an issue with `claimed:<its App>`.

## The PR body

Decisions, one line each, implementation decisions only: a decision that would change a line,
fill a contract gap, pick an oracle or settle where a test runs is out of road. What changed, in a
few lines. Tests added, under their own heading. Changes outside the task, each with its reason,
or the PR is wrong. One line per check with its result; anything that failed, in full. Only an
item that needs the developer's decision goes under "Noticed, not touched": a workflow opens one
issue per item there. The body is public text: no local path, account or machine, and no other
product, in any case.

## Out of road

Fail loud. Locked tests still red, a spec gap, a question, a decision the PR body may not make, or
anything doubtful, worked around, silenced or skipped: push the branch, comment on the issue with
it in full, add `needs-developer`, stop. Never edit a test to make it pass; never guess; never
file new work.

## Conventions a linter cannot see

- Every goroutine has an owner and stops when its context ends; shutdown drains, unless the
  behavior lines say a stop closes at once (Part 1 does: the developer, 2026-10-16). An error is
  returned or logged, never both; no panic crosses a package boundary. An interface is declared
  where it is consumed. Anything read from a network or a file has a size bound.
- A comment says why, never what, never a step or line number, never a bare pointer to a spec.
- Never read the source code of other BBS software or its companions (transfer programs, door
  kits, terminals); know them by their documentation and observed behavior. The loop's hooks
  refuse it; a session that has read such source writes no code or text here on that topic.
- Names read without knowing abbreviations: `sessionID`, not `sid`; `tools/namecheck` fails the
  rest. A method is a verb; reads follow Go style, no `Get`. Tests are table-driven, on real
  sockets and temp files, no mocks, no sleeps; each row names the line it proves.

Everything else that is a rule is a check in `check.sh` or `.golangci.yml`, or it is not a rule.
