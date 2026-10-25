#!/usr/bin/env bash
# The only definition of green. Every gate tolerates an empty repository and says so; a gate that
# cannot run fails and says so.
# Usage: bash check.sh [--mutation]   env: BASE (default origin/development), RACE, COVER,
#   SKIP_GO=1 (CI, a change set with no Go in it), TESTSKIP (CI, a -skip pattern for go test)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
BASE="${BASE:-origin/development}"
MUTATION=0; [ "${1:-}" = "--mutation" ] && MUTATION=1
fail() { echo "FAIL: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || fail "$1 is not installed: $2"; }
# Gates 3, 4a and 4e judge this branch against $BASE. Without it they cannot run, and a gate that
# cannot run fails: fetch the base, or name in BASE the commit to judge from.
if [ "$MUTATION" = 0 ]; then
  git rev-parse -q --verify "$BASE" >/dev/null 2>&1 || fail "$BASE does not resolve, so the gates that judge this branch against it cannot run: fetch it, or set BASE to the commit to judge from"
fi

# 1. The standing instructions stay short. A repository with no CLAUDE.md yet has none to cap,
# and says so.
if [ -f CLAUDE.md ]; then
  lines=$(wc -l < CLAUDE.md)
  [ "$lines" -le 90 ] || fail "CLAUDE.md is $lines lines; the cap is 90"
else
  echo "no CLAUDE.md: nothing to cap"
fi

# 2. Specs are language-neutral.
if [ -d docs/spec ]; then
  hits=$(grep -rnE 'err != nil|pgx\.|context\.Context|goroutine|\binternal/[a-z]+|[a-z]+\.go\b|golang|lua_' docs/spec || true)
  [ -z "$hits" ] || { echo "$hits"; fail "docs/spec names the implementation"; }
fi

# 3. The paths in developer-owned-paths are not touched by a commit a loop authored. .github/ is
# the CI that judges the loop's work: a loop session may not change it. The loop's edit lock
# reads the same file, so the commit lock and the edit lock cannot disagree. The loops are the
# App logins in loop-identities; the interactive session's App is not one, and its changes to
# owned paths land by pull request on the developer's code-owner review.
# Gates 3 and 4a judge a branch's commits before it merges; --mutation's range is already merged.
# Both lists are read from the base when it has them, never from the branch being judged: a loop
# commit that edits a list would otherwise judge itself by its own copy (the codebase review,
# 2026-10-24). The tree's copy serves only where the base has none, as on a first branch.
list_of() {
  if [ "$MUTATION" = 0 ] && git cat-file -e "$BASE:$1" 2>/dev/null; then git show "$BASE:$1"
  elif [ -f "$1" ]; then cat -- "$1"
  else fail "$1 is missing"; fi
}
mapfile -t owned < <(list_of developer-owned-paths | sed -e 's/#.*//' -e 's/[[:space:]]//g' | grep . || true)
[ "${#owned[@]}" -gt 0 ] || fail "developer-owned-paths names no path"
mapfile -t loops < <(list_of loop-identities | sed -e 's/#.*//' -e 's/[[:space:]]//g' | grep . || true)
[ "${#loops[@]}" -gt 0 ] || fail "loop-identities names no identity"
# A loop's commit: its author or its committer address is <id>+<login>@ or <login>@ for a login
# on the list. The committer counts too: an amend, rebase or squash by a loop keeps the earlier
# author and makes the loop the committer.
is_loop_address() { local id; for id in "${loops[@]}"; do case "$1" in *"+$id@"*|"$id@"*) return 0 ;; esac; done; return 1; }
is_loop() { is_loop_address "$1" || is_loop_address "${2:-}"; }
if [ "$MUTATION" = 0 ]; then
  # On a pull request CI checks out GitHub's merge of the branch into the base, which GitHub
  # authors as whoever opened the PR, and which a branch behind the base shows as touching
  # owned paths: judge the branch's own commits, up to its head, the merge's second parent.
  tip=HEAD
  if [ "${GITHUB_EVENT_NAME:-}" = pull_request ]; then
    tip=$(git rev-parse -q --verify 'HEAD^2') || fail "a pull request's checkout is not GitHub's merge"
  fi
  # git's output is taken whole first, so a git that fails fails the gate instead of reading as
  # no commits (the codebase review, 2026-10-24).
  touched=$(git log --no-merges --format='%h %ae %ce' "$BASE..$tip" -- "${owned[@]}") ||
    fail "git could not list the branch's commits to owned paths"
  loop=$(while read -r h a c; do [ -n "$h" ] && is_loop "$a" "$c" && echo "$h $a $c"; done <<< "$touched"; true)
  [ -z "$loop" ] || { echo "$loop"; fail "a loop-authored or loop-committed commit touched a developer-owned path"; }
  # A loop catches up by merging the base in, which shows the base's owned edits as its own. A
  # loop's merge passes when its second side is already in the base and each owned path is as a
  # clean merge leaves it: the base's copy, or the branch's where the base has not changed it
  # since the two sides parted. Keeping the branch's older copy would undo the base's edit.
  merges=$(git log --merges --format='%H %ae %ce' "$BASE..$tip") || fail "git could not list the branch's merges"
  while read -r merge email committer; do
    [ -n "$merge" ] || continue
    is_loop "$email" "$committer" || continue
    if git rev-parse -q --verify "$merge^3" >/dev/null; then
      fail "the loop's merge ${merge:0:7} has more than two parents"
    fi
    git merge-base --is-ancestor "$merge^2" "$BASE" ||
      fail "the loop's merge ${merge:0:7} merges a commit the base does not have"
    parted=$(git merge-base "$merge^1" "$merge^2")
    while read -r path; do
      git diff --quiet "$parted" "$merge^2" -- "$path" && git diff --quiet "$merge^1" "$merge" -- "$path" ||
        fail "the loop's merge ${merge:0:7} has $path as no clean merge leaves it"
    done < <(git diff --name-only "$merge^2" "$merge" -- "${owned[@]}")
  done <<< "$merges"
fi

# 4. Approved tests are locked from the QA commit on.
# A QA commit carries the trailer "Helios-Role: qa" and is either signed by a key in qa-signers
# (helios-aegle's, held by the QA session's account; developer, 2026-10-25) or listed in
# qa-grandfathered, the QA commits from before signing. A trailer alone proves nothing: anyone can
# type it (the codebase review, 2026-10-24). Both files come from the base, never the branch.
signers=$(mktemp); trap 'rm -f "$signers"' EXIT
if [ "$MUTATION" = 0 ] && git cat-file -e "$BASE:qa-signers" 2>/dev/null; then git show "$BASE:qa-signers" > "$signers"
elif [ -f qa-signers ]; then cp qa-signers "$signers"; fi
if [ "$MUTATION" = 0 ] && git cat-file -e "$BASE:qa-grandfathered" 2>/dev/null; then grandfathered=$(git show "$BASE:qa-grandfathered")
elif [ -f qa-grandfathered ]; then grandfathered=$(cat qa-grandfathered); else grandfathered=; fi
is_qa() {
  git log -1 --format=%B "$1" | grep -q '^Helios-Role: qa$' || return 1
  grep -qxF "$(git rev-parse "$1")" <<< "$grandfathered" && return 0
  [ -s "$signers" ] && git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile="$signers" verify-commit "$1" >/dev/null 2>&1
}
# Paths are read NUL-separated and git quotes nothing, so a name with a space or a quote is judged
# like any other; renames are split into a deletion and an addition (--no-renames), so a renamed
# or retyped test is a change to the approved one (the codebase review, 2026-10-24).
qa=$(for c in $(git log --format=%H --grep='^Helios-Role: qa$' 2>/dev/null); do is_qa "$c" && { echo "$c"; break; }; done; true)
if [ -n "$qa" ]; then
  changed=$(git diff -z --no-renames --name-only --diff-filter=MDT "$qa" HEAD -- '*_test.go' | tr '\0' '\n') ||
    fail "git could not list the tests changed since the QA commit"
  # The base moves on after a QA commit, and a squash merge drops its own QA commits' trailer, so
  # a test approved on the base since shows here as changed. It came from the base when the QA
  # commit left it as it found it and HEAD holds it as the base does; gate 4a locks the base's
  # tests. The base's copy over a test this QA commit changed is still a change to it.
  if [ -n "$changed" ] && git rev-parse -q --verify "$BASE" >/dev/null 2>&1 &&
    forked=$(git merge-base "$qa" "$BASE"); then
    changed=$(while IFS= read -r f; do
      [ -n "$f" ] || continue
      git diff --quiet "$forked" "$qa" -- "$f" && git diff --quiet "$BASE" HEAD -- "$f" || echo "$f"
    done <<< "$changed")
  fi
  [ -z "$changed" ] || { echo "$changed"; fail "test files approved at ${qa:0:8} were changed or deleted"; }
fi
# 4a. A squash merge drops the trailer, so the anchor above is absent on the base. A test
# file already on the base is locked for every branch: only a QA commit may change or delete it.
# Into main, the commits already on development passed this gate there; only the rest are judged,
# so a release is never failed over a QA change that a squash merge brought to development
# (the codebase review, 2026-10-24).
if [ "$MUTATION" = 0 ]; then
  exclude=()
  [ "$BASE" = origin/main ] && git rev-parse -q --verify origin/development >/dev/null 2>&1 && exclude=(--not origin/development)
  basetests=$(git diff -z --no-renames --name-only --diff-filter=MDT "$BASE...HEAD" -- '*_test.go' | tr '\0' '\n') ||
    fail "git could not list the tests this branch changed"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    commits=$(git log --format=%H "$BASE..HEAD" "${exclude[@]}" -- "$f") || fail "git could not list the commits to $f"
    nonqa=$(for c in $commits; do
      is_qa "$c" || echo "$c"; done)
    [ -z "$nonqa" ] || { echo "$f: $nonqa"; fail "a test file on $BASE was changed or deleted by a non-QA commit"; }
  done <<< "$basetests"
fi
# 4b. A test file not from a QA commit may not run before the approved ones. A file held as the
# base holds it passed this gate on its own branch before it merged; a squash merge drops the
# trailer that showed it.
onbase=0; git rev-parse -q --verify "$BASE" >/dev/null 2>&1 && onbase=1
while IFS= read -r -d '' f; do
  [ "$onbase" = 1 ] && git diff --quiet "$BASE" HEAD -- "$f" && continue
  last=$(git log -1 --format=%H -- "$f")
  is_qa "$last" && continue
  bad=$(grep -nE '^func (TestMain|init)\(|^//go:build' -- "$f" || true)
  [ -z "$bad" ] || { echo "$f: $bad"; fail "a non-QA test file declares TestMain, init or a build tag"; }
done < <(git ls-files -z '*_test.go')

# 4c. A comment never carries a line number or a step number: both drift silently. Attempt
# one measured 66 drifted line numbers and 154 dead citations in its docs. Approved tests
# are exempt: a row names the behaviour line it proves.
pointers=$(git ls-files -z '*.go' | grep -zv '_test\.go$' | xargs -0 -r grep -niE '//.*[^[:alpha:]](line|step) [0-9]+' || true)
[ -z "$pointers" ] || { echo "$pointers"; fail "a comment carries a line or step number"; }

# 4d. GitHub reads .github/ from the default branch, main, so a merge into main must bring
# development's copy with it. Keyed on the base: a PR to development is never blocked by main
# being stale; a PR to main is blocked until .github/ is in step.
if [ "$BASE" = "origin/main" ] && git rev-parse -q --verify origin/development >/dev/null 2>&1; then
  git diff --quiet origin/development HEAD -- .github || { git diff --stat origin/development HEAD -- .github; fail ".github/ differs from development; main must carry development's copy"; }
fi

# 4e. A security linter's finding is fixed or brought to the developer, never silenced: no line
# this branch adds may switch off gosec, forbidigo or depguard, or every linter at once: in an
# earlier attempt the bootstrap code held 17 unsafe uses, each silenced by a one-line reason that
# every review let through. gosec's own "#nosec" counts too (the lint config also makes gosec
# ignore it).
if [ "$MUTATION" = 0 ]; then
  silenced=$(git diff -U0 "$BASE...HEAD" -- '*.go' | grep -E '^\+' |
    grep -E '//[[:space:]]*nolint([[:space:]]|$)|//[[:space:]]*nolint:[^/]*\b(gosec|forbidigo|depguard|all)\b|#nosec' || true)
  [ -z "$silenced" ] || { echo "$silenced"; fail "a security linter is silenced: fix the finding, or bring it to the developer"; }
fi

# 4f. A package's specification lives in one file, its contract.go. The developer: "There
# should never be 2 contracts.go living side by side. final spec is the truth." So no
# other Go file is named for a contract, and none but a test carries a "shall" in a comment,
# which is how a unit line reads.
specs=$(git ls-files '*.go' | grep -v '_test\.go$' | grep -v '/contract\.go$' | grep -i 'contract' || true)
[ -z "$specs" ] || { echo "$specs"; fail "a second contract file beside contract.go: a package's specification is its contract.go alone"; }
specs=$(git ls-files -z '*.go' | grep -zv '_test\.go$' | grep -zv '/contract\.go$' | xargs -0 -r grep -nwE '//.*shall' || true)
[ -z "$specs" ] || { echo "$specs"; fail "a unit line outside contract.go: a package's specification is its contract.go alone"; }

# 4g. A comment line is at most 100 columns, a tab counted as four: the width the comments are
# wrapped to, which reviews checked by eye until a review round and two noticed issues went to
# it. Code lines have no limit, since a test row quotes its behavior line whole. A line holding a
# link is exempt, since a link does not wrap.
long=$(git ls-files -z '*.go' | xargs -0 -r awk '/^[ \t]*\/\// && !/:\/\// {
  line = $0; gsub(/\t/, "    ", line)
  if (length(line) > 100) print FILENAME ":" FNR ": " length(line) " columns"
}')
[ -z "$long" ] || { echo "$long"; fail "a comment line runs past 100 columns: wrap it, or shorten a nolint's reason"; }

# 5. Go gates, when there is Go. A failing go list is a failure, not an empty repository.
# CI sets SKIP_GO on its one runner for the cheap gates, and the full matrix does not start
# when the change set holds only Markdown, docs/, developer-owned-paths and .github/ other
# than check.yml.
if [ "${SKIP_GO:-}" = 1 ]; then echo "no Go in the change set; Go gates skipped"; echo green; exit 0; fi
pkgs=$(go list ./... 2>&1) || { echo "$pkgs"; fail "go list failed"; }
if [ -n "$pkgs" ]; then
  need golangci-lint "https://golangci-lint.run"
  need govulncheck "go install golang.org/x/vuln/cmd/govulncheck@latest"
  need go-licenses "go install github.com/google/go-licenses/v2@v2.0.1"
  go mod verify
  # Every module the engine is built from, indirect ones included, carries a licence that can
  # be combined with AGPL-3.0-only; the engine's own module is the AGPL-3.0 one.
  licences=MIT,BSD-2-Clause,BSD-3-Clause,ISC,Apache-2.0,MPL-2.0
  # When go.mod asks for a newer Go than the one installed, go switches to a downloaded toolchain,
  # and go-licenses, which looks for the standard library under the installed Go's root, then
  # fails on every standard package. The root of the Go in use is passed to it.
  goroot=$(go env GOROOT)
  for os in windows linux; do
    GOROOT=$goroot GOOS=$os go-licenses check ./... --allowed_licenses="$licences" --ignore github.com/heliosestate/heliosadvance ||
      fail "a module's licence ($os build) is not one AGPL-3.0-only can carry: $licences"
  done
  # With one main package, go build writes its program into the clone; build into a temporary
  # folder instead, so the check leaves the clone as it found it.
  buildout=$(mktemp -d)
  go build -o "$buildout/" ./...
  rm -rf "$buildout"
  go vet ./...
  golangci-lint run ./...
  # Files built for one platform are linted only when GOOS names it, and the loop runs this
  # on Windows: lint the other platform too, so a Linux-only file's faults show before CI. With
  # cgo off, since a C compiler for this platform cannot preprocess the other platform's cgo
  # files in the standard library; the engine has no cgo, so its own files lint the same.
  other=linux; [ "$(go env GOOS)" = linux ] && other=windows
  CGO_ENABLED=0 GOOS=$other golangci-lint run ./...
  go run ./tools/namecheck .
  # On Windows the rows that need a Linux container (TestOracle…) or Linux itself (TestLinux…)
  # cannot pass, so they are skipped there unless TESTSKIP says otherwise: the loop runs this on
  # Windows, and CI sets the same pattern for its Windows runner.
  [ "$(go env GOOS)" = windows ] && TESTSKIP=${TESTSKIP-'^(TestOracle|TestLinux)'}
  go test ${RACE:-} ${COVER:-} ${TESTSKIP:+-skip "$TESTSKIP"} -count=1 ./...
  govulncheck ./...
  if [ "$MUTATION" = 1 ] && git diff --name-only "$BASE...HEAD" -- '*.go' ':!*_test.go' 2>/dev/null | grep -q .; then
    need gremlins "go install github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0"
    # A report, not a gate (the developer, 2026-10-22): QA reads the survivors beside its broken
    # copies, and a survivor becomes a test only when a caller, the sysop, the log or stored data
    # could see its fault. The run still fails when gremlins fails or prints no result lines, since
    # then there is nothing to read. GOFLAGS=-count=1: coverage gathered from Go's test cache made
    # every mutant "time out", which counts as killed, and read 100% (2026-10-21).
    # cmd/ is left out: its tests run the built program as its own process, which gremlins'
    # coverage cannot see, so every mutant there reads "Not covered". The rows and QA's broken
    # copies prove it instead (the developer, 2026-10-22).
    mutants=$(GOFLAGS="${GOFLAGS:+$GOFLAGS }-count=1" gremlins unleash --diff "$BASE" --exclude-files '^cmd/' . 2>&1) || { echo "$mutants"; fail "mutation testing: gremlins failed"; }
    echo "$mutants"
    grep -qE 'Killed: [0-9]+, Lived: [0-9]+, Not covered: [0-9]+' <<< "$mutants" || fail "mutation testing: no result lines, so there is nothing to report"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
      { echo "## Mutation testing, a report"; echo '```'
        grep -E 'LIVED|NOT COVERED|Killed:|Timed out:|Test efficacy|Mutator coverage' <<< "$mutants"
        echo '```'; } >> "$GITHUB_STEP_SUMMARY"
    fi
  fi
else
  echo "no Go packages yet; Go gates skipped"
fi
echo "green"
