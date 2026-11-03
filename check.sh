#!/usr/bin/env bash
# The only definition of green. Every gate tolerates an empty repository and says so; a gate that
# cannot run fails and says so.
# Usage: bash check.sh [--mutation]   env: BASE (default origin/development), RACE, COVER,
#   SKIP_GO=1 (CI, a change set with no Go in it), TESTSKIP (CI, a -skip pattern for go test),
#   PKGS (CI, the packages one job tests; default all), GATES=0 (CI, a job whose Go gates another
#   job of the same run checks), TIMED (CI, a file for the timed rows' place-in-window lines),
#   MUTATE (CI, with --mutation: whole packages to mutate instead of the lines changed since BASE)
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
# Gates 3 and 4a judge a branch's commits before it merges; --mutation is a report, never the
# required check, so it skips them.
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
    # Each name whole and taken literally (a leading : or a wildcard is part of the name), with no
    # rename hiding the old name; a git that fails here fails the gate too.
    while IFS= read -r -d '' path; do
      git diff --quiet "$parted" "$merge^2" -- ":(literal)$path" && git diff --quiet "$merge^1" "$merge" -- ":(literal)$path" ||
        fail "the loop's merge ${merge:0:7} has $path as no clean merge leaves it"
    done < <(git diff -z --no-renames --name-only "$merge^2" "$merge" -- "${owned[@]}")
    wait $! || fail "git could not list the owned paths the loop's merge ${merge:0:7} touched"
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
    # A merge whose copy of the file is one of its parents' adds nothing of its own: git lists it
    # when that parent is on the base and the other side's copy differs, and every change on the
    # other side is a commit of its own, judged here or on the base. A merge that writes what
    # neither parent had is judged like any commit.
    nonqa=$(for c in $commits; do
      parents=$(git rev-list --parents -n 1 "$c" | cut -s -d' ' -f2-)
      case $parents in *' '*)
        for p in $parents; do git diff --quiet "$p" "$c" -- "$f" && continue 2; done ;;
      esac
      is_qa "$c" || echo "$c"; done)
    [ -z "$nonqa" ] || { echo "$f: $nonqa"; fail "a test file on $BASE was changed or deleted by a non-QA commit"; }
  done <<< "$basetests"
fi
# 4b. A test file not from a QA commit may not run before the approved ones. A file held as the
# base holds it passed this gate on its own branch before it merged; a squash merge drops the
# trailer that showed it. A name ending in an operating system or a processor, as Go lists them,
# is a build constraint as much as a //go:build line (developer, 2026-10-27).
onbase=0; git rev-parse -q --verify "$BASE" >/dev/null 2>&1 && onbase=1
goos=$(go tool dist list | cut -d/ -f1 | sort -u | paste -sd'|' -)
goarch=$(go tool dist list | cut -d/ -f2 | sort -u | paste -sd'|' -)
while IFS= read -r -d '' f; do
  [ "$onbase" = 1 ] && git diff --quiet "$BASE" HEAD -- "$f" && continue
  last=$(git log -1 --format=%H -- "$f")
  is_qa "$last" && continue
  bad=$(grep -nE '^func (TestMain|init)\(|^//go:build' -- "$f" || true)
  [ -z "$bad" ] || { echo "$f: $bad"; fail "a non-QA test file declares TestMain, init or a build tag"; }
  stem=${f##*/}; stem=${stem%_test.go}
  if [[ $stem =~ _($goos)(_($goarch))?$ || $stem =~ _($goarch)$ ]]; then
    echo "$f"; fail "a non-QA test file is named for an operating system or a processor, a build constraint"
  fi
done < <(git ls-files -z '*_test.go')

# 4c. A comment never carries a line number or a step number: both drift silently. Attempt
# one measured 66 drifted line numbers and 154 dead citations in its docs. Approved tests
# are exempt: a row names the behaviour line it proves.
pointers=$(git ls-files -z '*.go' | grep -zv '_test\.go$' | xargs -0 -r grep -niE '//.*[^[:alpha:]](line|step) [0-9]+' || true)
[ -z "$pointers" ] || { echo "$pointers"; fail "a comment carries a line or step number"; }

# 4d. A merge into main brings development's .github/ with it: main takes pull requests from
# development alone, so the two stay in step. Keyed on the base: a PR to development is never
# blocked by main being stale; a PR to main is blocked until .github/ is in step.
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

# 4h. An import rule names each of the engine's own packages exactly. The linter reads an allowed
# entry as a prefix unless it ends in $, so an entry without it lets in every package whose path
# only begins the same way; a merge that keeps the other side of a conflict would bring one back
# with everything green (HeliosAdvance #160). Each of the engine's paths in the file is judged,
# written plainly, quoted, in a one-line list or mapping, or on the line after a folded marker,
# once comments are taken off; a deny entry's own lines are left out, since there $ narrows what
# is blocked. The dependencies rule's module-wide entry, ending in /, is the one exception, and
# there is one. This catches what a merge or a slip brings back, not a disguise (a shortened
# path, a reference to another rule's list, an escape, a # inside quotes): the file is the
# developer's, and his review of every change to it is the check for that.
[ -f .golangci.yml ] || fail "the import rules (.golangci.yml) are missing, so they cannot be checked"
paths=$(sed -E '/^[[:space:]]*(- )?(pkg|desc):/s/.*//' .golangci.yml | sed 's/#.*//' |
  grep -noE "github\.com/heliosestate/heliosadvance[^]}\"'[:space:],]*") ||
  fail "no path of the engine's own was found in .golangci.yml, so its import rules cannot be checked"
loose=$(grep -vE ':(github\.com/heliosestate/heliosadvance/|.*\$)$' <<< "$paths" || true)
[ -z "$loose" ] || { echo "$loose"; fail "an import rule names one of the engine's paths without a closing \$"; }
wide=$(grep -cE ':github\.com/heliosestate/heliosadvance/$' <<< "$paths" || true)
[ "$wide" = 1 ] || fail "the import rules hold the engine's module-wide entry $wide times, not once"

# 4i. The test support (internal/testrun) is for tests: no other file imports it, whatever its
# build tags, which the linter's import rules do not see (a file built only for the race detector).
leak=$(grep -rlE --include='*.go' '"github\.com/heliosestate/heliosadvance/internal/testrun"' . |
  grep -vE '_test\.go$|^\./internal/testrun/' || true)
[ -z "$leak" ] || { echo "$leak"; fail "a file that is not a test imports the test support"; }

# 5. Go gates, when there is Go. A failing go list is a failure, not an empty repository.
# CI sets SKIP_GO on its one runner for the cheap gates, and the full matrix does not start
# when the change set holds only Markdown, docs/, developer-owned-paths and .github/ other
# than check.yml.
if [ "${SKIP_GO:-}" = 1 ]; then echo "no Go in the change set; Go gates skipped"; echo green; exit 0; fi
pkgs=$(go list ./... 2>&1) || { echo "$pkgs"; fail "go list failed"; }
if [ -n "$pkgs" ] && [ "${GATES:-1}" = 0 ]; then
  echo "Go gates checked by another job of this run; tests only"
elif [ -n "$pkgs" ]; then
  need golangci-lint "https://golangci-lint.run"
  need govulncheck "go install golang.org/x/vuln/cmd/govulncheck at the version in .github/tool-versions"
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
  govulncheck ./...
fi
if [ -n "$pkgs" ]; then
  # On Windows the rows that need a Linux container (TestOracle…) or Linux itself (TestLinux…)
  # cannot pass, so they are skipped there unless TESTSKIP says otherwise: the loop runs this on
  # Windows, and CI sets the same pattern for its Windows runner.
  [ "$(go env GOOS)" = windows ] && TESTSKIP=${TESTSKIP-'^(TestOracle|TestLinux)'}
  # One package at a time, on every machine: the timed rows' margins are measured that way, and
  # every failure from load on record came with every package at once (HeliosDesign #258).
  if [ -n "${TIMED:-}" ]; then
    # CI keeps every timed row's place in its window (#258), and every line where a row says it
    # cannot tell and sets its check aside, since such a pass proves nothing (HeliosDesign #217): a
    # passing run's logs show only in Go's -json stream, so those lines go to $TIMED, a few KB. The
    # rows TESTSKIP skips by name are named above. The console gets each package's result, and a
    # failed package's whole output, so a crash or a hang that Go does not pin on one test still
    # shows its cause.
    need jq "jq, from the system's packages"
    stream=$(mktemp); status=0
    go test -json -p 1 ${RACE:-} ${COVER:-} ${TESTSKIP:+-skip "$TESTSKIP"} -count=1 ${PKGS:-./...} > "$stream" || status=$?
    jq -j 'select(.Action == "output") | .Package + ":" + .Output' "$stream" | grep -E 'into its window of|cannot tell' > "$TIMED" || true
    jq -sj '[.[] | select(.Action == "fail" and (.Test | not)) | .Package] as $failed
      | .[] | select(.Action == "build-output" or .Action == "output")
      | select((.Package as $p | any($failed[]; . == $p))
          or (.Test == null and (.Output | test("^(PASS|coverage: .*)\n$") | not)))
      | .Output' "$stream"
    rm -f "$stream"
    [ "$status" = 0 ] || exit "$status"
  else
    go test -p 1 ${RACE:-} ${COVER:-} ${TESTSKIP:+-skip "$TESTSKIP"} -count=1 ${PKGS:-./...}
  fi
  if [ "$MUTATION" = 1 ] && [ "$(go env GOOS)" = windows ]; then
    # gremlins v0.6.0 misreads coverage on Windows (its issue #222: coverage paths use / and file
    # paths \, so every mutant reads "Not covered"), and a report with nothing covered would read as
    # one. Mutation testing runs on Linux, in CI, until upstream fixes it (the developer, 2026-10-27).
    echo "mutation testing: not run on Windows; read the mutation report in the pull request's CI run"
  elif [ "$MUTATION" = 1 ] && { [ -n "${MUTATE:-}" ] || git diff --name-only "$BASE...HEAD" -- '*.go' ':!*_test.go' ':!internal/testrun/*' 2>/dev/null | grep -q .; }; then
    need gremlins "go install github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0"
    # A report, not a gate (the developer, 2026-10-22): QA reads the survivors beside its broken
    # copies, and a survivor becomes a test only when a caller, the sysop, the log or stored data
    # could see its fault. The run still fails when gremlins fails or prints no result lines, since
    # then there is nothing to read. GOFLAGS=-count=1: coverage gathered from Go's test cache made
    # every mutant "time out", which counts as killed, and read 100% (2026-10-21).
    # cmd/ is left out: its tests run the built program as its own process, which gremlins'
    # coverage cannot see, so every mutant there reads "Not covered". The rows and QA's broken
    # copies prove it instead (the developer, 2026-10-22). internal/testrun/ is left out too: it is
    # test support, proved by the rows that use it; so is tools/, the gates' own tools.
    # diff.context=0, for gremlins' git alone: v0.6.0 reads each hunk as one unbroken run of added
    # lines, so where git joins nearby edits into one hunk, every edit after the first gap went
    # unmutated (its issue 301; HeliosDesign #212: 3 of PR 143's 9 points in listener.go). With no
    # context lines, git writes one hunk per run of edits. Kept until a gremlins release fixes it.
    # The run on a diff stays at the repository root (.): a package path matches no diff entry (its
    # 278). MUTATE names whole packages instead (a QA change to existing rows, a milestone), each
    # mutated in full.
    if [ -n "${MUTATE:-}" ]; then read -ra targets <<< "$MUTATE"; diffarg=(); else targets=(.); diffarg=(--diff "$BASE"); fi
    mutants=
    for target in "${targets[@]}"; do
      out=$(GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=diff.context GIT_CONFIG_VALUE_0=0 GOFLAGS="${GOFLAGS:+$GOFLAGS }-count=1" gremlins unleash "${diffarg[@]}" --exclude-files '^(cmd|internal/testrun|tools)/' "$target" 2>&1) || { echo "$out"; fail "mutation testing: gremlins failed on $target"; }
      echo "$out"
      grep -qE 'Killed: [0-9]+, Lived: [0-9]+, Not covered: [0-9]+' <<< "$out" || fail "mutation testing: no result lines for $target, so there is nothing to report"
      mutants+="$out"$'\n'
    done
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
