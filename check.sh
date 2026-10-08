#!/usr/bin/env bash
# The only definition of green. Every gate tolerates an empty repository and says so.
# Usage: bash check.sh [--mutation]   env: BASE (default origin/development), RACE, COVER, EFFICACY,
#   SKIP_GO=1 (CI, a change set with no Go in it), TESTRUN (CI, a -run pattern for go test)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
BASE="${BASE:-origin/development}"
MUTATION=0; [ "${1:-}" = "--mutation" ] && MUTATION=1
fail() { echo "FAIL: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || fail "$1 is not installed: $2"; }

# 1. The standing instructions stay short.
lines=$(wc -l < CLAUDE.md)
[ "$lines" -le 60 ] || fail "CLAUDE.md is $lines lines; the cap is 60"

# 2. Specs are language-neutral.
if [ -d docs/spec ]; then
  hits=$(grep -rnE 'err != nil|pgx\.|context\.Context|goroutine|\binternal/[a-z]+|[a-z]+\.go\b|golang|lua_' docs/spec || true)
  [ -z "$hits" ] || { echo "$hits"; fail "docs/spec names the implementation"; }
fi

# 3. The paths in developer-owned-paths are not touched by a bot-authored commit. .github/ is
# the CI that judges the loop's work: a session may not change it. The loop's edit lock reads
# the same file, so the commit lock and the edit lock cannot disagree.
# Gates 3 and 4a judge a branch's commits before it merges; --mutation's range is already merged.
[ -f developer-owned-paths ] || fail "developer-owned-paths is missing"
mapfile -t owned < <(sed -e 's/#.*//' -e 's/[[:space:]]//g' developer-owned-paths | grep . || true)
[ "${#owned[@]}" -gt 0 ] || fail "developer-owned-paths names no path"
if [ "$MUTATION" = 0 ] && git rev-parse -q --verify "$BASE" >/dev/null 2>&1; then
  # On a pull request CI checks out GitHub's merge of the branch into the base, which GitHub
  # authors as whoever opened the PR, and which a branch behind the base shows as touching
  # owned paths: judge the branch's own commits, up to its head, the merge's second parent.
  tip=HEAD
  if [ "${GITHUB_EVENT_NAME:-}" = pull_request ]; then
    tip=$(git rev-parse -q --verify 'HEAD^2') || fail "a pull request's checkout is not GitHub's merge"
  fi
  bot=$(git log --format='%h %ae' "$BASE..$tip" -- "${owned[@]}" | grep '\[bot\]@' || true)
  [ -z "$bot" ] || { echo "$bot"; fail "a bot-authored commit touched a developer-owned path"; }
fi

# 4. Approved tests are locked from the QA commit on.
qa=$(git log -1 --format=%H --grep='^Helios-Role: qa$' 2>/dev/null || true)
if [ -n "$qa" ]; then
  changed=$(git diff --name-only --diff-filter=MD "$qa" HEAD -- '*_test.go' || true)
  [ -z "$changed" ] || { echo "$changed"; fail "test files approved at ${qa:0:8} were changed or deleted"; }
fi
# 4a. A squash merge drops the trailer, so the anchor above is absent on the base. A test
# file already on the base is locked for every branch: only a QA commit may change or delete it.
if [ "$MUTATION" = 0 ] && git rev-parse -q --verify "$BASE" >/dev/null 2>&1; then
  for f in $(git diff --name-only --diff-filter=MD "$BASE...HEAD" -- '*_test.go'); do
    nonqa=$(for c in $(git log --format=%H "$BASE..HEAD" -- "$f"); do
      git log -1 --format=%B "$c" | grep -q '^Helios-Role: qa$' || echo "$c"; done)
    [ -z "$nonqa" ] || { echo "$f: $nonqa"; fail "a test file on $BASE was changed or deleted by a non-QA commit"; }
  done
fi
# 4b. A test file not from a QA commit may not run before the approved ones.
for f in $(git ls-files '*_test.go'); do
  last=$(git log -1 --format=%H -- "$f")
  git log -1 --format=%B "$last" | grep -q '^Helios-Role: qa$' && continue
  bad=$(grep -nE '^func (TestMain|init)\(|^//go:build' "$f" || true)
  [ -z "$bad" ] || { echo "$f: $bad"; fail "a non-QA test file declares TestMain, init or a build tag"; }
done

# 4c. A comment never carries a line number or a step number: both drift silently. Attempt
# one measured 66 drifted line numbers and 154 dead citations in its docs. Approved tests
# are exempt: a row names the behaviour line it proves.
pointers=$(git ls-files '*.go' | grep -v '_test\.go$' | xargs -r grep -niE '//.*[^[:alpha:]](line|step) [0-9]+' || true)
[ -z "$pointers" ] || { echo "$pointers"; fail "a comment carries a line or step number"; }

# 4d. GitHub reads .github/ from the default branch, main, so a merge into main must bring
# development's copy with it. Keyed on the base: a PR to development is never blocked by main
# being stale; a PR to main is blocked until .github/ is in step.
if [ "$BASE" = "origin/main" ] && git rev-parse -q --verify origin/development >/dev/null 2>&1; then
  git diff --quiet origin/development HEAD -- .github || { git diff --stat origin/development HEAD -- .github; fail ".github/ differs from development; main must carry development's copy"; }
fi

# 4e. A security linter's finding is fixed or brought to the developer, never silenced: no line
# this branch adds may switch off gosec, forbidigo or depguard, or every linter at once. The
# developer, 2026-10-07: the bootstrap code held 17 unsafe uses, each silenced by a one-line
# reason that every review let through. gosec's own "#nosec" counts too (found 2026-10-08; the
# lint config also makes gosec ignore it).
if [ "$MUTATION" = 0 ] && git rev-parse -q --verify "$BASE" >/dev/null 2>&1; then
  silenced=$(git diff -U0 "$BASE...HEAD" -- '*.go' | grep -E '^\+' |
    grep -E '//[[:space:]]*nolint([[:space:]]|$)|//[[:space:]]*nolint:[^/]*\b(gosec|forbidigo|depguard|all)\b|#nosec' || true)
  [ -z "$silenced" ] || { echo "$silenced"; fail "a security linter is silenced: fix the finding, or bring it to the developer"; }
fi

# 4f. A package's specification lives in one file, its contract.go. The developer, 2026-10-03:
# "There should never be 2 contracts.go living side by side. final spec is the truth." So no
# other Go file is named for a contract, and none but a test carries a "shall" in a comment,
# which is how a unit line reads.
specs=$(git ls-files '*.go' | grep -v '_test\.go$' | grep -v '/contract\.go$' | grep -i 'contract' || true)
[ -z "$specs" ] || { echo "$specs"; fail "a second contract file beside contract.go: a package's specification is its contract.go alone"; }
specs=$(git ls-files '*.go' | grep -v '_test\.go$' | grep -v '/contract\.go$' | xargs -r grep -nwE '//.*shall' || true)
[ -z "$specs" ] || { echo "$specs"; fail "a unit line outside contract.go: a package's specification is its contract.go alone"; }

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
  for os in windows linux; do
    GOOS=$os go-licenses check ./... --allowed_licenses="$licences" --ignore github.com/heliosestate/heliosadvance ||
      fail "a module's licence ($os build) is not one AGPL-3.0-only can carry: $licences"
  done
  go build ./...
  go vet ./...
  golangci-lint run ./...
  # Files built for one platform are linted only when GOOS names it, and the loop runs this
  # on Windows: lint the other platform too, so a Linux-only file's faults show before CI.
  other=linux; [ "$(go env GOOS)" = linux ] && other=windows
  GOOS=$other golangci-lint run ./...
  go run ./tools/namecheck .
  go test ${RACE:-} ${COVER:-} ${TESTRUN:+-run "$TESTRUN"} -count=1 ./...
  govulncheck ./...
  if [ "$MUTATION" = 1 ] && git diff --name-only "$BASE...HEAD" -- '*.go' ':!*_test.go' 2>/dev/null | grep -q .; then
    need gremlins "go install github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0"
    gremlins unleash --diff "$BASE" --threshold-efficacy "${EFFICACY:-80}" .
  fi
else
  echo "no Go packages yet; Go gates skipped"
fi
echo "green"
