#!/usr/bin/env bash
# The only definition of green. Every gate tolerates an empty repository and says so.
# Usage: bash check.sh [--mutation]   env: BASE (default origin/development), RACE, EFFICACY
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

# 3. Developer-owned paths are not touched by a bot-authored commit.
if git rev-parse -q --verify "$BASE" >/dev/null 2>&1; then
  bot=$(git log --format='%h %ae' "$BASE..HEAD" -- docs/spec docs/architecture.md features '*/contract.go' | grep '\[bot\]@' || true)
  [ -z "$bot" ] || { echo "$bot"; fail "a bot-authored commit touched a developer-owned path"; }
fi

# 4. Approved tests are locked from the QA commit on.
qa=$(git log -1 --format=%H --grep='^Helios-Role: qa$' 2>/dev/null || true)
if [ -n "$qa" ]; then
  changed=$(git diff --name-only --diff-filter=MD "$qa" HEAD -- '*_test.go' || true)
  [ -z "$changed" ] || { echo "$changed"; fail "test files approved at ${qa:0:8} were changed or deleted"; }
fi
# 4b. A test file not from a QA commit may not run before the approved ones.
for f in $(git ls-files '*_test.go'); do
  last=$(git log -1 --format=%H -- "$f")
  git log -1 --format=%B "$last" | grep -q '^Helios-Role: qa$' && continue
  bad=$(grep -nE '^func (TestMain|init)\(|^//go:build' "$f" || true)
  [ -z "$bad" ] || { echo "$f: $bad"; fail "a non-QA test file declares TestMain, init or a build tag"; }
done

# 5. Go gates, when there is Go. A failing go list is a failure, not an empty repository.
pkgs=$(go list ./... 2>&1) || { echo "$pkgs"; fail "go list failed"; }
if [ -n "$pkgs" ]; then
  need golangci-lint "https://golangci-lint.run"
  need govulncheck "go install golang.org/x/vuln/cmd/govulncheck@latest"
  go build ./...
  go vet ./...
  golangci-lint run ./...
  go test ${RACE:-} -count=1 ./...
  govulncheck ./...
  if [ "$MUTATION" = 1 ] && git diff --name-only "$BASE...HEAD" -- '*.go' ':!*_test.go' 2>/dev/null | grep -q .; then
    need gremlins "go install github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0"
    gremlins unleash --diff "$BASE" --threshold-efficacy "${EFFICACY:-80}" .
  fi
else
  echo "no Go packages yet; Go gates skipped"
fi
echo "green"
