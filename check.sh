#!/usr/bin/env bash
# The only definition of green. Every gate tolerates an empty repository and says so; a gate that
# cannot run fails and says so.
# Usage: bash check.sh [--mutation | --self-test]
#   env: BASE (default origin/development), RACE, COVER, SKIP_GO=1 (CI, a change set with no Go
#   in it), TESTSKIP (CI, a -skip pattern for go test), PKGS (CI, the packages one job tests;
#   default all), GATES=0 (CI, a job whose Go gates another job of the same run checks),
#   LINT_WORKFLOWS=0 (CI, a job whose workflows and shell scripts another job of the same run
#   lints), TIMED
#   (CI, a file for the timed rows' place-in-window lines), MUTATE (CI, with --mutation: whole
#   packages to mutate instead of the lines changed since BASE)
set -euo pipefail
if [ "${1:-}" = --self-test ]; then script=$(realpath -- "$0"); fi
cd "$(git rev-parse --show-toplevel)"
BASE="${BASE:-origin/development}"
MUTATION=0; [ "${1:-}" = "--mutation" ] && MUTATION=1
fail() { echo "FAIL: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || fail "$1 is not installed: $2"; }
# --self-test: the gates that lock the developer's files and the approved tests (3, 4, 4a and 4b),
# the workflows' gate (4k), the shell gate (4l), zizmor's (4m) and the swallowed failures' (4n),
# judged over small histories built in a temporary folder, each the shape a real one takes. This
# whole script runs over each, as CI's cheap gates run it. A green case is built so that judging
# from the wrong QA commit, or from the wrong copy of the base, fails it. QA commits are signed
# with a key made for the run, which the fake base's qa-signers names.
self_test() {
  local n=0 failed=0 plain main qa_b qa_c gate="" refused_gates="" heading missing="" hash='#'
  need ssh-keygen "OpenSSH's, which signs the self-test's QA commits"
  need go "Go, which gate 4b asks for the names of operating systems and processors, and which builds actionlint"
  # Not local: the trap that removes it runs after this function has returned.
  t=$(mktemp -d) || fail "could not make the self-test's folder"
  trap 'cd / && rm -rf "$t"' EXIT
  # Run from inside a git hook, these would point every git command here at that repository.
  unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE
  ssh-keygen -q -t ed25519 -N '' -C qa -f "$t/key" || fail "ssh-keygen could not make the self-test's key"
  plain='func TestX(t *testing.T) { t.Log() }'
  main='func TestMain(m *testing.M) { m.Run() }'
  # as who git-arguments: runs git as dev, loop or qa, each a minute after the last, so a history's
  # order is the order it is built in. Only a QA commit is signed, and only with the run's key.
  as() {
    local who=$1 email date; shift
    n=$((n + 1)); date="$((1700000000 + n * 60)) +0000"
    case $who in
      dev) email=dev@example.invalid ;;
      loop) email='1+loop[bot]@users.noreply.github.com' ;;
      qa) email=qa@example.invalid ;;
    esac
    GIT_AUTHOR_NAME=$who GIT_AUTHOR_EMAIL=$email GIT_AUTHOR_DATE=$date \
      GIT_COMMITTER_NAME=$who GIT_COMMITTER_EMAIL=$email GIT_COMMITTER_DATE=$date \
      git -c commit.gpgsign=false -c gpg.format=ssh -c gpg.ssh.program=ssh-keygen \
        -c user.signingkey="$t/key" "$@" >/dev/null ||
      fail "self-test: git $* failed"
  }
  dev() { as dev commit -q -m "$1"; }
  qa() { as qa commit -q -S -m "$1" -m "Helios-Role: qa"; }
  # test_file path [body]: writes a test file, a plain test unless a body is given, and stages it.
  test_file() {
    mkdir -p "${1%/*}"
    printf 'package x\n\nimport "testing"\n\n%s\n' "${2:-$plain}" > "$1"
    git add -- "$1"
  }
  change() { echo "// changed" >> "$1"; git add -- "$1"; }
  # sync branch...: the fake remote's branches set to the local ones.
  sync() { local b; for b; do git update-ref "refs/remotes/origin/$b" "refs/heads/$b"; done; }
  # fresh: a new repository whose development and main both hold one commit: the lists the gates
  # read, an owned file and two tests.
  fresh() {
    { cd / && rm -rf "$t/r" && git init -q -b development "$t/r" && cd "$t/r"; } || fail "self-test: no repository"
    printf 'owned/*\n' > developer-owned-paths
    printf 'loop[bot]\n' > loop-identities
    printf 'qa@example.invalid %s\n' "$(cat "$t/key.pub")" > qa-signers
    printf 'linters:\n  settings:\n    depguard:\n      rules:\n        main:\n          allow:\n            - %s\n' \
      github.com/heliosestate/heliosadvance/ > .golangci.yml
    mkdir owned && echo owned > owned/file
    { git add -A && test_file a/a_test.go && test_file b/b_test.go; } || fail "self-test: no base"
    dev base; git branch main; sync development main
  }
  # expect case want base event [flag]: runs this script over the repository as CI would, and fails
  # the self-test unless its last line starts with want and it exits as want says: 0 for green.
  # A case that refuses as it should counts for the gate named in gate, set before it.
  expect() {
    local out status=0 got refused=0 to_refuse=0
    out=$(GITHUB_EVENT_NAME=$4 BASE=$3 SKIP_GO=1 LINT_WORKFLOWS=1 bash "$script" ${5:+"$5"} 2>&1) || status=$?
    got=$(tail -1 <<< "$out")
    [ "$status" = 0 ] || refused=1
    [ "$2" = green ] || to_refuse=1
    if [[ $got == "$2"* ]] && [ "$refused" = "$to_refuse" ]; then
      echo "self-test: $1: $got"
      [ "$to_refuse" = 0 ] || refused_gates+=" $gate "
    else
      echo "self-test: $1: wanted \"$2\", got (exit $status): $got" >&2; failed=1
    fi
  }

  fresh; git checkout -q -b f; test_file c/c_test.go; dev c
  expect "a branch with no QA commit adds a test" green origin/development push

  gate=4
  fresh; change b/b_test.go; qa b; qa_b=$(git rev-parse HEAD); sync development
  git checkout -q -b f; change a/a_test.go; dev a
  expect "a branch with no QA commit of its own edits a test the base approved" \
    "FAIL: test files approved at ${qa_b:0:8}" origin/development push

  fresh; git checkout -q -b f; test_file c/c_test.go; qa c; qa_c=$(git rev-parse HEAD)
  change c/c_test.go; dev c
  expect "a branch's own QA commit, then a non-QA edit to the test it approved" \
    "FAIL: test files approved at ${qa_c:0:8}" origin/development push

  gate=4a
  fresh; git checkout -q -b f; change a/a_test.go; dev a; test_file c/c_test.go; qa c
  expect "a non-QA edit to a test on the base, before the branch's QA commit" \
    "FAIL: a test file on origin/development was changed or deleted by a non-QA commit" origin/development push

  gate=4b
  fresh; git checkout -q -b f; test_file d/d_test.go "$main"; dev d
  expect "a non-QA test file declares TestMain" "FAIL: a non-QA test file declares TestMain" origin/development push
  fresh; git checkout -q -b f; test_file d/d_test.go "$main"; qa d
  expect "a QA commit's test file declares TestMain" green origin/development push
  fresh; git checkout -q -b f; test_file d/d_test.go "$main"; as dev commit -q -m d -m "Helios-Role: qa"
  expect "the QA trailer without the QA key's signature" "FAIL: a non-QA test file declares TestMain" origin/development push

  # The branch is anchored on its own QA commit, which changed a/a_test.go, not on the newer one the
  # base gained; and it is judged against the base as it merged it, before the base changed
  # b/b_test.go and e/e_test.go again.
  fresh; change b/b_test.go; qa b; test_file e/e_test.go "$main"; dev "e, squashed"; sync development
  git checkout -q -b f main; change a/a_test.go; qa a; as loop merge -q --no-ff --no-edit origin/development
  git checkout -q development; change b/b_test.go; qa b; change e/e_test.go; dev "e, squashed"; sync development
  git checkout -q f
  expect "the loop merges the base in, then the base moves on" green origin/development push

  gate=3
  fresh; git checkout -q -b f; change owned/file; as loop commit -q -m owned
  expect "the loop changes an owned file" \
    "FAIL: a loop-authored or loop-committed commit touched a developer-owned path" origin/development push

  fresh; git checkout -q -b g; test_file c/c_test.go; qa c
  git checkout -q -b f development; as loop merge -q --no-ff --no-edit g
  expect "the loop merges a commit the base does not have" \
    "FAIL: the loop's merge" origin/development push

  # GitHub's merge of a pull request is authored by whoever opened it, the loop here, and shows the
  # base's own changes, an owned file's included, beside the branch's.
  fresh; git checkout -q -b f; test_file c/c_test.go; qa c
  git checkout -q development; change b/b_test.go; qa b; change owned/file; dev owned; sync development
  git checkout -q --detach origin/development; as loop merge -q --no-ff --no-edit f
  expect "a pull request's merge, opened by the loop, the base moved on" green origin/development pull_request

  fresh; git checkout -q -b f; change a/a_test.go; qa a
  git checkout -q development; as dev merge -q --no-ff --no-edit f; change b/b_test.go; dev "b, squashed"
  sync development
  expect "a push to development" green origin/development push

  # A push to main is judged against development, which has moved on since the release.
  fresh; change b/b_test.go; qa b; change a/a_test.go; dev "a, squashed"; sync development
  git checkout -q main; as dev merge -q --no-ff --no-edit development; sync main
  git checkout -q development; change b/b_test.go; qa b; change a/a_test.go; dev "a, squashed"; sync development
  git checkout -q main
  expect "a push to main, development ahead of it" green origin/development push

  # A release brings development whole, the loop's catch-up merges with it.
  fresh; change b/b_test.go; qa b; sync development
  git checkout -q -b f main; test_file c/c_test.go; qa c; as loop merge -q --no-ff --no-edit origin/development
  git checkout -q development; as dev merge -q --no-ff --no-edit f; change a/a_test.go; dev "a, squashed"
  sync development
  git checkout -q --detach origin/main; as dev merge -q --no-ff --no-edit origin/development
  expect "a release into main, a loop's catch-up merge on development" green origin/main pull_request

  # Only a head development holds whole is a release. One commit more makes it a change like any
  # other into main, judged against main, so development's own edit to a test counts again.
  gate=4a
  fresh; change a/a_test.go; dev "a, squashed"; sync development
  git checkout -q -b h development; test_file c/c_test.go; dev c
  git checkout -q --detach origin/main; as dev merge -q --no-ff --no-edit h
  expect "a pull request into main with a commit development lacks" \
    "FAIL: a test file on origin/main was changed or deleted by a non-QA commit" origin/main pull_request

  fresh; git checkout -q -b f; test_file c/c_test.go; qa c
  expect "a mutation run" green origin/development push --mutation

  gate=3
  fresh; git checkout -q -b f; test_file c/c_test.go; qa c; qa_c=$(git rev-parse HEAD)
  rm -f ".git/objects/${qa_c:0:2}/${qa_c:2}"
  expect "a commit git cannot read" "FAIL: git could not" origin/development push

  # workflow runner [none] [file]: a workflow of one job on runner, its token granted nothing,
  # written to file (a.yaml unless given), its runs-on line left out when the second argument is
  # "none", committed with the real pins beside it.
  workflow() {
    mkdir -p .github/workflows || fail "self-test: no workflows folder"
    cp "${script%/*}/.github/tool-versions" .github/tool-versions || fail "self-test: no tool pins"
    { printf 'on: push\npermissions: {}\njobs:\n  a:\n'
      [ "${2:-}" = none ] || printf '    runs-on: %s\n' "$1"
      printf '    steps:\n      - run: echo a\n'; } > ".github/workflows/${3:-a.yaml}"
    git add -A && dev workflow
  }
  gate=4k
  fresh; git checkout -q -b f; workflow ubuntu-latest none
  expect "a workflow job with no runner" "FAIL: actionlint: a workflow" origin/development push
  fresh; git checkout -q -b f; workflow ubuntu-latest none A.YML
  expect "a workflow job with no runner, its file's extension in capitals" \
    "FAIL: actionlint: a workflow" origin/development push
  fresh; git checkout -q -b f; workflow ubuntu-26.04-arm
  expect "a workflow on the runner actionlint does not know yet" green origin/development push
  fresh; git checkout -q -b f; workflow ubuntu-99.04
  expect "a workflow on a runner nobody provides" "FAIL: actionlint: a workflow" origin/development push
  fresh; git checkout -q -b f; workflow ubuntu-latest; mkdir -p .github/workflows/parts
  printf 'not a workflow\n' > .github/workflows/parts/b.yml; git add -A && dev "a fragment in a subfolder"
  expect "a file in a folder below the workflows, which GitHub never runs" green origin/development push
  fresh; git checkout -q -b f; workflow ubuntu-99.04
  printf 'self-hosted-runner:\n  labels: [ubuntu-99.04]\n' > .github/actionlint.yaml; git add -A && dev config
  expect "a config file that would excuse a workflow" "FAIL: actionlint's config file" origin/development push
  fresh; git checkout -q -b f; workflow ubuntu-latest
  sed -i 's/^ACTIONLINT=.*/ACTIONLINT=v0.0.0-test/' .github/tool-versions; git add -A && dev "a new pin"
  expect "a new pin of actionlint, its set-aside not tried again" "FAIL: actionlint's pin is no longer" \
    origin/development push
  # shellcheck disable=SC2016 # the sample scripts' dollar signs are theirs, written as they are
  sound='echo "$1"' split='echo $1'
  # A directive written after a space in the samples below would be refused in check.sh itself,
  # which gate 4l reads as it reads any script, so they spell it through this word.
  directive='# shellcheck'
  # On Linux actionlint hands a workflow's scripts to shellcheck; elsewhere it says it skips them.
  fresh; git checkout -q -b f; workflow ubuntu-latest
  printf '      - run: %s\n' "$split" >> .github/workflows/a.yaml; git add -A && dev "a script word-split"
  if [ "$(uname -s)" = Linux ]; then
    expect "a workflow's script shellcheck finds wrong" "FAIL: actionlint: a workflow" origin/development push
  else
    expect "a workflow's script, not read off Linux" green origin/development push
  fi

  # shell_script file first-line body: a shell script at file, its first line and body as given,
  # committed with the real pins beside it.
  shell_script() {
    mkdir -p .github "$(dirname "$1")" || fail "self-test: no folder for $1"
    cp "${script%/*}/.github/tool-versions" .github/tool-versions || fail "self-test: no tool pins"
    printf '%s\n%s\n' "$2" "$3" > "$1"
    git add -A && dev "script $1"
  }
  gate=4l
  fresh; git checkout -q -b f; shell_script a.sh '#!/bin/sh' "$sound"
  expect "a sound shell script" green origin/development push
  fresh; git checkout -q -b f; shell_script a.sh '#!/bin/sh' "$split"
  expect "a shell script shellcheck finds wrong" "FAIL: shellcheck: a shell script" origin/development push
  fresh; git checkout -q -b f; shell_script tools/run '#!/usr/bin/env bash' "$split"
  expect "a shell script known by its first line, not its name" "FAIL: shellcheck: a shell script" \
    origin/development push
  fresh; git checkout -q -b f; shell_script A.SH '#!/bin/sh' "$split"
  expect "a shell script, its name's extension in capitals" "FAIL: shellcheck: a shell script" \
    origin/development push
  fresh; git checkout -q -b f
  shell_script a.sh '#!/bin/sh' "# shellcheck disable=SC2086 # the words are split on purpose
$split"
  expect "a finding set aside with its reason" green origin/development push
  fresh; git checkout -q -b f; shell_script a.sh '#!/bin/sh' "# shellcheck disable=SC2086
$split"
  expect "a finding set aside with no reason" "FAIL: a shellcheck directive" origin/development push
  fresh; git checkout -q -b f; shell_script a.sh '#!/bin/sh' "$split"
  printf 'disable=SC2086\n' > .shellcheckrc; git add -A && dev "an rc file"
  expect "an rc file that would excuse a script" "FAIL: a shellcheck rc file" origin/development push
  fresh; git checkout -q -b f; shell_script a.sh '#!/bin/sh' "$sound"
  sed -i -E 's/^(SHELLCHECK_[A-Z0-9_]+=).*/\1'"$(printf '0%.0s' {1..64})"'/' .github/tool-versions
  git add -A && dev "a hash nobody released"
  expect "a shellcheck archive that does not match its pinned hash" "FAIL: shellcheck's" \
    origin/development push
  # Every form shellcheck takes as a script is read: by its first line through busybox or env -S,
  # by a first-line shell= in a file with no extension, by a .bash name alone, and by a name
  # holding an equals sign; a page that only begins like a directive is no script.
  fresh; git checkout -q -b f; shell_script tools/a '#!/bin/busybox sh' "$split"
  expect "a script known by busybox in its first line" "FAIL: shellcheck: a shell script" origin/development push
  fresh; git checkout -q -b f; shell_script tools/b '#!/usr/bin/env -S bash -e' "$split"
  expect "a script known by env -S in its first line" "FAIL: shellcheck: a shell script" origin/development push
  fresh; git checkout -q -b f; shell_script tools/c '# shellcheck shell=bash' "$split"
  expect "a script known by a first-line shell directive" "FAIL: shellcheck: a shell script" origin/development push
  fresh; git checkout -q -b f; shell_script lib/common.bash '# sourced, no first line of its own' "$split"
  expect "a bash library known by its name alone" "FAIL: shellcheck: a shell script" origin/development push
  fresh; git checkout -q -b f; shell_script 'x=y.sh' '#!/bin/sh' "$split"
  expect "a script whose name holds an equals sign" "FAIL: shellcheck: a shell script" origin/development push
  fresh; git checkout -q -b f; shell_script a.md '# shellcheck shell=bash' 'Notes on the shell gate.'
  expect "a page that begins like a shell directive" green origin/development push
  # Two forms of directive are allowed and every other is refused, in a script or a workflow.
  fresh; git checkout -q -b f; shell_script a.sh '#!/bin/sh' "# shellcheck disable=all # everything
$split"
  expect "a directive that sets every check aside" "FAIL: a shellcheck directive" origin/development push
  fresh; git checkout -q -b f; shell_script a.sh '#!/bin/sh' "# shellcheck source=/dev/null disable=SC2086 # why
$split"
  expect "a directive with another key beside its codes" "FAIL: a shellcheck directive" origin/development push
  fresh; git checkout -q -b f; shell_script a.sh '#!/bin/sh' "# shellcheck disable=SC2086#x
$split"
  expect "a directive whose only hash sign is inside its value" "FAIL: a shellcheck directive" origin/development push
  fresh; git checkout -q -b f; shell_script a.sh '#!/bin/sh' "# shellchecking notes, which the tool reads as a directive
$sound"
  expect "a comment the tool reads as a directive though it names none" "FAIL: a shellcheck directive" \
    origin/development push
  fresh; git checkout -q -b f; shell_script a.sh '#!/bin/sh' "if true; then $directive disable=SC2086 # why
$split
fi"
  expect "a directive after code on its line, which the tool honours" "FAIL: a shellcheck directive" \
    origin/development push
  # A file the branch marks binary is still found and read.
  fresh; git checkout -q -b f; shell_script a.sh '#!/bin/sh' "# shellcheck disable=all # everything
$split"
  echo 'a.sh binary' > .gitattributes; git add -A && dev "marked binary"
  expect "a refused directive in a script marked binary" "FAIL: a shellcheck directive" origin/development push
  fresh; git checkout -q -b f; shell_script tools/d '#!/bin/sh' "$split"
  echo 'tools/d -diff' > .gitattributes; git add -A && dev "marked binary"
  expect "a script known by its first line, marked binary" "FAIL: shellcheck: a shell script" origin/development push
  fresh; git checkout -q -b f; workflow ubuntu-latest
  printf '      - run: |\n          %s disable=SC2086\n          echo a\n' "$directive" >> .github/workflows/a.yaml
  git add -A && dev "a workflow directive with no reason"
  expect "a workflow's directive with no reason, no script tracked" "FAIL: a shellcheck directive" \
    origin/development push
  # The environment's options for shellcheck are cleared.
  fresh; git checkout -q -b f; shell_script a.sh '#!/bin/sh' "$split"
  SHELLCHECK_OPTS='-e SC2086' expect "a finding the machine's own options would excuse" \
    "FAIL: shellcheck: a shell script" origin/development push

  gate=4m
  fresh; git checkout -q -b f; workflow ubuntu-latest
  sed -i '/^permissions:/d' .github/workflows/a.yaml; git add -A && dev "a token granted everything"
  expect "a workflow whose token keeps GitHub's broad default" "FAIL: zizmor: a file above" \
    origin/development push
  fresh; git checkout -q -b f; workflow ubuntu-latest
  sed -i -e '/^permissions:/d' -e 's/^  a:$/  a: # zizmor: ignore[excessive-permissions]/' .github/workflows/a.yaml
  git add -A && dev "a finding silenced"
  expect "a zizmor finding silenced by its own comment" "FAIL: zizmor: a file above" origin/development push
  fresh; git checkout -q -b f; workflow ubuntu-latest
  printf 'rules:\n  excessive-permissions:\n    disable: true\n' > zizmor.yml; git add -A && dev "a config"
  expect "a zizmor config file" "FAIL: zizmor's config file" origin/development push
  fresh; git checkout -q -b f; mkdir -p .github
  cp "${script%/*}/.github/tool-versions" .github/tool-versions || fail "self-test: no tool pins"
  printf 'version: 2\nupdates:\n  - package-ecosystem: gomod\n    directory: /\n    schedule:\n      interval: weekly\n' \
    > .github/dependabot.yml
  git add -A && dev "Dependabot with no cooldown"
  expect "Dependabot's settings with no wait for a new release" "FAIL: zizmor: a file above" \
    origin/development push
  fresh; git checkout -q -b f; workflow ubuntu-latest
  printf 'lock\n' > .github/workflows/actions.lock; git add -A && dev "a lockfile"
  expect "zizmor's lockfile" "FAIL: zizmor's config file or lockfile" origin/development push
  fresh; git checkout -q -b f; workflow ubuntu-latest '' A.YML
  expect "a sound workflow zizmor cannot read, its extension in capitals" "FAIL: zizmor reads a workflow only" \
    origin/development push
  fresh; git checkout -q -b f; mkdir -p .github
  cp "${script%/*}/.github/tool-versions" .github/tool-versions || fail "self-test: no tool pins"
  printf 'repos: [unclosed\n' > .pre-commit-config.yaml; git add -A && dev "a pre-commit file"
  expect "a pre-commit file zizmor cannot parse" "FAIL: zizmor could not judge" origin/development push

  gate=4n
  fresh; git checkout -q -b f; shell_script a.sh '#!/bin/sh' 'false || true'
  expect "a failure swallowed with no reason" "FAIL: a failure is swallowed" origin/development push
  fresh; git checkout -q -b f; shell_script a.sh '#!/bin/sh' 'false || true # nothing reads the answer'
  expect "a failure swallowed with its reason" green origin/development push
  fresh; git checkout -q -b f; workflow ubuntu-latest
  printf '      - run: false || true\n' >> .github/workflows/a.yaml; git add -A && dev "a step swallowed"
  expect "a workflow step's failure swallowed with no reason" "FAIL: a failure is swallowed" \
    origin/development push
  fresh; git checkout -q -b f; shell_script a.sh '#!/bin/sh' 'false || true'
  echo 'a.sh binary' > .gitattributes; git add -A && dev "marked binary"
  expect "a failure swallowed in a script marked binary" "FAIL: a failure is swallowed" origin/development push
  # A gate that reads through awk fails, saying so, when a file it must read is gone.
  gate=4c
  fresh; git checkout -q -b f; printf 'package x\n' > x.go; git add -A && dev "a Go file"; rm x.go
  expect "a tracked Go file the gates cannot read" "FAIL: git or awk could not read the Go files" \
    origin/development push

  # go_file file comment-or-code: a Go file holding the line given, committed.
  go_file() {
    mkdir -p "$(dirname "$1")" || fail "self-test: no folder for $1"
    printf 'package x\n\n%s\n' "$2" > "$1"
    git add -A && dev "Go file $1"
  }
  gate=1
  fresh; git checkout -q -b f; seq 101 > CLAUDE.md; git add -A && dev "long rules"
  expect "a rules file past its cap" "FAIL: CLAUDE.md is 101 lines" origin/development push
  gate=2
  fresh; git checkout -q -b f; mkdir -p docs/spec; echo 'Written in golang.' > docs/spec/a.md
  git add -A && dev "a spec"
  expect "a spec that names the implementation" "FAIL: docs/spec names the implementation" origin/development push
  gate=4c
  fresh; git checkout -q -b f; go_file x.go '// As said at line 12 above.'
  expect "a comment naming a line number" "FAIL: a comment carries a line or step number" origin/development push
  gate=4d
  fresh; mkdir -p .github; echo a > .github/a; git add -A && dev "development's copy"; sync development
  git checkout -q main
  expect "main without development's .github" "FAIL: .github/ differs from development" origin/main push
  gate=4e
  fresh; git checkout -q -b f; go_file x.go 'var a = 1 //nolint:gosec'
  expect "a security linter silenced" "FAIL: a security linter is silenced" origin/development push
  # A file the branch marks binary, or that holds a NUL byte, is still read line by line.
  fresh; git checkout -q -b f; go_file x.go 'var a = 1 //nolint:gosec'
  echo 'x.go binary' > .gitattributes; git add -A && dev "marked binary"
  expect "a security linter silenced in a file marked binary" "FAIL: a security linter is silenced" \
    origin/development push
  fresh; git checkout -q -b f; printf 'package x\n\nvar a = 1 //nolint:gosec\n// \000\n' > x.go
  git add -A && dev "a NUL byte"
  expect "a security linter silenced in a file holding a NUL byte" "FAIL: a security linter is silenced" \
    origin/development push
  gate=4f
  fresh; git checkout -q -b f; go_file x/contracts.go '// Rules.'
  expect "a second contract file" "FAIL: a second contract file beside contract.go" origin/development push
  fresh; git checkout -q -b f; go_file x/x.go '// The unit shall answer.'
  expect "a unit line outside contract.go" "FAIL: a unit line outside contract.go" origin/development push
  gate=4g
  fresh; git checkout -q -b f; go_file x.go "// $(printf 'a%.0s' {1..100})"
  expect "a comment line past 100 columns" "FAIL: a comment line runs past 100 columns" origin/development push
  # awk takes a name holding = as a setting, so gates 4g and 4j hand it each name with ./ before it.
  fresh; git checkout -q -b f; go_file 'x=y.go' "// $(printf 'a%.0s' {1..100})"
  expect "a long comment in a file whose name holds an equals sign" "FAIL: a comment line runs past 100 columns" \
    origin/development push
  gate=4h
  fresh; git checkout -q -b f
  printf '            - github.com/heliosestate/heliosadvance/internal/x\n' >> .golangci.yml
  git add -A && dev "an import rule without its end"
  expect "an import rule that names a path without a closing dollar sign" "FAIL: an import rule names" \
    origin/development push
  gate=4i
  fresh; git checkout -q -b f; go_file x.go 'import _ "github.com/heliosestate/heliosadvance/internal/testrun"'
  expect "the test support imported outside a test" "FAIL: a file that is not a test imports the test support" \
    origin/development push
  gate=4j
  fresh; git checkout -q -b f; go_file x.go "// As the issue ${hash}12 says."
  expect "a comment naming an issue by number" "FAIL: a comment names an issue or pull request by number" \
    origin/development push
  fresh; git checkout -q -b f; go_file 'x=y.go' "// As the issue ${hash}12 says."
  expect "an issue number in a file whose name holds an equals sign" \
    "FAIL: a comment names an issue or pull request by number" origin/development push

  # Every gate above the Go gates has a case that makes it refuse. The Go gates (5) are the
  # tools' own: the linter, the vulnerability and licence checks and the tests, which a fake
  # repository cannot hold.
  while read -r heading; do
    [ "$heading" = 5 ] || [[ $refused_gates == *" $heading "* ]] || missing="$missing $heading"
  done < <(sed -n -E 's/^# ([0-9]+[a-z]?)\. .*/\1/p' "$script")
  [ -z "$missing" ] || { echo "self-test: no case makes these gates refuse:$missing" >&2; failed=1; }

  [ "$failed" = 0 ] || fail "self-test: a case above did not go as it should"
  echo "self-test: green"
}
# Called from an if's body, not an && list, so set -e holds inside it.
if [ "${1:-}" = --self-test ]; then self_test; exit 0; fi
# pinned name module pin: prints the path of the Go tool name at the version .github/tool-versions
# pins as pin, built by the Go in use, installed into a folder of its own for that version and that
# Go when it is missing there. Whatever version is on the path is never run, so every machine runs
# what CI runs, and a pin moved by its pull request moves every machine (the developer, 2026-11-05:
# "it should install it if it's missing"). The install is a go install: Go's module proxy and
# checksum database fix what a version holds, as in CI, unless the machine's own Go settings turn
# them off. It goes to a folder beside its own and is renamed into place, so a check running beside
# this one never runs a half-written tool. Each tool's version and the Go that built it go to the
# log. It runs inside $(...), where set -e does not hold, so every step fails by itself.
pinned() {
  local version goenv gopath goversion hostos sep dir tmp
  version=$(sed -n "s/^$3=//p" .github/tool-versions | tr -d '\r') || fail "reading .github/tool-versions failed"
  [[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || fail "$3 in .github/tool-versions is not a module version like v1.2.3, so $1 cannot be run at its pin"
  goenv=$(go env GOPATH GOVERSION GOHOSTOS | tr -d '\r') || fail "go env failed, so $1 has no folder"
  { read -r gopath; read -r goversion; read -r hostos; } <<< "$goenv"
  # A GOPATH of several entries installs into its first, as go install does.
  sep=:; [ "$hostos" = windows ] && sep=';'
  gopath=${gopath%%"$sep"*}
  [ -n "$gopath" ] && [ -n "$goversion" ] && [ -n "$hostos" ] || fail "go env gave no GOPATH, GOVERSION or GOHOSTOS, so $1 has no folder"
  dir="$gopath/hadv-tools/$1/$version-$goversion"
  if [ ! -x "$dir/$1" ]; then
    mkdir -p "${dir%/*}" || fail "could not make ${dir%/*}"
    tmp=$(mktemp -d "${dir%/*}/.install.XXXXXX") || fail "could not make a folder to install $1 into"
    GOBIN="$tmp" go install "$2@$version" >&2 || { rm -rf "$tmp"; fail "$1 $version could not be installed from $2"; }
    mv -T "$tmp" "$dir" 2>/dev/null || rm -rf "$tmp" # another check installed it first
  fi
  [ -x "$dir/$1" ] || fail "$1 $version is not in $dir: remove that folder and run the check again"
  echo "check: $1 $version, built by $goversion" >&2
  echo "$dir/$1"
}
# released tool: prints the path of shellcheck or zizmor at the release .github/tool-versions pins
# under the tool's name in capitals, downloaded from its GitHub releases when missing. Neither is a
# Go module, so no checksum database stands behind them: what is trusted is the SHA-256 pinned
# beside the release for this system's archive (the developer, 2026-11-17), checked before the
# archive is unpacked. The folder is named for the version and the hash, so a moved pin or hash
# downloads again, and it is renamed into place, as pinned's is. A system with no archive pinned
# fails, naming itself. Once installed, the program is trusted as pinned's Go tools are: the
# folder is this machine's own, and only a matching archive ever reaches it. It runs inside
# $(...), where set -e does not hold, so every step fails by itself.
released() {
  local tool=$1 name version os arch system repository archive member exe pin hash goenv gopath hostos sep dir tmp got
  name=${tool^^}
  version=$(sed -n "s/^$name=//p" .github/tool-versions | tr -d '\r') || fail "reading .github/tool-versions failed"
  [[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "$name in .github/tool-versions is not a release like v1.2.3, so $tool cannot be run at its pin"
  os=$(uname -s) || fail "uname failed, so no $tool archive can be chosen"
  arch=$(uname -m) || fail "uname failed, so no $tool archive can be chosen"
  case "$os $arch" in
    "Linux x86_64") system=LINUX_X86_64 ;;
    "Linux aarch64") system=LINUX_AARCH64 ;;
    "MINGW64_NT"*" x86_64" | "MSYS_NT"*" x86_64") system=WINDOWS_X86_64 ;;
    *) fail "no $tool archive is pinned for $os $arch in .github/tool-versions" ;;
  esac
  # Each release's own names: its repository, and for each system the archive and the program in it.
  case "$tool $system" in
    "shellcheck LINUX_X86_64") repository=koalaman/shellcheck archive=shellcheck-$version.linux.x86_64.tar.gz member=shellcheck-$version/shellcheck ;;
    "shellcheck LINUX_AARCH64") repository=koalaman/shellcheck archive=shellcheck-$version.linux.aarch64.tar.gz member=shellcheck-$version/shellcheck ;;
    "shellcheck WINDOWS_X86_64") repository=koalaman/shellcheck archive=shellcheck-$version.zip member=shellcheck.exe ;;
    "zizmor LINUX_X86_64") repository=zizmorcore/zizmor archive=zizmor-x86_64-unknown-linux-gnu.tar.gz member=zizmor ;;
    "zizmor LINUX_AARCH64") repository=zizmorcore/zizmor archive=zizmor-aarch64-unknown-linux-gnu.tar.gz member=zizmor ;;
    "zizmor WINDOWS_X86_64") repository=zizmorcore/zizmor archive=zizmor-x86_64-pc-windows-msvc.zip member=zizmor.exe ;;
    *) fail "check.sh names no release of $tool" ;;
  esac
  exe=${member##*/}
  pin=${name}_$system
  hash=$(sed -n "s/^$pin=//p" .github/tool-versions | tr -d '\r') || fail "reading .github/tool-versions failed"
  [[ $hash =~ ^[0-9a-f]{64}$ ]] || fail "$pin in .github/tool-versions is not a SHA-256, so $tool's archive cannot be checked"
  goenv=$(go env GOPATH GOHOSTOS | tr -d '\r') || fail "go env failed, so $tool has no folder"
  { read -r gopath; read -r hostos; } <<< "$goenv"
  sep=:; [ "$hostos" = windows ] && sep=';'
  gopath=${gopath%%"$sep"*}
  [ -n "$gopath" ] || fail "go env gave no GOPATH, so $tool has no folder"
  dir="$gopath/hadv-tools/$tool/$version-${hash:0:16}"
  if [ ! -x "$dir/$exe" ]; then
    need curl "curl, to fetch $tool's release"
    need sha256sum "sha256sum, from the system's core utilities"
    mkdir -p "${dir%/*}" || fail "could not make ${dir%/*}"
    tmp=$(mktemp -d "${dir%/*}/.install.XXXXXX") || fail "could not make a folder to install $tool into"
    curl -fsSL --retry 3 -o "$tmp/$archive" "https://github.com/$repository/releases/download/$version/$archive" ||
      { rm -rf "$tmp"; fail "fetching $tool's $archive failed"; }
    got=$(sha256sum < "$tmp/$archive" | cut -d' ' -f1) || { rm -rf "$tmp"; fail "sha256sum could not read $tool's $archive"; }
    [ "$got" = "$hash" ] || { rm -rf "$tmp"; fail "$tool's $archive has SHA-256 $got, not the $hash .github/tool-versions pins as $pin"; }
    case $archive in
      *.zip) need unzip "unzip, to unpack $tool's release"; unzip -q -o "$tmp/$archive" "$member" -d "$tmp" ;;
      *) tar -xzf "$tmp/$archive" -C "$tmp" --strip-components="$(tr -cd / <<< "$member" | wc -c)" "$member" ;;
    esac || { rm -rf "$tmp"; fail "could not unpack $exe from $tool's $archive"; }
    rm -f "$tmp/$archive"
    mv -T "$tmp" "$dir" 2>/dev/null || rm -rf "$tmp" # another check installed it first
  fi
  [ -x "$dir/$exe" ] || fail "$tool $version is not in $dir: remove that folder and run the check again"
  echo "check: $tool $version, its archive matching the SHA-256 pinned as $pin" >&2
  echo "$dir/$exe"
}
# Gates 3, 4a and 4e judge this branch against $BASE. Without it they cannot run, and a gate that
# cannot run fails: fetch the base, or name in BASE the commit to judge from.
if [ "$MUTATION" = 0 ]; then
  git rev-parse -q --verify "$BASE" >/dev/null 2>&1 || fail "$BASE does not resolve, so the gates that judge this branch against it cannot run: fetch it, or set BASE to the commit to judge from"
fi

# 1. The standing instructions stay short. A repository with no CLAUDE.md yet has none to cap,
# and says so.
if [ -f CLAUDE.md ]; then
  lines=$(wc -l < CLAUDE.md)
  [ "$lines" -le 100 ] || fail "CLAUDE.md is $lines lines; the cap is 100"
else
  echo "no CLAUDE.md: nothing to cap"
fi

# 2. Specs are language-neutral.
if [ -d docs/spec ]; then
  # grep answers 1 for no match, which is the pass; more is a file it could not read.
  hits=$(grep -rnE 'err != nil|pgx\.|context\.Context|goroutine|\binternal/[a-z]+|[a-z]+\.go\b|golang|lua_' docs/spec) ||
    [ $? = 1 ] || fail "grep could not read docs/spec"
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
# A list that cannot be read fails here by itself, never as one naming nothing.
mapfile -t owned < <(list_of developer-owned-paths | sed -e 's/#.*//' -e 's/[[:space:]]//g' | awk 'NF')
wait $! || fail "developer-owned-paths could not be read"
[ "${#owned[@]}" -gt 0 ] || fail "developer-owned-paths names no path"
mapfile -t loops < <(list_of loop-identities | sed -e 's/#.*//' -e 's/[[:space:]]//g' | awk 'NF')
wait $! || fail "loop-identities could not be read"
[ "${#loops[@]}" -gt 0 ] || fail "loop-identities names no identity"
# A loop's commit: its author or its committer address is <id>+<login>@ or <login>@ for a login
# on the list. The committer counts too: an amend, rebase or squash by a loop keeps the earlier
# author and makes the loop the committer.
is_loop_address() { local id; for id in "${loops[@]}"; do case "$1" in *"+$id@"*|"$id@"*) return 0 ;; esac; done; return 1; }
is_loop() { is_loop_address "$1" || is_loop_address "${2:-}"; }
tip=HEAD
if [ "$MUTATION" = 0 ]; then
  # On a pull request CI checks out GitHub's merge of the branch into the base, which GitHub
  # authors as whoever opened the PR, and which a branch behind the base shows as touching
  # owned paths: judge the branch's own commits, up to its head, the merge's second parent.
  if [ "${GITHUB_EVENT_NAME:-}" = pull_request ]; then
    tip=$(git rev-parse -q --verify 'HEAD^2') || fail "a pull request's checkout is not GitHub's merge"
  fi
fi
# A release is a change into main that development already holds whole. Every commit it brings
# passed gates 3, 4, 4a and 4b on development, judged against development, so a release is judged
# the same way: only what it adds beyond development counts. Judged against main, which lags,
# every catch-up merge of the loop's on development merges commits main lacks, and two tests
# approved side by side on development read as changed since the newer QA commit: a release would
# fail with nothing wrong. Gates 3 and 4a leave development's commits out (exclude); gates 4 and 4b
# take their anchor and copies from development (lock_base). Anything else into main, a head
# holding a commit development lacks, is judged against main.
exclude=(); lock_base=$BASE
if [ "$MUTATION" = 0 ] && [ "$BASE" = origin/main ] && git rev-parse -q --verify origin/development >/dev/null 2>&1; then
  # git answers 1 for "not held whole" and more when it fails, which must not read as an answer.
  held=0; git merge-base --is-ancestor "$tip" origin/development || held=$?
  case $held in
    0) exclude=(--not origin/development); lock_base=origin/development
      echo "check: a release, which development holds whole: judged as development judged it" >&2 ;;
    1) echo "check: into main with a commit development lacks: judged against main" >&2 ;;
    *) fail "git could not tell whether development holds this head whole" ;;
  esac
fi
if [ "$MUTATION" = 0 ]; then
  # git's output is taken whole first, so a git that fails fails the gate instead of reading as
  # no commits (the codebase review, 2026-10-24).
  touched=$(git log --no-merges --format='%h %ae %ce' "$BASE..$tip" "${exclude[@]}" -- "${owned[@]}") ||
    fail "git could not list the branch's commits to owned paths"
  loop=$(while read -r h a c; do [ -n "$h" ] && is_loop "$a" "$c" && echo "$h $a $c"; done <<< "$touched"; true)
  [ -z "$loop" ] || { echo "$loop"; fail "a loop-authored or loop-committed commit touched a developer-owned path"; }
  # A loop catches up by merging the base in, which shows the base's owned edits as its own. A
  # loop's merge passes when its second side is already in the base and each owned path is as a
  # clean merge leaves it: the base's copy, or the branch's where the base has not changed it
  # since the two sides parted. Keeping the branch's older copy would undo the base's edit.
  merges=$(git log --merges --format='%H %ae %ce' "$BASE..$tip" "${exclude[@]}") || fail "git could not list the branch's merges"
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
      { git diff --quiet "$parted" "$merge^2" -- ":(literal)$path" && git diff --quiet "$merge^1" "$merge" -- ":(literal)$path"; } ||
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
# A commit git cannot read fails the check, and so does a missing ssh-keygen when a signature must
# be checked: either, read as "not a QA commit", would move the gates' anchor or drop it without a
# word. git is told to use ssh-keygen itself, whatever its own settings name. A signature check
# that runs and fails is still read as "not a QA commit", since git does not tell a bad signature
# from a check that broke.
is_qa() {
  local body id
  [ -n "$1" ] || return 1
  body=$(git log -1 --format=%B "$1") || fail "git could not read commit $1, so it cannot be judged"
  grep -q '^Helios-Role: qa$' <<< "$body" || return 1
  id=$(git rev-parse "$1^{commit}") || fail "git could not read commit $1, so it cannot be judged"
  grep -qxF "$id" <<< "$grandfathered" && return 0
  [ -s "$signers" ] || return 1
  need ssh-keygen "OpenSSH's, which git uses to check a QA commit's signature"
  git -c gpg.format=ssh -c gpg.ssh.program=ssh-keygen -c gpg.ssh.allowedSignersFile="$signers" \
    verify-commit "$id" >/dev/null 2>&1
}
# Paths are read NUL-separated and git quotes nothing, and each goes back to git as :(literal), so
# a name with a space, a quote, a newline or git's pattern syntax is judged like any other, in
# gates 4, 4a and 4b alike; renames are split into a deletion and an addition (--no-renames), so a renamed
# or retyped test is a change to the approved one (the codebase review, 2026-10-24).
# The anchor is this branch's own newest QA commit, one the base does not hold, when it has one;
# otherwise the newest in the whole history, as before. Taken from the whole history alone, a QA
# commit the base gained since, from another issue's tests, came first in a merge with the base,
# and every test this branch's own QA commits approved read as changed. Where the branch has no
# QA commit of its own (a push to the base or to main, a branch already merged), nothing changes.
first_qa() {
  local log c
  log=$(git log --format=%H --grep='^Helios-Role: qa$' "$@") ||
    fail "git could not list the QA commits, so the approved tests cannot be checked"
  for c in $log; do is_qa "$c" && { echo "$c"; return 0; }; done
  return 0
}
qa=""
# The base for gates 4 and 4b is lock_base: development for a release into main, as above gate 3.
onbase=0; git rev-parse -q --verify "$lock_base" >/dev/null 2>&1 && onbase=1
# merged is the base as this branch last took it in, the merge base of HEAD and the base: gates 4
# and 4b spare a test held as it was there, so a test the base changed after this branch's last
# merge from it is not read as this branch's change. Empty when it cannot be found: none is spared.
merged=""
if [ "$onbase" = 1 ]; then merged=$(git merge-base HEAD "$lock_base") || merged=""; fi
[ "$onbase" = 1 ] && qa=$(first_qa "$lock_base..HEAD")
[ -n "$qa" ] || qa=$(first_qa)
[ -n "$qa" ] || echo "check: no QA commit in this history, so no test is locked by one yet" >&2
if [ -n "$qa" ]; then
  # The base moves on after a QA commit, and a squash merge drops its own QA commits' trailer, so
  # a test approved on the base since shows here as changed. It came from the base when the QA
  # commit left it as it found it and HEAD holds it as the base held it when this branch last took
  # it in (merged, above); gate 4a locks the base's tests. The base's copy over a test this QA
  # commit changed is still a change to it.
  forked=""
  if [ "$onbase" = 1 ]; then forked=$(git merge-base "$qa" "$lock_base") || forked=""; fi
  changed=$(while IFS= read -r -d '' f; do
      [ -n "$forked" ] && [ -n "$merged" ] && git diff --quiet "$forked" "$qa" -- ":(literal)$f" &&
        git diff --quiet "$merged" HEAD -- ":(literal)$f" && continue
      echo "$f"
    done < <(git diff -z --no-renames --name-only --diff-filter=MDT "$qa" HEAD -- '*_test.go')
    wait $!) || fail "git could not list the tests changed since the QA commit"
  [ -z "$changed" ] || { echo "$changed"; fail "test files approved at ${qa:0:8} were changed or deleted"; }
fi
# 4a. A squash merge drops the trailer, so the anchor above is absent on the base. A test
# file already on the base is locked for every branch: only a QA commit may change or delete it.
# On a release, which development holds whole, its commits passed this gate there and are left
# out (exclude, above gate 3), so a release is never failed over a QA change that a squash merge
# brought to development (the codebase review, 2026-10-24).
if [ "$MUTATION" = 0 ]; then
  while IFS= read -r -d '' f; do
    commits=$(git log --format=%H "$BASE..HEAD" "${exclude[@]}" -- ":(literal)$f") || fail "git could not list the commits to $f"
    # A merge whose copy of the file is one of its parents' adds nothing of its own: git lists it
    # when that parent is on the base and the other side's copy differs, and every change on the
    # other side is a commit of its own, judged here or on the base. A merge that writes what
    # neither parent had is judged like any commit.
    nonqa=$(for c in $commits; do
      parents=$(git rev-list --parents -n 1 "$c" | cut -s -d' ' -f2-)
      case $parents in *' '*)
        for p in $parents; do git diff --quiet "$p" "$c" -- ":(literal)$f" && continue 2; done ;;
      esac
      is_qa "$c" || echo "$c"; done)
    [ -z "$nonqa" ] || { echo "$f: $nonqa"; fail "a test file on $BASE was changed or deleted by a non-QA commit"; }
  done < <(git diff -z --no-renames --name-only --diff-filter=MDT "$BASE...HEAD" -- '*_test.go')
  wait $! || fail "git could not list the tests this branch changed"
fi
# 4b. A test file not from a QA commit may not run before the approved ones. A file held as the
# base held it when this branch last took it in (merged, above) passed this gate on its own branch
# before it merged; a squash merge drops the trailer that showed it. A name ending in an operating
# system or a processor, as Go lists them, is a build constraint as much as a //go:build line
# (developer, 2026-10-27).
goos=$(go tool dist list | cut -d/ -f1 | sort -u | paste -sd'|' -)
goarch=$(go tool dist list | cut -d/ -f2 | sort -u | paste -sd'|' -)
while IFS= read -r -d '' f; do
  [ -n "$merged" ] && git diff --quiet "$merged" HEAD -- ":(literal)$f" && continue
  last=$(git log -1 --format=%H -- ":(literal)$f")
  is_qa "$last" && continue
  bad=$(grep -nE '^func (TestMain|init)\(|^//go:build' -- "$f") || [ $? = 1 ] || fail "grep could not read $f"
  [ -z "$bad" ] || { echo "$f: $bad"; fail "a non-QA test file declares TestMain, init or a build tag"; }
  stem=${f##*/}; stem=${stem%_test.go}
  if [[ $stem =~ _($goos)(_($goarch))?$ || $stem =~ _($goarch)$ ]]; then
    echo "$f"; fail "a non-QA test file is named for an operating system or a processor, a build constraint"
  fi
done < <(git ls-files -z '*_test.go')

# 4c. A comment never carries a line number or a step number: both drift silently. Attempt
# one measured 66 drifted line numbers and 154 dead citations in its docs. Approved tests
# are exempt: a row names the behaviour line it proves. The gates that search tracked files use git
# grep, which answers 1 for no match, the pass, and more when it could not search, which fails the
# gate rather than reading as nothing found. Every gate reads a file's lines as text (git grep
# -a, git diff --text): a branch can mark any file binary in .gitattributes, or put a NUL byte in
# it, and git would then show no line of it, so the gate would see nothing. git grep is also told
# --no-column, since a user's own git settings could add that field to its answer.
pointers=$(git grep -a --no-column -n -i -E '//.*[^[:alpha:]](line|step) [0-9]+' -- '*.go' ':!*_test.go') ||
  [ $? = 1 ] || fail "git grep could not search the Go files"
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
  added=$(git diff --text -U0 "$BASE...HEAD" -- '*.go') || fail "git could not show what this branch adds"
  # grep answers 1 when no added line matches, the pass; more is a failure to read.
  silenced=$(grep -E '^\+' <<< "$added" |
    grep -E '//[[:space:]]*nolint([[:space:]]|$)|//[[:space:]]*nolint:[^/]*\b(gosec|forbidigo|depguard|all)\b|#nosec') ||
    [ $? = 1 ] || fail "grep could not read what this branch adds"
  [ -z "$silenced" ] || { echo "$silenced"; fail "a security linter is silenced: fix the finding, or bring it to the developer"; }
fi

# 4f. A package's specification lives in one file, its contract.go. The developer: "There
# should never be 2 contracts.go living side by side. final spec is the truth." So no
# other Go file is named for a contract, and none but a test carries a "shall" in a comment,
# which is how a unit line reads.
go_files=$(git ls-files '*.go') || fail "git could not list the Go files"
specs=$(grep -v '_test\.go$' <<< "$go_files" | grep -v '/contract\.go$' | grep -i 'contract') ||
  [ $? = 1 ] || fail "grep could not read the list of Go files"
[ -z "$specs" ] || { echo "$specs"; fail "a second contract file beside contract.go: a package's specification is its contract.go alone"; }
specs=$(git grep -a --no-column -n -w -E '//.*shall' -- '*.go' ':!*_test.go' ':!*/contract.go') ||
  [ $? = 1 ] || fail "git grep could not search the Go files"
[ -z "$specs" ] || { echo "$specs"; fail "a unit line outside contract.go: a package's specification is its contract.go alone"; }

# 4g. A comment line is at most 100 columns, a tab counted as four: the width the comments are
# wrapped to, which reviews checked by eye until a review round and two noticed issues went to
# it. Code lines have no limit, since a test row quotes its behavior line whole. A line holding a
# link is exempt, since a link does not wrap. This gate and 4j read files with awk, which takes a
# name holding = as a setting rather than a file, so each name reaches it with ./ before it.
# shellcheck disable=SC2016 # the dollar sign is awk's own field, not the shell's
long=$(git ls-files -z '*.go' | sed -z 's|^|./|' | xargs -0 -r awk '/^[ \t]*\/\// && !/:\/\// {
  line = $0; gsub(/\t/, "    ", line)
  if (length(line) > 100) print FILENAME ":" FNR ": " length(line) " columns"
}') || fail "git or awk could not read the Go files"
[ -z "$long" ] || { echo "$long"; fail "a comment line runs past 100 columns: wrap it, or shorten a nolint's reason"; }

# 4h. An import rule names each of the engine's own packages exactly. The linter reads an allowed
# entry as a prefix unless it ends in $, so an entry without it lets in every package whose path
# only begins the same way; a merge that keeps the other side of a conflict would bring one back
# with everything green. Each of the engine's paths in the file is judged, written plainly,
# quoted, in a one-line list or mapping, or on the line after a folded marker, once comments are
# taken off; a deny entry's own lines are left out, since there $ narrows what is blocked. The
# dependencies rule's module-wide entry, ending in /, is the one exception, and there is one. This
# catches what a merge or a slip brings back, not a disguise (a shortened path, a reference to
# another rule's list, an escape, a # inside quotes): the file is the developer's, and his review
# of every change to it is the check for that.
[ -f .golangci.yml ] || fail "the import rules (.golangci.yml) are missing, so they cannot be checked"
paths=$(sed -E '/^[[:space:]]*(- )?(pkg|desc):/s/.*//' .golangci.yml | sed 's/#.*//' |
  grep -noE "github\.com/heliosestate/heliosadvance[^]}\"'[:space:],]*") ||
  fail "no path of the engine's own was found in .golangci.yml, so its import rules cannot be checked"
loose=$(grep -vE ':(github\.com/heliosestate/heliosadvance/|.*\$)$' <<< "$paths") ||
  [ $? = 1 ] || fail "grep could not read the import rules' paths"
[ -z "$loose" ] || { echo "$loose"; fail "an import rule names one of the engine's paths without a closing \$"; }
# grep -c prints 0 and answers 1 when no line matches.
wide=$(grep -cE ':github\.com/heliosestate/heliosadvance/$' <<< "$paths") ||
  [ $? = 1 ] || fail "grep could not read the import rules' paths"
[ "$wide" = 1 ] || fail "the import rules hold the engine's module-wide entry $wide times, not once"

# 4i. The test support (internal/testrun) is for tests: no other file imports it, whatever its
# build tags, which the linter's import rules do not see (a file built only for the race detector).
leak=$(git grep -a -l -F '"github.com/heliosestate/heliosadvance/internal/testrun"' -- '*.go' ':!*_test.go' \
  ':!internal/testrun/*') || [ $? = 1 ] || fail "git grep could not search the Go files"
[ -z "$leak" ] || { echo "$leak"; fail "a file that is not a test imports the test support"; }

# 4j. A comment says its reason, never an issue's or a pull request's number for a reader to look
# up (the developer, 2026-10-03: "I do not want IDs in public documents. Comments, etc, should be
# readable without having to go reference something else."). Reviews kept missing such numbers
# by eye, as with the width above. A backstop, not the test of the rule, which stays review's: it
# reads one line at a time, from the comment's marker to the line's end. That is after // in Go
# files and go.mod files, so a Go block comment goes unread whole; after // in Free Pascal files,
# or after { or (* up to its close on that line; and from a # that opens the line or follows a
# space or tab in shell, workflow, Dockerfile and Makefile files. So the lines inside a block
# comment go unread, and quotes are not parsed: a string after the marker counts as comment, so
# reword it. A comment fails when it holds a number after a lone hash sign (not in Free Pascal,
# where a hash sign and a number make a character), after a repository's name, "PR", "pull
# request" or "issue" (joined, spaced, or with "number" or "no."), or after /issues/ or /pull/ in
# a link. A lone hash sign before a number fails even as an ordinal: write "first", not the number.
# shellcheck disable=SC2016 # the dollar signs are awk's own fields, not the shell's
numbered=$(git ls-files -z '*.go' '*go.mod' '*.pas' '*.sh' '*.yml' '*.yaml' '*Dockerfile' '*Makefile' |
  sed -z 's|^|./|' | xargs -0 -r awk '
  FNR == 1 { slash = (FILENAME ~ /(\.go|(^|\/)go\.mod)$/); pas = (FILENAME ~ /\.pas$/) }
  {
    text = ""
    if (slash) {
      if ((at = index($0, "//"))) text = substr($0, at + 2)
    } else if (pas) {
      if (match($0, /\/\/|\{|\(\*/)) {
        opener = substr($0, RSTART, RLENGTH); text = substr($0, RSTART + RLENGTH)
        closer = (opener == "{") ? "}" : (opener == "(*") ? "*)" : ""
        if (closer != "" && (at = index(text, closer))) text = substr(text, 1, at - 1)
      }
    } else if (match($0, /(^|[ \t])#/)) {
      text = substr($0, RSTART + RLENGTH - 1)
    }
    if (text == "") next
    text = tolower(text)
    # A standard named with a hash sign, such as PKCS #1 or PKCS#8, is not a lookup.
    gsub(/pkcs ?#[0-9]+/, "", text)
    if ((!pas && text ~ /(^|[^a-z0-9&\/])#[0-9]+([^a-z0-9]|$)/) ||
        text ~ /(^|[^a-z0-9])(helios(design|advance|loop)|pr|issue|pull)#[0-9]+/ ||
        text ~ /(^|[^a-z0-9])(prs?|pull[ -]requests?|issues?)[ -](number |no\. ?)?#?[0-9]+([^a-z0-9]|$)/ ||
        text ~ /\/(issues|pull)\/[0-9]+/)
      print FILENAME ":" FNR ": " $0
  }') || fail "git or awk could not read the files"
[ -z "$numbered" ] || { echo "$numbered"; fail "a comment names an issue or pull request by number: say its reason in words"; }

# The workflow and shell gates (4k to 4n) read the same files, listed once here from what git
# tracks, by each tool's own rules (its manual and source at its pin). No tool is let find files
# by itself, read a config file, or take options from the environment: the gates' answer depends
# on the tracked files and this script alone.
#
# workflow_files: every file GitHub might run as a workflow, a .yml or .yaml file straight in
# .github/workflows, the folder and the extension in any case. GitHub's documentation spells them
# in lower case and does not say whether case counts, so a file GitHub might run is never left
# unread, at the cost of reading one it would not.
mapfile -d '' -t workflow_files < <(git ls-files -z ':(glob,icase).github/workflows/*.yml' \
  ':(glob,icase).github/workflows/*.yaml')
wait $! || fail "git could not list the workflows"
#
# shell_files: every tracked file shellcheck judges as a shell script, by shellcheck's own rules:
# a name ending .sh, .bash, .bats, .dash or .ksh, in any case; a first line #! naming one of its
# shells (sh, bash, bats, dash, ash, ksh, ksh88, ksh93, oksh, or busybox with sh or ash), by path
# or through env, past env's flags and NAME=value words; or, in a file with no extension, a first
# line `# shellcheck shell=`. shellcheck also takes that directive lower in such a file, above
# its first command; a file naming its shell only there is not found here and is review's. git
# grep reads every file as text, whatever .gitattributes says of it, and gives each name whole
# whatever it holds.
is_shell_shebang() { # the first line, without its "#!"
  local words word program
  read -r -a words <<< "${1%$'\r'}"
  [ "${#words[@]}" -gt 0 ] || return 1
  program=${words[0]##*/}; words=("${words[@]:1}")
  if [ "$program" = env ]; then
    program=""
    for word in "${words[@]}"; do
      case $word in
        -S?*) program=${word#-S}; break ;;
        --split-string=?*) program=${word#--split-string=}; break ;;
        -*|*=*) ;;
        *) program=$word; break ;;
      esac
    done
    program=${program##*/}
  fi
  case $program in
    sh|bash|bats|dash|ash|ksh|ksh88|ksh93|oksh) return 0 ;;
    busybox) [[ " ${words[*]} " == *" sh "* || " ${words[*]} " == *" ash "* ]] ;;
    *) return 1 ;;
  esac
}
declare -A shell_seen=()
shell_files=()
while IFS= read -r -d '' file; do
  [ -n "${shell_seen[$file]:-}" ] || { shell_seen[$file]=1; shell_files+=("$file"); }
done < <(git ls-files -z ':(glob,icase)**/*.sh' ':(glob,icase)**/*.bash' ':(glob,icase)**/*.bats' \
  ':(glob,icase)**/*.dash' ':(glob,icase)**/*.ksh')
wait $! || fail "git could not list the shell scripts by name"
first_lines=$(mktemp) || fail "could not make a file for the tracked files' first lines"
git grep -a --no-column -z -n -E '^#!|^#[[:space:]]*shellcheck[[:space:]]+shell=' > "$first_lines" ||
  [ $? = 1 ] || { rm -f "$first_lines"; fail "git grep could not read the tracked files' first lines"; }
while IFS= read -r -d '' file && IFS= read -r -d '' number && IFS= read -r text; do
  [ "$number" = 1 ] || continue
  if [[ $text == '#!'* ]]; then
    is_shell_shebang "${text#'#!'}" || continue
  else
    # A first-line shell= marks a script only in a file with no extension: a page that happens
    # to begin with one is no script.
    [[ ${file##*/} != *.* ]] || continue
  fi
  [ -n "${shell_seen[$file]:-}" ] || { shell_seen[$file]=1; shell_files+=("$file"); }
done < "$first_lines"
rm -f "$first_lines"
#
# Each tool's options from the environment, which no flag turns off, are cleared: shellcheck's
# (SHELLCHECK_OPTS, read by actionlint's shellcheck pass too) and zizmor's (its config file, and
# where it stops looking for the repository's root).
unset SHELLCHECK_OPTS ZIZMOR_CONFIG GIT_CEILING_DIRECTORIES
# The pinned shellcheck's path, in shellcheck, resolved once a run by shellcheck_tool.
shellcheck_tool() { [ -n "${shellcheck:-}" ] || shellcheck=$(released shellcheck); }

# 4k. Every workflow in workflow_files is read as GitHub reads it before it runs, by actionlint at
# its pin: a workflow GitHub would refuse, or one whose expressions or job references name
# something that does not exist, fails here and not on a runner. A cheap gate, since a change set
# of workflows alone runs no Go gates; in CI the cheap job alone runs it, so it is built once a
# run, and a mutation run, which is a report, skips it.
# What decides its answer is this script alone. Its pyflakes pass is turned off by name, since it
# turns it on when it finds the tool on the machine. Its config file is refused, since it is
# parsed whenever it exists. Its shellcheck pass is given the pinned tool by path, which
# `released` has proved runnable (actionlint drops a shellcheck it cannot run without a word), and
# on Linux only: actionlint writes a script whole into shellcheck's input before starting it, so
# on Windows a script over the 4 KiB a pipe holds waits forever (probed at the pin). That costs
# nothing the loop needs: .github/ is the developer's own, so the loop never changes a workflow,
# and CI's cheap job, on Linux, reads every workflow change. One message is set aside, anchored,
# for this pin only: v1.7.12 does not know ubuntu-26.04-arm, a runner GitHub provides and the
# engine's checks run on. A new pin fails until the set-aside is tried without and kept or
# removed.
if [ "${LINT_WORKFLOWS:-1}" != 0 ] && [ "$MUTATION" = 0 ]; then
  for config in .github/actionlint.yaml .github/actionlint.yml; do
    [ ! -e "$config" ] || fail "actionlint's config file $config would change what the workflows' gate decides: its rules belong in check.sh"
  done
  if [ "${#workflow_files[@]}" -gt 0 ]; then
    [ "$(sed -n 's/^ACTIONLINT=//p' .github/tool-versions | tr -d '\r')" = v1.7.12 ] ||
      fail "actionlint's pin is no longer v1.7.12: try gate 4k without its set-aside for ubuntu-26.04-arm, then keep it for the new pin or remove it"
    actionlint=$(pinned actionlint github.com/rhysd/actionlint/cmd/actionlint ACTIONLINT)
    if [ "$(uname -s)" = Linux ]; then
      shellcheck_tool
      shell_pass=-shellcheck=$shellcheck
    else
      shell_pass=-shellcheck=
      echo "check: on $(uname -s) actionlint's shellcheck pass waits forever on a script over 4 KiB, so the workflows' scripts are read on Linux, in CI's cheap job"
    fi
    # actionlint answers 1 for a workflow it finds wrong, and more when it could not judge.
    linted=0
    "$actionlint" -no-color "$shell_pass" -pyflakes= -ignore '^label "ubuntu-26\.04-arm" is unknown\.' \
      "${workflow_files[@]}" < /dev/null || linted=$?
    case $linted in
      0) ;;
      1) fail "actionlint: a workflow above is one GitHub would refuse or misread" ;;
      *) fail "actionlint could not judge the workflows (it answered $linted): see its message above" ;;
    esac
  else
    echo "check: no workflows in .github/workflows; gate 4k has nothing to read"
  fi
elif [ "$MUTATION" = 0 ]; then
  echo "check: LINT_WORKFLOWS=0, so another job of this run lints the workflows; gate 4k skipped"
fi

# 4l. Every file in shell_files is read by shellcheck at its pinned release, on every system the
# check runs on, its findings at shellcheck's own defaults and its extended analysis on. What
# decides its answer is this script alone: no rc file is read (--norc, which also stops the ones
# in the home folder), one in the repository is refused, since it would seem to count, and the
# environment's options were cleared above. shellcheck lets a script's own directives change what
# it judges, and nothing turns them off. It reads as a directive every comment that begins with
# its own name in lower case, whatever follows the name, and honours one after code on its line,
# such as after then, a brace or a semicolon (both probed at the pin). So this gate reads every
# such comment wherever it starts, in a shell script or a workflow, allows exactly two forms, each
# on its own line, and refuses every other: a finding set aside by its codes with the reason
# after a second hash sign, `# shellcheck disable=SC2086 # why`, and a script's first line
# naming its dialect, `# shellcheck shell=bash`. A hash sign inside a string, after a space, reads
# the same way here and is refused too; such a line is reworded. This reading is a backstop for
# the way a directive is written, not the test of the rule (the developer, 2026-11-17): a text
# search cannot find every spelling the tool honours, such as one in a workflow's script written
# with YAML's escapes, which shellcheck obeys (probed at the pin). Those stay review's, where
# every directive is in the diff, as gate 4n leaves its other spellings to review. shellcheck
# answers 0 for no finding, 1 for a finding, and 2 to 4 when it could not judge. Run, or skipped,
# where gate 4k is.
if [ "${LINT_WORKFLOWS:-1}" != 0 ] && [ "$MUTATION" = 0 ]; then
  rcs=$(git ls-files ':(glob,icase)**/.shellcheckrc' ':(glob,icase)**/shellcheckrc') ||
    fail "git could not list the files"
  [ -z "$rcs" ] || { echo "$rcs"; fail "a shellcheck rc file would change what the shell gate decides: its rules belong in check.sh"; }
  directive_paths=()
  for file in "${shell_files[@]}" "${workflow_files[@]}"; do directive_paths+=(":(literal)$file"); done
  if [ "${#directive_paths[@]}" -gt 0 ]; then
    directives=$(mktemp) || fail "could not make a file for the shellcheck directives"
    git grep -a --no-column -z -n -E '(^|[[:space:];&|()<>])#[[:space:]]*shellcheck' -- "${directive_paths[@]}" > "$directives" ||
      [ $? = 1 ] || { rm -f "$directives"; fail "git grep could not read the shell scripts and workflows"; }
    allowed_disable='^[[:space:]]*#[[:space:]]*shellcheck[[:space:]]+disable=SC[0-9]+(,SC[0-9]+)*[[:space:]]+#[[:space:]]*[^[:space:]]'
    allowed_shell='^#[[:space:]]*shellcheck[[:space:]]+shell=(sh|bash|dash|ksh|busybox)[[:space:]]*$'
    refused=""
    while IFS= read -r -d '' file && IFS= read -r -d '' number && IFS= read -r text; do
      text=${text%$'\r'}
      [[ $text =~ $allowed_disable ]] && continue
      [ "$number" = 1 ] && [ -n "${shell_seen[$file]:-}" ] && [[ $text =~ $allowed_shell ]] && continue
      refused+="$file:$number: $text"$'\n'
    done < "$directives"
    rm -f "$directives"
    [ -z "$refused" ] || { printf '%s' "$refused"; fail "a shellcheck directive is not one of the two allowed, each on its own line: \`# shellcheck disable=SC<code>[,SC<code>] # why\` or a first line \`# shellcheck shell=<dialect>\`"; }
  fi
  if [ "${#shell_files[@]}" -gt 0 ]; then
    shellcheck_tool
    checked=0
    "$shellcheck" --norc --extended-analysis=true -f gcc -- "${shell_files[@]}" < /dev/null || checked=$?
    case $checked in
      0) ;;
      1) fail "shellcheck: a shell script above has a finding: fix it, or set it aside on its line with the reason" ;;
      *) fail "shellcheck could not judge the scripts (it answered $checked): see its message above" ;;
    esac
  else
    echo "check: no shell scripts tracked; gate 4l has nothing to read"
  fi
elif [ "$MUTATION" = 0 ]; then
  echo "check: LINT_WORKFLOWS=0, so another job of this run reads the shell scripts; gate 4l skipped"
fi

# 4m. Every file zizmor audits for how GitHub runs code is read by zizmor at its pinned release:
# each workflow, .github/dependabot.yml or .yaml, every action.yml or action.yaml, and the
# pre-commit files .pre-commit-config.yaml and .pre-commit-hooks.yaml, as git tracks them. zizmor
# tells a file's kind by these exact names and reads a workflow only with its extension in lower
# case, so a workflow with another is refused here, as one the security checker cannot read. A
# finding, such as a pull request's text put straight into a shell line or a checkout that keeps
# its token, fails. It is a security linter, so a finding is fixed or brought to the developer,
# never silenced: its ignore comments are not read (--no-ignores), nor a config file (--no-config),
# one in the repository being refused, since it would seem to count. Its lockfile,
# .github/workflows/actions.lock, is refused too: zizmor reads it whenever it finds the
# repository's root, it changes the findings, and no flag turns it off. A file it cannot parse
# fails rather than being skipped (--strict-collection). It runs offline, judging only what is in
# the repository; the actions-watch workflow reads the advisories. zizmor answers 0 for no
# finding, 11 to 14 for findings by their worst severity, and 1 to 3 when it could not judge. Run,
# or skipped, where gate 4k is.
if [ "${LINT_WORKFLOWS:-1}" != 0 ] && [ "$MUTATION" = 0 ]; then
  refused=$(git ls-files ':(glob,icase)zizmor.yml' ':(glob,icase)zizmor.yaml' ':(glob,icase).github/zizmor.yml' \
    ':(glob,icase).github/zizmor.yaml' ':(glob,icase).github/workflows/actions.lock') || fail "git could not list the files"
  [ -z "$refused" ] || { echo "$refused"; fail "zizmor's config file or lockfile would change what its gate decides: its rules belong in check.sh"; }
  audited=()
  for file in "${workflow_files[@]}"; do
    case $file in
      *.yml|*.yaml) audited+=("$file") ;;
      *) echo "$file"; fail "zizmor reads a workflow only with its extension in lower case, so the security checker cannot judge this one: rename it" ;;
    esac
  done
  mapfile -d '' -t others < <(git ls-files -z ':(literal).github/dependabot.yml' ':(literal).github/dependabot.yaml' \
    ':(glob)**/action.yml' ':(glob)**/action.yaml' ':(glob)**/.pre-commit-config.yaml' ':(glob)**/.pre-commit-hooks.yaml')
  wait $! || fail "git could not list the files zizmor audits"
  audited+=("${others[@]}")
  if [ "${#audited[@]}" -gt 0 ]; then
    zizmor=$(released zizmor)
    audit=0
    "$zizmor" --offline --no-config --no-ignores --strict-collection --no-progress --color=never --format plain \
      -- "${audited[@]}" < /dev/null || audit=$?
    case $audit in
      0) ;;
      1[1-4]) fail "zizmor: a file above lets code run as it should not, or keeps a token it should not: fix it, or bring it to the developer" ;;
      *) fail "zizmor could not judge the files (it answered $audit): see its message above" ;;
    esac
  else
    echo "check: no workflows, Dependabot settings, actions or pre-commit files tracked; gate 4m has nothing to read"
  fi
elif [ "$MUTATION" = 0 ]; then
  echo "check: LINT_WORKFLOWS=0, so another job of this run audits the workflows; gate 4m skipped"
fi

# 4n. No failure is swallowed unseen: in a shell script or a workflow, a line holding an or-true,
# or its colon form, which throw a command's whole answer away, carries its reason after a hash
# sign after it. Gates that did so read a failed git or grep as nothing found and stayed green
# (the codebase review, 2026-11-13); where one answer alone is the pass, such as grep's 1 for no
# match, the script tests for that answer instead. A backstop for those two spellings, reading one
# line at a time, not the test of the rule: a fallback command, set +e or an answer never read
# stay review's, as gate 4j leaves block comments to it. It needs no tool, so it runs wherever
# check.sh does.
swallow_paths=()
for file in "${shell_files[@]}" "${workflow_files[@]}"; do swallow_paths+=(":(literal)$file"); done
if [ "${#swallow_paths[@]}" -gt 0 ]; then
  swallow_lines=$(mktemp) || fail "could not make a file for the lines that swallow a failure"
  git grep -a --no-column -z -n -E '\|\|[[:space:]]*(true|:)([[:space:];)]|$)' -- "${swallow_paths[@]}" > "$swallow_lines" ||
    [ $? = 1 ] || { rm -f "$swallow_lines"; fail "git grep could not read the shell scripts and workflows"; }
  reasoned='\|\|[[:space:]]*(true|:)[^#]*#[[:space:]]*[^[:space:]]'
  swallowed=""
  while IFS= read -r -d '' file && IFS= read -r -d '' number && IFS= read -r text; do
    [[ ${text%$'\r'} =~ $reasoned ]] || swallowed+="$file:$number: $text"$'\n'
  done < "$swallow_lines"
  rm -f "$swallow_lines"
  [ -z "$swallowed" ] || { printf '%s' "$swallowed"; fail "a failure is swallowed with no reason: test for the one answer that passes, or say why after a hash sign on the line"; }
fi

# 5. Go gates, when there is Go. A failing go list is a failure, not an empty repository.
# CI sets SKIP_GO on its one runner for the cheap gates, and the full matrix does not start
# when the change set holds only Markdown, docs/, developer-owned-paths and .github/ other
# than check.yml.
if [ "${SKIP_GO:-}" = 1 ]; then echo "no Go in the change set; Go gates skipped"; echo green; exit 0; fi
pkgs=$(go list ./... 2>&1) || { echo "$pkgs"; fail "go list failed"; }
if [ -n "$pkgs" ] && [ "${GATES:-1}" = 0 ]; then
  echo "Go gates checked by another job of this run; tests only"
elif [ -n "$pkgs" ]; then
  lint=$(pinned golangci-lint github.com/golangci/golangci-lint/v2/cmd/golangci-lint GOLANGCI_LINT)
  vulncheck=$(pinned govulncheck golang.org/x/vuln/cmd/govulncheck GOVULNCHECK)
  licencecheck=$(pinned go-licenses github.com/google/go-licenses/v2 GO_LICENSES)
  go mod verify
  # Every module the engine is built from, indirect ones included, carries a licence that can
  # be combined with AGPL-3.0-only; the engine's own module is the AGPL-3.0 one.
  licences=MIT,BSD-2-Clause,BSD-3-Clause,ISC,Apache-2.0,MPL-2.0
  # When go.mod asks for a newer Go than the one installed, go switches to a downloaded toolchain,
  # and go-licenses, which looks for the standard library under the installed Go's root, then
  # fails on every standard package. The root of the Go in use is passed to it.
  goroot=$(go env GOROOT)
  for os in windows linux; do
    GOROOT=$goroot GOOS=$os "$licencecheck" check ./... --allowed_licenses="$licences" --ignore github.com/heliosestate/heliosadvance ||
      fail "a module's licence ($os build) is not one AGPL-3.0-only can carry: $licences"
  done
  # With one main package, go build writes its program into the clone; build into a temporary
  # folder instead, so the check leaves the clone as it found it.
  buildout=$(mktemp -d)
  go build -o "$buildout/" ./...
  rm -rf "$buildout"
  go vet ./...
  # The developer's .golangci.yml by name: found on its own, the linter prefers a .golangci.yaml,
  # .toml or .json beside it, which any branch could add, and every rule would be gone unseen.
  "$lint" run --config .golangci.yml ./...
  # Files built for one platform are linted only when GOOS names it, and the loop runs this
  # on Windows: lint the other platform too, so a Linux-only file's faults show before CI. With
  # cgo off, since a C compiler for this platform cannot preprocess the other platform's cgo
  # files in the standard library; the engine has no cgo, so its own files lint the same.
  other=linux; [ "$(go env GOOS)" = linux ] && other=windows
  CGO_ENABLED=0 GOOS=$other "$lint" run --config .golangci.yml ./...
  go run ./tools/namecheck .
  "$vulncheck" ./...
fi
# fetch_oracle folder: an oracle that is not this repository's code is not committed (the
# developer, 2026-11-10: "If it's not our code, I'd prefer it not to be in our repo. Instead CI
# should download it as needed."). The folder's pin names the source repository's commit, then each
# file's SHA-256 and path there. A file missing from the folder is fetched from that commit into a
# temporary file beside it and moved into place only once it matches; a file that does not match
# its pin, fetched or already there, fails the check, since the tests would judge the engine against
# files nobody approved. Nothing fetched is run.
fetch_oracle() {
  local folder=$1 source=$2 commit hash path name file tmp got
  need curl "curl, to fetch the oracle's files"
  need sha256sum "sha256sum, from the system's core utilities"
  [ -f "$folder/pin" ] || fail "$folder/pin is missing, so the oracle's files cannot be fetched or checked"
  commit=$(tr -d '\r' < "$folder/pin" | sed -n 's/^commit \([0-9a-f]\{40\}\)$/\1/p')
  [ "$(echo "$commit" | grep -c .)" = 1 ] || fail "$folder/pin names no single 40-character commit"
  while read -r hash path; do
    name=${path##*/}
    file=$folder/$name
    if [ ! -f "$file" ]; then
      tmp=$(mktemp "$folder/.fetch.XXXXXX") || fail "could not make a file to fetch $name into"
      curl -fsSL --retry 3 -o "$tmp" "$source/$commit/$path" || { rm -f "$tmp"; fail "fetching $name from $source at $commit failed"; }
      got=$(sha256sum "$tmp" | cut -d' ' -f1)
      [ "$got" = "$hash" ] || { rm -f "$tmp"; fail "$name fetched at $commit has SHA-256 $got, not the $hash $folder/pin names"; }
      mv "$tmp" "$file" || fail "could not move the fetched $name into $folder"
      echo "check: fetched $name at $commit, as $folder/pin names it"
    fi
    got=$(sha256sum "$file" | cut -d' ' -f1)
    [ "$got" = "$hash" ] || fail "$file has SHA-256 $got, not the $hash $folder/pin names: remove it, and this check fetches the pinned one"
  done < <(tr -d '\r' < "$folder/pin" | grep -E '^[0-9a-f]{64}  [^ ]+$')
}
if [ -n "$pkgs" ]; then
  fetch_oracle oracle/messageformat2 https://raw.githubusercontent.com/unicode-org/message-format-wg
  # On Windows the rows that need a Linux container (TestOracle…) or Linux itself (TestLinux…)
  # cannot pass, so they are skipped there unless TESTSKIP says otherwise: the loop runs this on
  # Windows, and CI sets the same pattern for its Windows runner. The rows that need an elevated
  # process (TestWindowsElevated…) are skipped too when this one is not: CI's Windows runner is
  # elevated and runs them, while the loop's run and the developer's are not, and would fail them
  # for a right they lack rather than for a fault. Windows is asked whether this
  # process's token holds the Administrators group, which only an elevated token does; anything but
  # "True" counts as not elevated. A skip is always said, never silent.
  elevated=
  if [ "$(go env GOOS)" = windows ]; then
    elevated=$(powershell.exe -NoProfile -Command '([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)' 2>/dev/null | tr -d '\r')
  fi
  if [ "$(go env GOOS)" = windows ] && [ -z "${TESTSKIP+set}" ]; then
    if [ "$elevated" = True ]; then TESTSKIP='^(TestOracle|TestLinux)'
    else
      TESTSKIP='^(TestOracle|TestLinux|TestWindowsElevated)'
      echo "check: this process is not elevated, so the TestWindowsElevated rows are skipped; CI runs them"
    fi
  fi
  # The rows on the TPM's key store (TestWindowsElevatedTPM…) need a TPM as well as an elevated
  # process, and CI's elevated Windows runner has no TPM: so on an elevated Windows they are
  # skipped wherever no TPM is ready, whether or not TESTSKIP was given, since CI gives it, and the
  # name is added to its pattern, never put in its place. QA runs them on a machine with a TPM.
  # Get-Tpm answers only an elevated process; an unelevated one skips them already by their name's
  # start. Anything but a TPM both present and ready, an error included, counts as none.
  if [ "$elevated" = True ]; then
    # shellcheck disable=SC2016 # the dollar signs are PowerShell's own, not the shell's
    tpm=$(powershell.exe -NoProfile -Command '$tpm = Get-Tpm -ErrorAction Stop; "$($tpm.TpmPresent) $($tpm.TpmReady)"' 2>/dev/null | tr -d '\r')
    if [ "$tpm" != "True True" ]; then
      TESTSKIP="${TESTSKIP:+$TESTSKIP|}^TestWindowsElevatedTPM"
      echo "check: this machine has no TPM ready, so the TestWindowsElevatedTPM rows are skipped; QA runs them on a machine with one"
    fi
  fi
  # One package at a time, on every machine: the timed rows' margins are measured that way, and
  # every failure from load on record came with every package at once. Each option and package is
  # an argument of its own; PKGS names packages split by spaces.
  gotest=(-p 1)
  if [ -n "${RACE:-}" ]; then gotest+=("$RACE"); fi
  if [ -n "${COVER:-}" ]; then gotest+=("$COVER"); fi
  if [ -n "${TESTSKIP:-}" ]; then gotest+=(-skip "$TESTSKIP"); fi
  gotest+=(-count=1)
  read -ra packages <<< "${PKGS:-./...}"
  if [ -n "${TIMED:-}" ]; then
    # CI keeps every timed row's place in its window, and every line where a row says it cannot
    # tell and sets its check aside, since such a pass proves nothing: a passing run's logs show
    # only in Go's -json stream, so those lines go to $TIMED, a few KB. The rows TESTSKIP skips by
    # name are named above. The console gets each package's result, and a failed package's whole
    # output, so a crash or a hang that Go does not pin on one test still shows its cause.
    need jq "jq, from the system's packages"
    stream=$(mktemp); status=0
    go test -json "${gotest[@]}" "${packages[@]}" > "$stream" || status=$?
    jq -j 'select(.Action == "output") | .Package + ":" + .Output' "$stream" | grep -E 'into its window of|cannot tell' > "$TIMED" || true # a report kept beside the run, never judged here
    jq -sj '[.[] | select(.Action == "fail" and (.Test | not)) | .Package] as $failed
      | .[] | select(.Action == "build-output" or .Action == "output")
      | select((.Package as $p | any($failed[]; . == $p))
          or (.Test == null and (.Output | test("^(PASS|coverage: .*)\n$") | not)))
      | .Output' "$stream"
    rm -f "$stream"
    [ "$status" = 0 ] || exit "$status"
  else
    go test "${gotest[@]}" "${packages[@]}"
  fi
  if [ "$MUTATION" = 1 ] && [ "$(go env GOOS)" = windows ]; then
    # gremlins v0.6.0 misreads coverage on Windows (its coverage paths use / and file
    # paths \, so every mutant reads "Not covered"), and a report with nothing covered would read as
    # one. Mutation testing runs on Linux, in CI, until upstream fixes it (the developer, 2026-10-27).
    echo "mutation testing: not run on Windows; read the mutation report in the pull request's CI run"
  elif [ "$MUTATION" = 1 ] && { [ -n "${MUTATE:-}" ] || git diff --name-only "$BASE...HEAD" -- '*.go' ':!*_test.go' ':!internal/testrun/*' 2>/dev/null | grep -q .; }; then
    mutator=$(pinned gremlins github.com/go-gremlins/gremlins/cmd/gremlins GREMLINS)
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
    # unmutated. With no context lines, git writes one hunk per run of edits. Kept until a
    # gremlins release fixes it.
    # The run on a diff stays at the repository root (.): gremlins matches a package path to no
    # diff entry. MUTATE names whole packages instead (a QA change to existing rows, a
    # milestone), each mutated in full.
    if [ -n "${MUTATE:-}" ]; then read -ra targets <<< "$MUTATE"; diffarg=(); else targets=(.); diffarg=(--diff "$BASE"); fi
    mutants=
    for target in "${targets[@]}"; do
      out=$(GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=diff.context GIT_CONFIG_VALUE_0=0 GOFLAGS="${GOFLAGS:+$GOFLAGS }-count=1" "$mutator" unleash "${diffarg[@]}" --exclude-files '^(cmd|internal/testrun|tools)/' "$target" 2>&1) || { echo "$out"; fail "mutation testing: gremlins failed on $target"; }
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
