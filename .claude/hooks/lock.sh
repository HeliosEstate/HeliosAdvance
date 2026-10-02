#!/usr/bin/env bash
# PreToolUse on Edit|Write. In a loop session (HELIOS_LOOP=1) deny writes to developer-owned
# paths and to approved tests. A convenience: check.sh in CI is the lock, this is the fast no.
[ "${HELIOS_LOOP:-}" = 1 ] || exit 0
input=$(cat)
path=$(printf '%s' "$input" | sed -n 's/.*"file_path":"\([^"]*\)".*/\1/p' | tr '\134' '/' | tr -s /)
[ -n "$path" ] || exit 0
root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
# Git Bash reports the root as C:/..., the tool may pass either form; compare in one form.
if command -v cygpath >/dev/null 2>&1; then path=$(cygpath -u "$path"); root=$(cygpath -u "$root"); fi
rel=${path#"$root"/}
case "$rel" in
  docs/spec/*|docs/architecture.md|features/*|*/contract.go|CLAUDE.md|check.sh|.golangci.yml|.claude/*|.github/*)
    echo "lock.sh: $rel is developer-owned; a loop session may not write it. Comment on the issue and stop." >&2
    exit 2 ;;
esac
case "$rel" in *_test.go)
  qa=$(git -C "$root" log -1 --format=%H --grep='^Helios-Role: qa$' 2>/dev/null)
  if [ -n "$qa" ] && git -C "$root" cat-file -e "$qa:$rel" 2>/dev/null; then
    echo "lock.sh: $rel is an approved test (QA commit ${qa:0:8}); a loop session may not edit it. Add a new test file or comment on the issue." >&2
    exit 2
  fi ;;
esac
exit 0
