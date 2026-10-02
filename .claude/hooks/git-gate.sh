#!/usr/bin/env bash
# PreToolUse on Bash. In a loop session (HELIOS_LOOP=1) deny the git commands that destroy
# work. Ported from attempt one's gate-destructive-git.ps1, the one old hook that got it
# right: filed there after an unattended run did checkout, branch -D and reset --hard in a
# row and discarded two files it had watched change all session, with the prose rule
# already as imperative as prose gets.
#
# Two classes. Working-tree destroyers (reset --hard, clean -f, checkout -- or ., restore,
# stash drop or clear) are denied while the tree is dirty, with no exemption for "I know
# this file": that judgement is what failed. History destroyers (push --force in any
# spelling, push --delete, branch -D) are denied always; a session never needs them, the
# developer's signoff and GitHub delete branches. Fails open on a payload it cannot read,
# so an unparseable call never blocks unrelated work; a destructive match is what denies.
[ "${HELIOS_LOOP:-}" = 1 ] || exit 0
input=$(cat)
command=$(printf '%s' "$input" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\(\([^"\\]\|\\.\)*\)".*/\1/p' | head -1)
[ -n "$command" ] || exit 0
always='git[[:space:]]+(-C[[:space:]]+[^[:space:]]+[[:space:]]+)?(push[[:space:]].*(--force|--force-with-lease|-[a-zA-Z]*f[a-zA-Z]*[[:space:]]|-[a-zA-Z]*f$|--delete)|branch[[:space:]]+(-[a-zA-Z]*D|--delete[[:space:]]+--force|--force[[:space:]]+--delete))'
dirty='git[[:space:]]+(-C[[:space:]]+[^[:space:]]+[[:space:]]+)?(reset[[:space:]]+(--hard|--merge|--keep)|clean[[:space:]]+(-[a-zA-Z]*f|--force)|checkout[[:space:]]+(--[[:space:]]|\.([[:space:]]|$))|restore[[:space:]]|stash[[:space:]]+(drop|clear))'
if printf '%s' "$command" | grep -Eq "$always"; then
  echo "git-gate.sh: a loop session never force-pushes, deletes a remote branch or force-deletes a local one; the developer's signoff merges and GitHub deletes the branch. Denied: $command" >&2
  exit 2
fi
if printf '%s' "$command" | grep -Eq "$dirty"; then
  status=$(git status --porcelain 2>/dev/null) || exit 0
  if [ -n "$status" ]; then
    count=$(printf '%s\n' "$status" | grep -c .)
    echo "git-gate.sh: this command discards working-tree changes and the tree has $count changed path(s). No exemption for files you did not touch. Run git stash push -u first (never stash drop), then retry. Denied: $command" >&2
    exit 2
  fi
fi
exit 0
