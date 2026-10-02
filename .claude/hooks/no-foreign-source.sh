#!/usr/bin/env bash
# PreToolUse on WebFetch, Bash and PowerShell. In a loop session (HELIOS_LOOP=1) refuses
# reading the source code of other BBS software and its companions (transfer programs, door
# kits, terminals): the loop writes code and public text no one reads first, so nothing it
# writes may have come from theirs (developer, 2026-10-02). A developer session decides for
# itself. Documentation, wikis and issue trackers stay readable. A docker build is allowed:
# a machine compiling an oracle reads nothing into any session.
[ "${HELIOS_LOOP:-}" = 1 ] || exit 0
input=$(cat)
case "$input" in *'docker build'*|*'docker buildx'*) exit 0 ;; esac
# One pattern per known source location; add a line when a new project is named.
patterns=(
    'gitlab\.synchro\.net/[^" ]*/-/(blob|raw|tree|archive|commit)/'
    'gitlab\.synchro\.net/api/v4/projects/[^" ]*/repository/(files|blobs|archive|tree)'
    'gitlab\.synchro\.net/[^" ]*\.git'
    'github\.com/SynchronetBBS/[^" /]+(/(blob|tree|raw|archive|commit)/|\.git|")'
    'raw\.githubusercontent\.com/(SynchronetBBS|wwivbbs|NuSkooler|UweOhse)/'
    'github\.com/(wwivbbs|NuSkooler|UweOhse)/[^" /]+(/(blob|tree|raw|archive|commit)/|\.git|")'
    'ohse\.de/uwe/releases/lrzsz'
    'git (clone|fetch|archive)[^"]*(synchro\.net|SynchronetBBS|wwivbbs|enigma-bbs|lrzsz)'
    'apt(-get)? source[^"]*lrzsz'
)
for pattern in "${patterns[@]}"; do
    if printf '%s' "$input" | grep -Eq "$pattern"; then
        echo "no-foreign-source.sh: refused by the developer's rule: never read the source code of other BBS software or its companions. Use their documentation, wiki, issue tracker or observed behaviour instead. Matched: $pattern" >&2
        exit 2
    fi
done
exit 0
