#!/usr/bin/env bash
# PreToolUse on WebFetch, Bash, PowerShell, Read, Grep and Glob. In a loop session
# (HELIOS_LOOP=1) refuses reading the source code of other BBS software and its companions
# (transfer programs, mail tools, door kits, terminals): the loop writes code and public text
# no one reads first, so nothing it writes may have come from theirs (developer, 2026-10-02).
# A developer session decides for itself. Documentation, wikis and issue trackers stay
# readable. A docker build is allowed: a machine compiling an oracle reads nothing into any
# session.
[ "${HELIOS_LOOP:-}" = 1 ] || exit 0
input=$(cat)
case "$input" in *'docker build'*|*'docker buildx'*) exit 0 ;; esac

# The list as of 2026-10-02. When the developer names a project not here, add it: its GitHub
# owner/repo, or its own host.
# WWIV's docs repository stays readable: it is documentation.
githubRepos='(SynchronetBBS/sbbs|NuSkooler/enigma-bbs|mbek/elebbs|anetonline/ANetBBS|maximmasiutin/argus|pgul/binkd|awehttam/binkterm-php|huskyproject/[^" /]+|wmcbrine/MultiMail|ViSiON-3/vision-3-bbs|wwivbbs/(wwiv|wwivnet)|Renegade-Exodus/[^" /]+|UweOhse/lrzsz)'
# Projects the developer holds as archives, not clones: refused by name as repositories and
# as source archives wherever they are hosted.
namedProjects='(renegade|vadv|virtual-?advance|wwiv|elebbs|syncterm|citadel)'
patterns=(
    # A repository's files on GitHub: its file, tree, raw and archive views, a clone, and the
    # API's content, git and archive endpoints. Its issues and wiki stay readable.
    "github\.com/$githubRepos(/(blob|tree|raw|archive|commit|commits)/|\.git|\"|$)"
    "(raw\.githubusercontent\.com|codeload\.github\.com)/$githubRepos"
    "api\.github\.com/repos/$githubRepos/(contents|git|tarball|zipball)"
    "github\.com/[^\" /]+/[^\" /]*$namedProjects[^\" /]*(/(blob|tree|raw|archive|commit)/|\.git)"
    # Synchronet's own GitLab, where SyncTERM's source lives too.
    'gitlab\.synchro\.net/[^" ]*/-/(blob|raw|tree|archive|commit)/'
    'gitlab\.synchro\.net/api/v4/projects/[^" ]*/repository/(files|blobs|archive|tree)'
    'gitlab\.synchro\.net/[^" ]*\.git'
    # Citadel's own git host, and source archives of any named project.
    'code\.citadel\.org'
    "$namedProjects[^\" /]*(-src|-source|_src)?\.(tgz|tar\.gz|tar\.bz2|tar|zip|7z|arj|lzh|rar)"
    'sourceforge\.net/projects/syncterm/files/[^" ]*src'
    'ohse\.de/uwe/releases/lrzsz'
    'apt(-get)? source[^"]*lrzsz'
    "git (clone|fetch|archive)[^\"]*(synchro\.net|citadel\.org|$githubRepos)"
)
for pattern in "${patterns[@]}"; do
    if printf '%s' "$input" | grep -Eiq "$pattern"; then
        echo "no-foreign-source.sh: refused by the developer's rule: never read the source code of other BBS software or its companions. Use their documentation, wiki, issue tracker or observed behaviour instead. Matched: $pattern" >&2
        exit 2
    fi
done
exit 0
