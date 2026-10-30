#!/usr/bin/env bash
# Opens one issue labeled noticed for each item of a "Noticed, not touched" list, in a pull
# request's body or in the plan in an issue's body (developer, 2026-10-10: a noticed item
# lived only in a body until a session copied it out, and two were never brought to him). The
# label means the item waits on his decision: fix it, defer it with its record and trigger,
# or close it as needing nothing, with the reason. An item seen before, in any body, gets no
# second issue: its text is the key, so a plan's item repeated in its pull request is one
# issue, which then names both sources.
#
# Each item is tagged with its issue, "(noticed: #123)" at its end, which the script writes into
# the body (developer, 2026-10-30: a key made of the text alone opened another issue each time a
# line was reworded). A tagged item whose text changed rewrites its issue's item and key, keeping
# whatever else that issue holds, when this body alone opened it; an issue other bodies also
# list gets a comment with the new wording instead. An untagged item finds its issue by its key,
# or opens one, and gets its tag. An issue this body opened whose item has left the list gets
# one comment and stays as it is: only the developer closes a noticed issue, so deleting a line
# never makes its item go away.
#
# Usage: noticed.sh SOURCE < body, where SOURCE is pr-<number> or issue-<number>. Without
# GH_TOKEN, or with DRY_RUN=1, it prints the items and what it would do.
set -euo pipefail

source=$1
case $source in
  pr-*) from="pull request #${source#pr-}" ;;
  issue-*) from="the plan in #${source#issue-}" ;;
  *) echo "noticed.sh: SOURCE is pr-<number> or issue-<number>" >&2; exit 2 ;;
esac
dry=${DRY_RUN:-}
[ -z "${GH_TOKEN:-}" ] && dry=1
marker="<!-- noticed-source: $source -->"
left="<!-- noticed-left: $source -->"
body=$(cat)

# items prints, for each item of the body's noticed list, the number of its last line, a tab and
# the item on one line: the list starts at a line that is only the heading (any # or ** around
# it) and ends at the next heading, the next bold line or the generated-by line. An item's
# indented continuation lines join it, and an item that is only "None", "Nothing" or "N/A", in
# any case, with or without a full stop, is no item: the template's other headings ask for
# "None", so a session writes it here too, and each one became an issue (developer, 2026-10-14).
items() {
  awk '
    function flush() { if (item != "" && tolower(item) !~ /^[ \t]*(none|nothing|n\/a)\.?[ \t]*$/) print last "\t" item; item = "" }
    {
      line = $0; sub(/\r$/, "", line)
      lower = tolower(line)
      if (lower ~ /^[#* \t]*noticed, not touched[* \t]*$/) { inside = 1; next }
      if (!inside) next
      if (line ~ /^#/ || line ~ /^\*\*.*\*\*[ \t]*$/ || line ~ /^🤖/) { flush(); inside = 0; next }
      if (line ~ /^[-*] /) { flush(); item = substr(line, 3); last = NR; next }
      if (line ~ /^[ \t]+[^ \t]/ && item != "") { sub(/^[ \t]+/, " ", line); item = item line; last = NR; next }
      if (line ~ /^[ \t]*$/) flush()
    }
    END { flush() }
  '
}

# key is an item's text with its white space folded, hashed: the same item in any body has it.
key() {
  printf '%s' "$1" | sed -e 's/[[:space:]]\+/ /g' -e 's/^ //' -e 's/ $//' | sha1sum | cut -c1-16
}

title_for() {
  printf 'Noticed: %s' "$(printf '%s' "$1" | tr -d '`' | cut -c1-80)"
}

tagged_item='^(.*[^[:space:]])[[:space:]]*\(noticed: #([0-9]+)\)[[:space:]]*$'

# The noticed issues, read once. No --label: with it, gh asks the search index, which lagged
# minutes behind a new issue, and one item became three issues (#52, #54, #57, 2026-10-22).
issues='[]'
[ -n "$dry" ] || issues=$(gh issue list --state all --limit 1000 --json number,state,body)
issue_field() { printf '%s' "$issues" | jq -r --argjson n "$1" ".[] | select(.number == \$n) | .$2"; }
issue_by_key() { printf '%s' "$issues" | jq -r --arg k "noticed-key: $1" 'map(select(.body | contains($k))) | .[0].number // empty'; }
issues_from_here() { printf '%s' "$issues" | jq -r --arg m "$marker" '.[] | select(.body | contains($m)) | .number'; }

# add_marker lists this body among an issue's sources, once, and takes back a note that its line
# had left, since it is back. It reads the issue as it is now, since this run may already have
# edited it.
add_marker() {
  local text
  text=$(gh issue view "$1" --json body -q .body)
  if printf '%s' "$text" | grep -qF "$left"; then
    text=$(printf '%s\n' "$text" | grep -vF "$left")
    printf '%s\n' "$text" | gh issue edit "$1" --body-file -
  fi
  printf '%s' "$text" | grep -qF "$marker" && return
  printf '%s\n%s\n' "$text" "$marker" | gh issue edit "$1" --body-file -
  gh issue comment "$1" --body "Noticed again, in $from."
}

declare -A tags=() listed=()
# The list comes in on its own descriptor, so a gh call inside the loop cannot read it away.
while IFS=$'\t' read -r -u 3 last item; do
  [ -n "$item" ] || continue
  if [[ $item =~ $tagged_item ]]; then
    text=${BASH_REMATCH[1]}; number=${BASH_REMATCH[2]}
    if [ -n "$dry" ]; then
      printf 'item %s, tagged #%s, from %s: %s\n' "$(key "$text")" "$number" "$from" "$text"
      listed[$number]=1
      continue
    fi
    current=$(issue_field "$number" body)
    if printf '%s' "$current" | grep -q 'noticed-key: '; then
      listed[$number]=1
      newkey=$(key "$text")
      if ! printf '%s' "$current" | grep -qF "noticed-key: $newkey"; then
        sources=$(printf '%s\n' "$current" | grep -c '^<!-- noticed-source: ' || true)
        if [ "$sources" = 1 ] && printf '%s' "$current" | grep -qF "$marker"; then
          # Only the item, the body's first paragraph, and its key change: whatever else the
          # issue holds, such as the developer's record of a deferral, stays, and a closed issue
          # stays closed.
          { printf '%s\n' "$text"
            printf '%s\n' "$current" | awk 'seen || /^[ \t\r]*$/ { seen = 1; print }' |
              sed -E "s/noticed-key: [0-9a-f]{16}/noticed-key: $newkey/"
            printf '%s' "$current" | grep -q '^[ \t\r]*$' || printf '\n<!-- noticed-key: %s -->\n%s\n' "$newkey" "$marker"
          } | gh issue edit "$number" --title "$(title_for "$text")" --body-file -
          gh issue comment "$number" --body "Reworded in $from; this issue now carries the new wording."
        elif ! printf '%s' "$current" | grep -qF "<!-- noticed-reworded: $source $newkey -->"; then
          # An issue other bodies also list keeps its wording; this rewording is noted once.
          printf '%s\n<!-- noticed-reworded: %s %s -->\n' "$current" "$source" "$newkey" | gh issue edit "$number" --body-file -
          gh issue comment "$number" --body "Reworded in $from as: $text"
        fi
      fi
      add_marker "$number"
      continue
    fi
    item=$text
  fi
  itemkey=$(key "$item")
  if [ -n "$dry" ]; then
    printf 'item %s, untagged, from %s: %s\n' "$itemkey" "$from" "$item"
    continue
  fi
  number=$(issue_by_key "$itemkey")
  if [ -n "$number" ]; then
    add_marker "$number"
  else
    url=$({
      printf '%s\n\n' "$item"
      printf 'Noticed in %s and not touched there. It waits on the developer'"'"'s decision: fix it (this issue becomes the work), defer it (say here where it is recorded and what brings it back, then close it), or close it as needing nothing, with the reason.\n\n' "$from"
      printf '<!-- noticed-key: %s -->\n%s\n' "$itemkey" "$marker"
    } | gh issue create --title "$(title_for "$item")" --label noticed --body-file -)
    number=${url##*/}
  fi
  listed[$number]=1
  tags[$last]=$number
done 3< <(printf '%s\n' "$body" | items)

[ -n "$dry" ] && exit 0

# An issue this body lists among its sources whose item is no longer in the list gets one comment.
for number in $(issues_from_here); do
  [ -z "${listed[$number]:-}" ] || continue
  current=$(issue_field "$number" body)
  printf '%s' "$current" | grep -qF "$left" && continue
  if [ "$(issue_field "$number" state)" = OPEN ]; then
    note="Its line left the list in $from. It stays open for the developer's decision."
  else
    note="Its line left the list in $from; the issue was already closed."
  fi
  printf '%s\n%s\n' "$current" "$left" | gh issue edit "$number" --body-file -
  gh issue comment "$number" --body "$note"
done

# Each newly tagged item gets "(noticed: #N)" at the end of its last line. A body edited since
# this run began is left alone: that edit starts a run of its own, which tags it.
[ "${#tags[@]}" -gt 0 ] || exit 0
case $source in
  pr-*) now=$(gh pr view "${source#pr-}" --json body -q .body) ;;
  issue-*) now=$(gh issue view "${source#issue-}" --json body -q .body) ;;
esac
[ "$now" = "$body" ] || { echo "the body changed during this run; its own run tags it"; exit 0; }
spec=$(for line in "${!tags[@]}"; do printf '%s %s\n' "$line" "${tags[$line]}"; done)
tagged=$(printf '%s\n' "$body" | awk -v spec="$spec" '
  BEGIN { n = split(spec, rows, "\n"); for (i = 1; i <= n; i++) { split(rows[i], f, " "); tag[f[1]] = f[2] } }
  { line = $0; if (NR in tag) { sub(/\r$/, "", line); sub(/[ \t]*\(noticed: #[0-9]+\)[ \t]*$/, "", line); line = line " (noticed: #" tag[NR] ")" } print line }')
case $source in
  pr-*) printf '%s\n' "$tagged" | gh pr edit "${source#pr-}" --body-file - ;;
  issue-*) printf '%s\n' "$tagged" | gh issue edit "${source#issue-}" --body-file - ;;
esac
