#!/usr/bin/env bash
# Opens one issue labeled noticed for each item of a "Noticed, not touched" list, in a pull
# request's body or in the plan in an issue's body (developer, 2026-10-10: a noticed item
# lived only in a body until a session copied it out, and two were never brought to him). The
# label means the item waits on his decision: fix it, defer it with its record and trigger,
# or close it as needing nothing, with the reason. An item seen before, in any body, gets no
# second issue: its text is the key, so a plan's item repeated in its pull request is one
# issue, which then names both sources.
#
# An edited body is compared with its text before the edit (developer, 2026-10-30, #226: each
# rewording of one line opened another issue). When as many items left the list as joined it,
# the edit reworded them: each issue that only this body opened takes its item's new wording, in
# list order, instead of a new issue being opened. An item that left the list with none in its
# place gets a comment and stays open: only the developer closes a noticed issue, so deleting a
# line never makes its item go away.
#
# Usage: noticed.sh SOURCE < body, where SOURCE is pr-<number> or issue-<number>; OLD_BODY holds
# the body before an edit, if any. Without GH_TOKEN, or with DRY_RUN=1, it prints the items and
# what it would do.
set -euo pipefail

source=$1

# items prints each item of the body's noticed list on one line: the list starts at a line
# that is only the heading (any # or ** around it) and ends at the next heading, the next
# bold line or the generated-by line. An item's indented continuation lines join it, and an
# item that is only "None", "Nothing" or "N/A", in any case, with or without a full stop, is no
# item: the template's other headings ask for "None", so a session writes it here too, and each
# one became an issue (developer, 2026-10-14).
items() {
  awk '
    function flush() { if (item != "" && tolower(item) !~ /^[ \t]*(none|nothing|n\/a)\.?[ \t]*$/) print item; item = "" }
    {
      line = $0; sub(/\r$/, "", line)
      lower = tolower(line)
      if (lower ~ /^[#* \t]*noticed, not touched[* \t]*$/) { inside = 1; next }
      if (!inside) next
      if (line ~ /^#/ || line ~ /^\*\*.*\*\*[ \t]*$/ || line ~ /^🤖/) { flush(); inside = 0; next }
      if (line ~ /^[-*] /) { flush(); item = substr(line, 3); next }
      if (line ~ /^[ \t]+[^ \t]/ && item != "") { sub(/^[ \t]+/, " ", line); item = item line; next }
      if (line ~ /^[ \t]*$/) flush()
    }
    END { flush() }
  '
}

# key is an item's text with its white space folded, hashed: the same item in any body has it.
key() {
  printf '%s' "$1" | sed -e 's/[[:space:]]\+/ /g' -e 's/^ //' -e 's/ $//' | sha1sum | cut -c1-16
}

case $source in
  pr-*) from="pull request #${source#pr-}" ;;
  issue-*) from="the plan in #${source#issue-}" ;;
  *) echo "noticed.sh: SOURCE is pr-<number> or issue-<number>" >&2; exit 2 ;;
esac

dry=${DRY_RUN:-}
[ -z "${GH_TOKEN:-}" ] && dry=1
marker="<!-- noticed-source: $source -->"

# issue_with prints the number of the issue whose body carries the key, if one does. No --label:
# with it, gh asks the search index, which lagged minutes behind a new issue, and one item became
# three issues (#52, #54, #57, 2026-10-22). Without it gh reads the issues themselves; the key
# marker is in noticed issues alone.
issue_with() {
  gh issue list --state all --limit 1000 --json number,body \
    -q ".[] | select(.body | contains(\"noticed-key: $1\")) | .number" | head -1
}

# The issue's body for an item: the item, what waits on the developer, its key and its sources.
issue_body() {
  printf '%s\n\n' "$1"
  printf 'Noticed in %s and not touched there. It waits on the developer'"'"'s decision: fix it (this issue becomes the work), defer it (say here where it is recorded and what brings it back, then close it), or close it as needing nothing, with the reason.\n\n' "$2"
  printf '<!-- noticed-key: %s -->\n%s\n' "$3" "$4"
}

title_for() {
  printf 'Noticed: %s' "$(printf '%s' "$1" | tr -d '`' | cut -c1-80)"
}

mapfile -t now < <(items)
before=()
if [ -n "${OLD_BODY:-}" ]; then
  mapfile -t before < <(printf '%s\n' "$OLD_BODY" | items)
fi

# The items that left the list and those that joined it, each in list order.
declare -A nowkeys=() beforekeys=()
for item in "${now[@]}"; do nowkeys[$(key "$item")]=1; done
for item in "${before[@]}"; do beforekeys[$(key "$item")]=1; done
gone=()
for item in "${before[@]}"; do [ -n "${nowkeys[$(key "$item")]:-}" ] || gone+=("$item"); done
joined=()
for item in "${now[@]}"; do [ -n "${beforekeys[$(key "$item")]:-}" ] || joined+=("$item"); done

reworded=0
[ "${#gone[@]}" -gt 0 ] && [ "${#gone[@]}" = "${#joined[@]}" ] && reworded=1

for index in "${!gone[@]}"; do
  old=${gone[$index]}
  oldkey=$(key "$old")
  if [ -n "$dry" ]; then
    if [ "$reworded" = 1 ]; then
      printf 'reworded %s to %s in %s: %s\n' "$oldkey" "$(key "${joined[$index]}")" "$from" "${joined[$index]}"
    else
      printf 'left the list %s in %s: %s\n' "$oldkey" "$from" "$old"
    fi
    continue
  fi
  existing=$(issue_with "$oldkey")
  [ -n "$existing" ] || continue
  body=$(gh issue view "$existing" --json body -q .body)
  sources=$(printf '%s\n' "$body" | grep -c '^<!-- noticed-source: ' || true)
  if [ "$reworded" = 1 ] && [ "$sources" = 1 ] && printf '%s' "$body" | grep -qF "$marker"; then
    new=${joined[$index]}
    # Only the item, its first paragraph, and its key change: whatever else the body holds, such
    # as the developer's record of a deferral, stays, and a closed issue stays closed.
    { printf '%s\n' "$new"; printf '%s\n' "$body" | awk 'seen || /^[ \t\r]*$/ { seen = 1; print }' |
      sed "s/noticed-key: $oldkey/noticed-key: $(key "$new")/"; } |
      gh issue edit "$existing" --title "$(title_for "$new")" --body-file -
    gh issue comment "$existing" --body "Reworded in $from; this issue now carries the new wording."
  else
    gh issue comment "$existing" --body "Its line left the list in $from. It stays open for the developer's decision."
  fi
done

for item in "${now[@]}"; do
  itemkey=$(key "$item")
  if [ -n "$dry" ]; then
    printf 'item %s from %s: %s\n' "$itemkey" "$from" "$item"
    continue
  fi
  existing=$(issue_with "$itemkey")
  if [ -n "$existing" ]; then
    body=$(gh issue view "$existing" --json body -q .body)
    if ! printf '%s' "$body" | grep -qF "$marker"; then
      printf '%s\n%s\n' "$body" "$marker" | gh issue edit "$existing" --body-file -
      gh issue comment "$existing" --body "Noticed again, in $from."
    fi
    continue
  fi
  issue_body "$item" "$from" "$itemkey" "$marker" | gh issue create --title "$(title_for "$item")" --label noticed --body-file -
done
