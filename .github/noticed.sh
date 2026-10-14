#!/usr/bin/env bash
# Opens one issue labeled noticed for each item of a "Noticed, not touched" list, in a pull
# request's body or in the plan in an issue's body (developer, 2026-10-10: a noticed item
# lived only in a body until a session copied it out, and two were never brought to him). The
# label means the item waits on his decision: fix it, defer it with its record and trigger,
# or close it as needing nothing, with the reason. An item seen before, in any body, gets no
# second issue: its text is the key, so a plan's item repeated in its pull request is one
# issue, which then names both sources.
#
# Usage: noticed.sh SOURCE < body, where SOURCE is pr-<number> or issue-<number>.
# Without GH_TOKEN, or with DRY_RUN=1, it prints the items and the issues it would open.
set -euo pipefail

source=$1

# items prints each item of the body's noticed list on one line: the list starts at a line
# that is only the heading (any # or ** around it) and ends at the next heading, the next
# bold line or the generated-by line. An item's indented continuation lines join it, and
# "Nothing" is no item.
items() {
  awk '
    function flush() { if (item != "" && tolower(item) !~ /^nothing\.?$/) print item; item = "" }
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

case $source in
  pr-*) from="pull request #${source#pr-}" ;;
  issue-*) from="the plan in #${source#issue-}" ;;
  *) echo "noticed.sh: SOURCE is pr-<number> or issue-<number>" >&2; exit 2 ;;
esac

dry=${DRY_RUN:-}
[ -z "${GH_TOKEN:-}" ] && dry=1

items | while IFS= read -r item; do
  key=$(printf '%s' "$item" | sed -e 's/[[:space:]]\+/ /g' -e 's/^ //' -e 's/ $//' | sha1sum | cut -c1-16)
  marker="<!-- noticed-source: $source -->"
  if [ -n "$dry" ]; then
    printf 'item %s from %s: %s\n' "$key" "$from" "$item"
    continue
  fi
  existing=$(gh issue list --label noticed --state all --limit 1000 --json number,body \
    -q ".[] | select(.body | contains(\"noticed-key: $key\")) | .number" | head -1)
  if [ -n "$existing" ]; then
    body=$(gh issue view "$existing" --json body -q .body)
    if ! printf '%s' "$body" | grep -qF "$marker"; then
      printf '%s\n%s\n' "$body" "$marker" | gh issue edit "$existing" --body-file -
      gh issue comment "$existing" --body "Noticed again, in $from."
    fi
    continue
  fi
  title="Noticed: $(printf '%s' "$item" | tr -d '`' | cut -c1-80)"
  {
    printf '%s\n\n' "$item"
    printf 'Noticed in %s and not touched there. It waits on the developer'"'"'s decision: fix it (this issue becomes the work), defer it (say here where it is recorded and what brings it back, then close it), or close it as needing nothing, with the reason.\n\n' "$from"
    printf '<!-- noticed-key: %s -->\n%s\n' "$key" "$marker"
  } | gh issue create --title "$title" --label noticed --body-file -
done
