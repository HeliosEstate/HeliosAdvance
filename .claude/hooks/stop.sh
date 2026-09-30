#!/usr/bin/env bash
# Stop hook. In a loop session (HELIOS_LOOP=1) a turn may not end on a red check.sh: the turn
# is sent back with the failure, three times; the fourth red ends the session and leaves
# .helios-stop-red for the loop wrapper to read.
[ "${HELIOS_LOOP:-}" = 1 ] || exit 0
root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
cd "$root"
if out=$(bash check.sh 2>&1); then rm -f .helios-red; exit 0; fi
n=$(( $(cat .helios-red 2>/dev/null || echo 0) + 1 )); echo "$n" > .helios-red
if [ "$n" -ge 4 ]; then
  printf '%s\n' "$out" | tail -40 > .helios-stop-red
  exit 0
fi
{ echo "check.sh is red (attempt $n of 3). Fix it or, if the locked tests cannot pass, comment on the issue and stop:"; printf '%s\n' "$out" | tail -40; } >&2
exit 2
