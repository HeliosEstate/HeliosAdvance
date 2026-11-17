# The MessageFormat 2 oracle

Unicode's published test suite for MessageFormat 2 (Unicode Technical Standard #35, LDML part
9), the oracle the Languages pages name for which texts the engine reads and which it counts as
missing. Each case is a message and what a correct reader makes of it: the text it gives, or the
errors it must report. The tests read these files; nothing is built from them, and the engine
never reads them.

## Where it comes from

The seven JSON files at the top of `test/tests/` in Unicode's `message-format-wg` repository on
GitHub, and that repository's own `LICENSE`. They are Unicode's, not this repository's, so they
are not committed here (the developer, 2026-11-10: "If it's not our code, I'd prefer it not to be
in our repo. Instead CI should download it as needed."). `pin` names the commit they come from and
each file's SHA-256. `bash check.sh`, before it runs the tests, fetches every file missing here
from that commit, and fails, naming the file and the pin, on any file whose SHA-256 is not the
pinned one, fetched or already here. The `functions/` folder is left out: every one of its cases
calls a function, which Languages Part 1 counts as missing, and the top-level files already hold
such cases.

The test files are under the Unicode License v3 (`SPDX-License-Identifier: Unicode-3.0`), as
`LICENSE` says of everything in that repository but the standard's own text; the developer
admitted that license on 2026-09-25. Its notice comes with the files, in the fetched `LICENSE`.

## What Languages Part 1 takes from it

Part 1 reads a text's characters, its escapes and its variable placeholders with no function,
option or attribute; everything else the standard allows counts as missing, as does a control or
bidi character and a placeholder the engine does not give that text. Against the suite that
means:

- A valid simple message of characters and escapes only is read as the case's `exp`.
- A case whose errors include `syntax-error` is not valid MessageFormat 2.
- Any other case is sorted by its shape: a complex message (a declaration or a quoted pattern);
  more of the standard than Part 1 reads (functions, literals, markup, attributes); a control or
  bidi character; a placeholder the text is not given. Each counts as missing.

## Updating it

A newer commit replaces the pin whole, by a pull request the developer reviews: the new commit on
its `commit` line, and each file's SHA-256 at that commit, from `sha256sum` over the files as
`https://raw.githubusercontent.com/unicode-org/message-format-wg/<commit>/<path>` serves them.
Remove the fetched files here, and `bash check.sh` fetches the new ones. The tests sort every case
afresh, so a case added upstream lands under the line its shape breaks.
