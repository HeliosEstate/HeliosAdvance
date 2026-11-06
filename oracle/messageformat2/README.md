# The MessageFormat 2 oracle

Unicode's published test suite for MessageFormat 2 (Unicode Technical Standard #35, LDML part
9), the oracle the Languages pages name for which texts the engine reads and which it counts as
missing. Each case is a message and what a correct reader makes of it: the text it gives, or the
errors it must report. The tests read these files; nothing is built from them, and the engine
never reads them.

## Where it comes from

The seven JSON files at the top of `test/tests/` in Unicode's `message-format-wg` repository on
GitHub, at commit `16372a6a02f41728be472a5921ba7c91774edeac`, copied byte for byte: each file's
git blob id matches that commit's. `LICENSE` is that repository's own license file, copied the
same way. The `functions/` folder is left out: every one of its cases calls a function, which
Languages Part 1 counts as missing, and the top-level files already hold such cases.

The test files are under the Unicode License v3 (`SPDX-License-Identifier: Unicode-3.0`), as
`LICENSE` says of everything in that repository but the standard's own text; the developer
admitted that license on 2026-09-25. Its notice travels with the files in `LICENSE`.

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

A newer commit replaces the files whole, by a pull request the developer reviews, with the commit
named here. The tests sort every case afresh, so a case added upstream lands under the line its
shape breaks.
