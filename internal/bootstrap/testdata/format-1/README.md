# Bootstrap file samples, format 1

Made by the bootstrap file oracle (`oracle/bootstrap-file`), never by the engine, and kept
for good: when a newer format exists, the engine must still open every file here. Never
regenerate or edit them; a new case is a new file.

`bootstrap.key` is the test key, in the key-file form: 32 bytes as base64 in 44 characters
and one newline. Each `.hadv` sits beside its `.records`, the oracle's `read` of it; the
oracle's `write` of that `.records` with this key gives the `.hadv` byte for byte.

| File | What it holds |
|---|---|
| `one-vault-key.hadv` | every known field, one vault key |
| `two-vault-keys.hadv` | every known field, two vault keys |
| `unknown-records.hadv` | unknown records first, last, between known ones, empty, binary, and one with a name past ASCII |
| `largest.hadv` | exactly 65,536 bytes, the format's limit, padded by one unknown record |
