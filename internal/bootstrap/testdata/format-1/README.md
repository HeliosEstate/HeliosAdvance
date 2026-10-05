# Bootstrap file samples, format 1

Made by the bootstrap file oracle (`oracle/bootstrap-file`), never by the engine, and kept
for good: when a newer format exists, the engine must still open every file here. Never
regenerate or edit them; a new case is a new file.

`test.key` is the test key, held exactly as a real key file holds one: 32 bytes as base64
in 44 characters and one trailing newline, so the engine's key-file reader opens it with no
special case and the oracle reads the same file. It is not named `bootstrap.key`, the real
key file's name in a bootstrap folder, so that no person or tool looking for real key files
takes it for one. It is public on purpose and opens nothing but the samples beside it; each
format version's folder has its own, so one version's samples never depend on another's
key. Each `.hadv` sits beside its `.records`, the oracle's `read` of it; the
oracle's `write` of that `.records` with this key gives the `.hadv` byte for byte.

| File | What it holds |
|---|---|
| `one-vault-key.hadv` | every known field, one vault key |
| `two-vault-keys.hadv` | every known field, two vault keys |
| `unknown-records.hadv` | unknown records first, last, between known ones, empty, binary, and one with a name past ASCII |
| `largest.hadv` | exactly 65,536 bytes, the format's limit, padded by one unknown record |
