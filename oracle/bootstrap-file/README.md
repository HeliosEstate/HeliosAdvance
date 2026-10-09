# The bootstrap file oracle

A second reader and writer of the bootstrap file, format 1. A Claude session wrote it from
the format description in `internal/bootstrap/contract.go`'s package comment and nothing
else, never from the engine's code. A Codex session (GPT Luna 6, medium effort) and a
DeepSeek-V4-Pro session (high effort) checked it, and the developer read it. When the
header gained its key holder and sealed key, a Claude session changed the oracle the same
way; that change was proved by running every file in the list below against it, not by
other models, since the AES and GCM code did not change.
The engine's code is written separately from the same description. When the two disagree
about a file, one of them misread the description. Free Pascal, with its own AES-256 and
GCM (FIPS-197, SP 800-38D), so the oracle and the engine share no code at all.

It handles only the file. It never touches a key store, systemd, a key file's rules or
permissions: it is handed the 32-byte bootstrap key directly, as a test key. It writes and
checks the header's key holder and sealed key as bytes, and never asks a key holder for
anything.

## Commands

    bootstrap-file write KEY RECORDS OUTPUT   seal a record list into a bootstrap file
    bootstrap-file read KEY FILE              print a bootstrap file as a record list
    bootstrap-file newkey OUTPUT              make a random test key
    bootstrap-file selftest                   the published AES and GCM vectors

Any path may be `-` for standard input or output. KEY holds the 32 bytes as base64 in 44
characters, the engine's key-file form, or as 64 hex digits; whitespace around it is
ignored.

Exit status, one for each code the engine gives a file:

| Status | The file | The engine's code |
|---|---|---|
| 0 | read, and every known field keeps its rule | none |
| 1 | not reached: usage, an unreadable path or a bad record list | none |
| 2 | its header breaks the format: larger than 65,536 bytes, too short, a wrong magic, format version 0 or newer than 1, a key holder outside 1 to 5, a sealed-key length wrong for its key holder, or a Windows key name not `hadv-` and 32 lowercase hex digits | `ErrFormat` |
| 3 | unsealed, but the records break the format (framing, a name, a duplicate, a name under `vault.key.` that is not a version) or a known field is absent or breaks its rule in the table on `Fields` (not one or two vault keys among them) | `ErrInvalid` |
| 4 | the GCM tag does not verify under the key | `ErrDecrypt` |

The reason is on standard error. Status 2 comes before the key is used. On status 3 from a
known-field problem the records are still printed; a framing problem prints nothing.

`read` prints exactly what `write` takes, header included, so feeding a read back into
write with the same key reproduces the file byte for byte.

## The record list

One directive a line; `#` starts a comment where a token would start (at the start of a
line or after a space), so `"x"#` is refused, not read as a comment; blank lines are
ignored. Without `magic`, `version`, `holder`, `sealed` or `nonce`, write uses `HADVBOOT`,
1, key holder 4 (the key file), no sealed key and a fresh random nonce. Write judges
nothing: whatever the list says is what is sealed, under every byte before the records as
the additional data, so the file passes the integrity check and reaches the engine's later
checks.

| Directive | Effect |
|---|---|
| `record NAME DATA` | a record, its lengths taken from NAME and DATA |
| `record NAME DATA name-length=N data-length=N` | either length overridden, so it can lie |
| `raw DATA` | bytes appended to the plaintext with no framing |
| `magic DATA` | the 8 magic bytes |
| `version N` | the format version, 0 to 65535 |
| `holder N` | the key holder, 0 to 255 |
| `sealed DATA ...` | the sealed key; several values are joined, so a Windows key's name and wrap fit on one line |
| `sealed-length N` | the sealed key's length as written, 0 to 65535, so it can lie |
| `nonce DATA` | the 12-byte nonce, instead of a random one |
| `truncate N` | after sealing, cut the file to N bytes |
| `flip N` | after sealing, flip the low bit of the byte at offset N |
| `append DATA` | after sealing, add bytes to the end |

Record lines, `raw` and the header directives may come in any order; records go into the
plaintext in the order given. The three after-sealing edits apply in the order given.
`read` prints the header in its order: `magic`, `version`, `holder`, `sealed` (`""` when
there is none), then `nonce`.

A NAME or DATA value is one of:

| Value | Bytes |
|---|---|
| `"text"` | the text's bytes; escapes `\\` `\"` `\n` `\r` `\t` `\xHH` |
| `hex:0aff` | the hex digits' bytes; `hex:` alone is empty |
| `zeros:N` | N zero bytes |
| `random:N` | N random bytes |

`zeros:` and `random:` stop at 262,144 bytes. `read` prints a value quoted when it is
UTF-8 with no control character (C0, DEL or C1), and as `hex:` otherwise.

## The wrong files the unit lines need

Each one is a good file's list with the lines below added; each gets the status beside it.

    record "pad" zeros:70000                   larger than 65,536 bytes                     2
    truncate 10                                shorter than the header's first 13 bytes     2
    truncate 40                                shorter than its header, nonce and tag       2
    magic "HADVBOOX"                           a wrong magic                                2
    version 0  /  version 2                    version 0, a newer format                    2
    holder 0  /  holder 6                      a key holder outside 1 to 5                  2
    holder 1 + sealed "hadv-..." random:255    a Windows sealed key one byte short          2
    holder 1 + sealed "hadv-0123...ABCD" ...   a Windows key name not lowercase hex         2
    holder 2 + sealed ""                       a systemd sealed key that is empty           2
    holder 3 + sealed random:4097              a systemd sealed key past 4,096 bytes        2
    holder 4 + sealed random:1                 a key file's header with a sealed key        2
    holder 2 + sealed random:100
      + sealed-length 4000                     a sealed-key length past the file's end      2
    holder 2 + sealed random:100
      + sealed-length 50                       a sealed-key length that lies inside it      4
    flip 14                                    a nonce changed (key holder 4)               4
    flip 10                                    key holder 4 changed to 5                    4
    flip 60                                    a ciphertext byte changed                    4
    (another key)                              the wrong key                                4
    record "a" "abc" data-length=100           a record's data runs past the end            3
    record "a" "abc" name-length=500           a record's name runs past the end            3
    raw hex:0005616263                         a record cut off inside its framing          3
    record "" "x"                              an empty name                                3
    record hex:ff "x"                          a name that is not UTF-8                     3
    record zeros:300 "x"                       a name longer than 255 bytes                 3
    (two records with one name)                a duplicate                                  3
    (leave a known field out)                  a missing field                              3
    record "server" hex:000001                 a known field in the wrong form, in place
                                               of the right one                             3
    record "server" hex:00000000               a known field that breaks its rule in the
                                               table on Fields, in place of the right one   3
    record "database.account.password" ""      an empty password, in place of the right one 3
    (three vault.key.N records)                three vault keys                             3
    record "vault.key.01" zeros:32             a version with a leading zero                3
    record "vault.key.0" zeros:32              version 0                                    3
    record "vault.key.4294967296" zeros:32     a version past 4,294,967,295                 3
    record "vault.key.x" zeros:32              a name under the prefix that is no version   3

## Build and run

    fpc -O2 -Sew -obootstrap-file bootstrapfile.pas && ./bootstrap-file selftest

or the image, as every oracle is:

    docker build -t heliosestate/bootstrap-file-oracle:0.1 oracle/bootstrap-file
    docker run --rm -i -v <dir>:/data heliosestate/bootstrap-file-oracle:0.1 \
        bootstrap-file write /data/test.key /data/case.records /data/case.hadv

The image's build runs the self-test, so an image that builds has a cipher that matches
the standard. The tag stayed 0.1 when the header changed, so an image built before then
reads the old header: build it again.

## The kept samples

In `internal/bootstrap/testdata/format-1/`, kept for good, so every later engine shows it
still reads format 1. Each `.records` file is what `read` prints in the image for the
`.hadv` beside it, so `write` with `test.key` rebuilds that file byte for byte. Built on
Windows, `read` ends its lines with CR LF; `write` takes either.

    test.key                       the test key, in the key file's form
    keyholder-1.hadv               the Windows key store: a made-up hadv- name and 256 random
                                   bytes standing in for the wrap
    keyholder-2.hadv               systemd, decrypted by the service: 512 random bytes
                                   standing in for the credential
    keyholder-3.hadv               systemd, decrypted at service start: the same
    keyholder-4.hadv               the key file: no sealed key
    keyholder-5.hadv               the Swarm secret: no sealed key
    two-vault-keys.hadv            two vault keys, as during a vault-key change
    unknown-record.hadv            a record of a name this version does not know, between
                                   the known ones

Each holds every known field, with one vault key unless its name says otherwise. The wrong
files are not kept: the tests make them at run time from the list above.
