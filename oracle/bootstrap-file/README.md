# The bootstrap file oracle

A second reader and writer of the bootstrap file, format 1. It was written from the format
description in `internal/bootstrap/contract.go`'s package comment and nothing else; the
engine's code was written separately from the same description. When the two disagree
about a file, one of them misread the description. Free Pascal, with its own AES-256 and
GCM (FIPS-197, SP 800-38D), so the oracle and the engine share no code at all.

It handles only the file. It never touches a key store, systemd, a key file's rules or
permissions: it is handed the 32-byte bootstrap key directly, as a test key.

## Commands

    bootstrap-file write KEY RECORDS OUTPUT   seal a record list into a bootstrap file
    bootstrap-file read KEY FILE              print a bootstrap file as a record list
    bootstrap-file newkey OUTPUT              make a random test key
    bootstrap-file selftest                   the published AES and GCM vectors

Any path may be `-` for standard input or output. KEY holds the 32 bytes as base64 in 44
characters, the engine's key-file form, or as 64 hex digits; whitespace around it is
ignored.

Exit status: 0 done; 1 usage, an unreadable path or a bad record list; 2 the file is not
unsealed (too large, too short, wrong magic, version 0 or newer than 1, tag fails);
3 unsealed, but the records break the format (framing, a name, a duplicate, a known field
absent or malformed, not one or two vault keys). The reason is on standard error. On
status 3 from a known-field problem the records are still printed; a framing problem
prints nothing.

`read` prints exactly what `write` takes, header included, so feeding a read back into
write with the same key reproduces the file byte for byte.

## The record list

One directive a line; `#` starts a comment outside a quoted value; blank lines are
ignored. Without `magic`, `version` or `nonce`, write uses `HADVBOOT`, 1 and a fresh
random nonce. Write judges nothing: whatever the list says is what is sealed, under the
real header as the additional data, so the file passes the integrity check and reaches
the engine's later checks.

| Directive | Effect |
|---|---|
| `record NAME DATA` | a record, its lengths taken from NAME and DATA |
| `record NAME DATA name-length=N data-length=N` | either length overridden, so it can lie |
| `raw DATA` | bytes appended to the plaintext with no framing |
| `magic DATA` | the 8 magic bytes |
| `version N` | the format version, 0 to 65535 |
| `nonce DATA` | the 12-byte nonce, instead of a random one |
| `truncate N` | after sealing, cut the file to N bytes |
| `flip N` | after sealing, flip the low bit of the byte at offset N |
| `append DATA` | after sealing, add bytes to the end |

Record lines, `raw` and the header directives may come in any order; records go into the
plaintext in the order given. The three after-sealing edits apply in the order given.

A NAME or DATA value is one of:

| Value | Bytes |
|---|---|
| `"text"` | the text's bytes; escapes `\\` `\"` `\n` `\r` `\t` `\xHH` |
| `hex:0aff` | the hex digits' bytes; `hex:` alone is empty |
| `zeros:N` | N zero bytes |
| `random:N` | N random bytes |

`zeros:` and `random:` stop at 262,144 bytes. `read` prints a value quoted when it is
UTF-8 with no control character, and as `hex:` otherwise.

## The wrong files the unit lines need

    record "a" "abc" data-length=100           a record's data runs past the end
    record "a" "abc" name-length=500           a record's name runs past the end
    raw hex:0005616263                         a record cut off inside its framing
    record "" "x"                              an empty name
    record hex:ff "x"                          a name that is not UTF-8
    record zeros:300 "x"                       a name longer than 255 bytes
    (two records with one name)                a duplicate
    (leave a known field out)                  a missing field
    record "server" hex:000001                 a known field in the wrong form, in place of
                                               the right one
    (three vault.key.N records)                three vault keys
    version 0  /  version 2                    version 0, a newer format
    magic "HADVBOOX"                           a wrong magic
    record "pad" zeros:70000                   larger than 65,536 bytes
    truncate 37                                shorter than header and tag
    flip 30                                    a tag that does not verify

## What the description leaves open

`read` takes a name `vault.key.` followed by anything but decimal digits as an unknown
record, not a malformed vault key, and accepts a version with leading zeros. The
description names neither case; until it does, no test should rest on them.

## Build and run

    fpc -O2 -Sew -obootstrap-file bootstrapfile.pas && ./bootstrap-file selftest

or the image, as every oracle is:

    docker build -t heliosestate/bootstrap-file-oracle:0.1 oracle/bootstrap-file
    docker run --rm -i -v <dir>:/data heliosestate/bootstrap-file-oracle:0.1 \
        bootstrap-file write /data/test.key /data/case.records /data/case.hadv

The image's build runs the self-test, so an image that builds has a cipher that matches
the standard.

The sample files kept for good are in `internal/bootstrap/testdata/format-1/`.
