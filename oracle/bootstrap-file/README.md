# The bootstrap file oracle

A second reader and writer of the bootstrap file, format version 1, for the key file. It was
written from the format's description in `internal/bootstrap/contract.go`'s package comment and
nothing else, never from the engine's code, and changed the same way when the format's layout
changed. The engine's code is written separately from the same description. When the two
disagree about a file, one of them misread the description. Free Pascal, with its own AES-256
and GCM (FIPS-197, SP 800-38D), so the oracle and the engine share no code at all.

It handles only the file and the key in the key file's form. It never checks a key file's owner
or permissions, and it knows nothing of what the sealed JSON means: it seals the bytes it is
given and prints the bytes it unseals.

## Commands

    bootstrap-file write KEY PLAINTEXT OUTPUT [EDITS]   seal PLAINTEXT's bytes into a bootstrap file
    bootstrap-file read KEY FILE                        print a bootstrap file's unsealed bytes
    bootstrap-file newkey OUTPUT                        make a random test key, in the key file's form
    bootstrap-file selftest                             the published AES and GCM vectors

Any path may be `-` for standard input or output. KEY is a key file in its form: 44 characters
of RFC 4648's standard base64 alphabet with its padding, decoding to 32 bytes with the bits
after the last byte zero, then nothing, one line feed, or one carriage return and line feed.
Any other key is refused with status 1. A key of 32 zero bytes is taken: the oracle judges no
key.

Without EDITS, write makes a good file: `HADVBOOT`, format version 1, key holder 1 (the key
file), a sealed-key length of 0 and a fresh random nonce. With EDITS, it makes the broken file
the list describes.

Exit status, one for each of the engine's refusals of a file:

| Status | The file | The engine's error |
|---|---|---|
| 0 | read: its unsealed bytes are on standard output | none |
| 1 | not reached: usage, an unreadable path, a key not in the key file's form, or a bad edits list | none |
| 2 | larger than 65,536 bytes | `ErrFileTooLarge` |
| 3 | its header is not format version 1's for the key file: shorter than its header, nonce and tag (41 bytes), a wrong magic, a format version but 1, a key holder but 1, or a sealed-key length but 0 | `ErrHeader` |
| 4 | the GCM tag does not verify under the key | `ErrUnseal` |

The reason is on standard error. Statuses 2 and 3 come before the key file is read, so a file
with a broken header gets its status even when KEY is missing or malformed.

## The edits list

One directive a line; `#` starts a comment where a token would start (at the start of a line or
after a space), so `"x"#` is refused, not read as a comment; blank lines are ignored. Write
judges nothing: whatever the list says is what is written, and every byte before the sealed
plaintext, as written, is the additional data, so a file with a wrong header still carries a tag
that verifies and reaches the engine's later checks.

| Directive | Effect |
|---|---|
| `magic DATA` | the 8 magic bytes |
| `version N` | the format version, 0 to 65535 |
| `holder N` | the key holder, 0 to 255 |
| `sealed DATA ...` | a sealed key after the header's first 13 bytes; several values are joined |
| `sealed-length N` | the sealed key's length as written, 0 to 65535, so it can lie |
| `nonce DATA` | the 12-byte nonce, instead of a random one |
| `truncate N` | after sealing, cut the file to N bytes |
| `flip N` | after sealing, flip the low bit of the byte at offset N |
| `append DATA` | after sealing, add bytes to the end |

The header directives may come in any order. The three after-sealing edits apply in the order
given.

A DATA value is one of:

| Value | Bytes |
|---|---|
| `"text"` | the text's bytes; escapes `\\` `\"` `\n` `\r` `\t` `\xHH` |
| `hex:0aff` | the hex digits' bytes; `hex:` alone is empty |
| `zeros:N` | N zero bytes |
| `random:N` | N random bytes |

`zeros:` and `random:` stop at 262,144 bytes, as do PLAINTEXT and EDITS.

## The broken files the page's lines need

Each one is a good file's plaintext written with the edits below; each gets the status beside
it. A good file is 41 bytes longer than its plaintext.

    (a plaintext of 65,495 bytes)              65,536 bytes exactly                         0
    (a plaintext of 65,496 bytes)              65,537 bytes                                 2
    append zeros:70000                         larger than 65,536 bytes                     2
    truncate 10                                shorter than the header's first 13 bytes     3
    truncate 40                                shorter than its header, nonce and tag       3
    magic "HADVBOOX"                           a wrong magic                                3
    version 0  /  version 2                    format version 0, a newer one                3
    holder 0  /  holder 2                      a key holder but the key file                3
    holder 2 + sealed random:100               another key holder with its sealed key       3
    sealed hex:00                              a sealed key under the key file              3
    sealed-length 1                            a sealed-key length that lies                3
    truncate 41                                a header, nonce and tag with nothing sealed  4
    flip 14                                    a nonce changed                              4
    flip 60                                    a sealed byte changed                        4
    append hex:00                              a byte added at the end                      4
    (another key)                              the wrong key                                4

## Build and run

    fpc -O2 -Sew -obootstrap-file bootstrapfile.pas && ./bootstrap-file selftest

or the image, as every oracle is:

    docker build -t heliosestate/bootstrap-file-oracle:0.2 oracle/bootstrap-file
    docker run --rm -i -v <dir>:/data heliosestate/bootstrap-file-oracle:0.2 \
        bootstrap-file write /data/test.key /data/case.json /data/case.hadv

The image's build runs the self-test, so an image that builds has a cipher that matches the
standard. The tag is 0.2: an image tagged 0.1 reads an earlier layout of the header.
