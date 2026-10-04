# Oracles

Reference implementations the tests speak to. Each image holds a program written apart from
the engine, which a loop session cannot edit, which is the point: the transfer programs are
other people's, and `bootstrap-file` is the developer's own, written from the format's
description and never from the engine's code.

| Image | Built from | Used by |
|---|---|---|
| `heliosestate/lrzsz-oracle:0.1` | `oracle/lrzsz/Dockerfile` | the ZMODEM tests (proof run one) |
| `heliosestate/sexyz-oracle:0.1` | `oracle/sexyz/Dockerfile` | the sexyz rows of every transfer test (#15) |
| `heliosestate/bootstrap-file-oracle:0.1` | `oracle/bootstrap-file/Dockerfile` | the bootstrap file's format lines; see its README |

Build: `docker build -t heliosestate/lrzsz-oracle:0.1 oracle/lrzsz`,
`docker build -t heliosestate/sexyz-oracle:0.1 oracle/sexyz` and
`docker build -t heliosestate/bootstrap-file-oracle:0.1 oracle/bootstrap-file`.
Remove when no longer needed: `docker rmi heliosestate/lrzsz-oracle:0.1
heliosestate/sexyz-oracle:0.1 heliosestate/bootstrap-file-oracle:0.1`.
Every image this project creates is listed here; one not listed is not ours to keep.

## How a test speaks to it

Over docker's stdio, bidirectionally, no terminal: `docker run --rm -i -v <dir>:/data
heliosestate/lrzsz-oracle:0.1 sz -b -q /data/<file>` to receive from the oracle, and the same
with `rz -b -q` in `-w /out` to send to it. Proved 2026-10-01 with a scratch Go program
bridging `sz` in one container to `rz` in another: 100,000 random bytes, identical hashes.
`socat` is in the image for a manual self-check only; FIFOs and `socat` bridges deadlock on
open ordering and are not how the tests work.

## sexyz

Synchronet's transfer program, the code SyncTERM carries, so it is the far end most callers
bring. Built clean-room from a pinned commit of the sbbs repository: the source is fetched,
compiled and discarded inside the image build, in a stage the final image does not keep;
it never exists in this repository or on the build machine, and no session reads it. What
sexyz does is learned from its documentation, its usage text, and its bytes on the wire.
The binary is GPL; the image is built and run locally and in CI, never pushed anywhere.

Over docker stdio with no socket argument sexyz runs in stdio mode; `-raw` turns Telnet
mode off. A receive path needs its trailing slash (`rz /data/`): `rz .` stores
`.payload.bin`. A batch is a list file: `sz @list.txt`. Probed 2026-10-01 against lrzsz
both ways, 8K, segmented, escaping, XMODEM-G and YMODEM-G between two sexyz ends.
