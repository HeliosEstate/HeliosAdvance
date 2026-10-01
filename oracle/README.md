# Oracles

Reference implementations the tests speak to. None of this code is ours; each image holds a
program the model did not write and cannot edit, which is the point.

| Image | Built from | Used by |
|---|---|---|
| `heliosestate/lrzsz-oracle:0.1` | `oracle/lrzsz/Dockerfile` | the ZMODEM tests (proof run one) |

Build: `docker build -t heliosestate/lrzsz-oracle:0.1 oracle/lrzsz`.
Remove when no longer needed: `docker rmi heliosestate/lrzsz-oracle:0.1`.
Every image this project creates is listed here; one not listed is not ours to keep.

## How a test speaks to it

Over docker's stdio, bidirectionally, no terminal: `docker run --rm -i -v <dir>:/data
heliosestate/lrzsz-oracle:0.1 sz -b -q /data/<file>` to receive from the oracle, and the same
with `rz -b -q` in `-w /out` to send to it. Proved 2026-10-01 with a scratch Go program
bridging `sz` in one container to `rz` in another: 100,000 random bytes, identical hashes.
`socat` is in the image for a manual self-check only; FIFOs and `socat` bridges deadlock on
open ordering and are not how the tests work.
