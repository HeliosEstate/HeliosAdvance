# The sexyz oracle: Synchronet's X/Y/ZMODEM program, the transfer code SyncTERM carries.
# Clean-room: the build stage fetches the source at one pinned commit, compiles it and is
# discarded; the final image holds the one binary. Nothing in this image is ours, and no
# session reads the source. The GPL binary is built and run locally, never pushed.
FROM debian:bookworm-slim AS build
# The last change to sexyz.c, 2026-09-07, carrying the August 2026 overhaul (ESCCTL fixes,
# ESC8 withdrawn); no release tag holds it yet. Moved to a tag when one does.
ARG SBBS_COMMIT=039cfb8ed9bcea571b8960a7d4c108ef1158acd2
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates build-essential pkg-config libncurses-dev \
    && rm -rf /var/lib/apt/lists/*
# The upstream repository first, its GitHub mirror second; the hash fixes identity either way.
RUN git init -q /sbbs \
    && (git -C /sbbs fetch -q --depth 1 https://gitlab.synchro.net/main/sbbs.git "$SBBS_COMMIT" \
        || git -C /sbbs fetch -q --depth 1 https://github.com/SynchronetBBS/sbbs.git "$SBBS_COMMIT") \
    && git -C /sbbs checkout -q -b pinned FETCH_HEAD
WORKDIR /sbbs/src/sbbs3
# The git headers are make targets the sexyz target does not depend on; make them first.
RUN for h in git_branch.h git_hash.h git_date.h; do make "$h" RELEASE=1 >/dev/null 2>&1 || true; done \
    && make sexyz RELEASE=1 \
    && cp "$(find . -type f -name sexyz -perm -u+x | head -1)" /sexyz

FROM debian:bookworm-slim
COPY --from=build /sexyz /usr/local/bin/sexyz
WORKDIR /data
