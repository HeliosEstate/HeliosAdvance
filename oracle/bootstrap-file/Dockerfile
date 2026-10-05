# The bootstrap file oracle: a second reader and writer of the bootstrap file format,
# written by a Claude session from the format's description alone, never from the engine's
# code; checked by a Codex session (GPT Luna 6, medium effort) and a DeepSeek-V4-Pro session
# (high effort), and read by the developer. Built from the Pascal source beside this file;
# the build stage runs the published AES and GCM vectors, so
# an image that builds is one whose cipher matches the standard.
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends fp-compiler \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY *.pas ./
RUN fpc -O2 -Sew -obootstrap-file bootstrapfile.pas && ./bootstrap-file selftest

FROM debian:bookworm-slim
COPY --from=build /src/bootstrap-file /usr/local/bin/bootstrap-file
WORKDIR /data
