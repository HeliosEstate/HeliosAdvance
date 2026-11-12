# The bootstrap file oracle: a second reader and writer of the bootstrap file format, written
# from the format's description alone, never from the engine's code (see README.md). Built from
# the Pascal source beside this file; the build stage runs the published AES and GCM vectors, so
# an image that builds is one whose cipher matches the standard.
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS build
RUN apt-get update && apt-get install -y --no-install-recommends fp-compiler \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY *.pas ./
RUN fpc -O2 -Sew -obootstrap-file bootstrapfile.pas && ./bootstrap-file selftest

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
COPY --from=build /src/bootstrap-file /usr/local/bin/bootstrap-file
WORKDIR /data
