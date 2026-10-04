# The bootstrap file oracle: the developer's own reader and writer of the bootstrap file
# format, written from the format's description and never from the engine. Built from the
# Pascal source beside this file; the build stage runs the published AES and GCM vectors, so
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
