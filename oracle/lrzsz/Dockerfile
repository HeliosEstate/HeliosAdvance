# The ZMODEM oracle: lrzsz, the reference implementation every Linux distribution ships.
# A test speaks ZMODEM to sz or rz over the container's stdin and stdout; the file arrives
# byte-identical or it does not. Nothing in this image is ours.
FROM debian:bookworm-slim
# socat only bridges sz to rz for a self-check; a Go test needs neither, it is the other end.
RUN apt-get update && apt-get install -y --no-install-recommends lrzsz socat && rm -rf /var/lib/apt/lists/*
WORKDIR /data
