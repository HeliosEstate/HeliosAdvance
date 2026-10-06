# Linux with systemd below 250: Ubuntu 22.04's systemd 249, which has no systemd-creds. The
# bootstrap package's Build rows run in it as root, with systemd booted as the container's
# first process (a privileged container), so "has systemd" is the real thing and not a file
# made to look like it. Started without systemd, the same image is "installed, not running".
FROM ubuntu@sha256:5ec03bb3441e8b0bf3b4f9cd4629a1ae763010dc3035bb8da3ae6cf026486401
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd \
    && rm -rf /var/lib/apt/lists/*
