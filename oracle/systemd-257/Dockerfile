# Linux with systemd 256 or later: Debian 13's systemd 257, whose credentials can be scoped to
# one account. The bootstrap package's Build rows run in it as root, with systemd booted as the
# container's first process (a privileged container): a credential scoped to the service
# account, which that account decrypts and another cannot. D-Bus is installed with it, as a
# server gets it with systemd's recommends: an account other than root reads the running
# manager's version over the system bus.
FROM debian@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd dbus \
    && rm -rf /var/lib/apt/lists/*
