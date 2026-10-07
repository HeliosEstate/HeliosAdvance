# Linux with systemd 250 to 255: Debian 12's systemd 252, the same pinned Debian as the
# bootstrap package's other Linux rows. The Build rows run in it as root, with systemd booted
# as the container's first process (a privileged container), so "has systemd" is the real
# thing and not a file made to look like it. Started without systemd, the same image is
# "installed, not running": the program reports 252 and no manager runs. D-Bus is installed
# with it, as a server gets it with systemd's recommends: an account other than root reads the
# running manager's version over the system bus.
FROM debian@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd dbus \
    && rm -rf /var/lib/apt/lists/*
