#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Pascal Fairchild
# SPDX-License-Identifier: AGPL-3.0-only
#
# Loads each oracle's image from the given cache folder, or builds it and saves it there. A saved
# image's file name carries a hash of its oracle folder, so an image is rebuilt, and Docker Hub
# asked for its base image, only when that folder changes. Every oracle the tree holds, none on a
# tree without any: main is the skeleton.
set -euo pipefail
cache=$1
mkdir -p "$cache"
for folder in oracle/*/; do
  [ -d "$folder" ] || continue
  name=$(basename "$folder")
  tag="heliosestate/$name-oracle:0.1"
  sum=$(cd "$folder" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -c1-16)
  saved="$cache/$name-$sum.tar"
  if [ -f "$saved" ]; then
    docker load -q -i "$saved"
  else
    docker build -q -t "$tag" "$folder"
    # Only this oracle's own saves: its name, a hyphen and the 16-character hash. A glob on the
    # name alone also caught another oracle's whose name starts with this one's plus a hyphen
    # (the codebase review, 2026-10-24).
    for old in "$cache/$name"-*.tar; do
      [[ $(basename "$old") =~ ^"$name"-[0-9a-f]{16}\.tar$ ]] && rm -f -- "$old"
    done
    docker save -o "$saved" "$tag"
  fi
done
