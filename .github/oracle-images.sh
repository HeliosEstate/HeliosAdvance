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
    rm -f "$cache/$name"-*.tar
    docker save -o "$saved" "$tag"
  fi
done
