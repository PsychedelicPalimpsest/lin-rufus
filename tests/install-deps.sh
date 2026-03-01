#!/usr/bin/env bash
# install-deps.sh — Install Rufus build and test dependencies on Ubuntu 22.04.
# Used by: tests/Dockerfile  and  .github/workflows/linux.yml
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
  build-essential autoconf automake libtool pkg-config \
  libgtk-3-dev libcurl4-openssl-dev libssl-dev \
  libudev-dev libblkid-dev \
  libfontconfig1-dev libxml2-dev \
  libcdio-dev libcdio-utils \
  libz-dev \
  mingw-w64 \
  dosfstools \
  gcc-12
