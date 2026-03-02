#!/usr/bin/env bash
# install-deps.sh — Install Rufus build and test dependencies on Ubuntu 22.04.
# Used by: tests/Dockerfile  and  .github/workflows/linux.yml
#
# Dependency categories:
#   BUILD  — required to configure and compile Rufus for Linux
#   TEST   — required to build and run the test suite
#   ASAN   — required for AddressSanitizer / UBSan test targets
#   STATIC — required for cppcheck static analysis
#   CROSS  — required to cross-compile for Windows (MinGW)
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
  `# BUILD: autotools + compiler` \
  build-essential autoconf automake libtool pkg-config gcc-12 \
  `# BUILD: GTK3 UI` \
  libgtk-3-dev \
  `# BUILD: network + crypto` \
  libcurl4-openssl-dev libssl-dev \
  `# BUILD: device and filesystem` \
  libudev-dev libblkid-dev \
  `# BUILD: fonts, notifications, XML, compression` \
  libfontconfig1-dev libnotify-dev libxml2-dev zlib1g-dev \
  `# BUILD: optical disc / ISO support (bundled libcdio uses these headers)` \
  libcdio-dev libiso9660-dev libudf-dev libcdio-utils \
  `# TEST: WIM image manipulation` \
  wimtools \
  `# TEST: filesystem formatting tools used by format tests` \
  dosfstools ntfs-3g exfatprogs udftools \
  `# TEST: loop device support for loopback integration tests` \
  util-linux \
  `# ASAN: AddressSanitizer + Undefined Behaviour Sanitizer runtime` \
  libasan6 libubsan1 \
  `# STATIC: cppcheck static analysis` \
  cppcheck \
  `# CROSS: MinGW Windows cross-compiler` \
  mingw-w64
