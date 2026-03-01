#!/usr/bin/env bash
#
# build-rufus-linux.sh
#
# Helper script to build Rufus for Linux.
#
# Usage:
#   ./build-rufus-linux.sh
#
# Optional environment overrides:
#   CC=...    (default: gcc)
#   JOBS=...  (default: 8)
#
set -euo pipefail

: "${CC:=gcc}"
: "${JOBS:=8}"

die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '==> %s\n' "$*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
cd "${SCRIPT_DIR}"

command -v "${CC}" >/dev/null 2>&1 || die "C compiler not found: ${CC}"

info "Using toolchain:"
info "  CC   = ${CC}"
info "  JOBS = ${JOBS}"

info "Configuring for Linux target ..."
./configure --with-os=linux CC="${CC}"

info "Building Rufus ..."
make clean
make -j"${JOBS}"

info "Build completed."
[ -f "src/rufus" ] && info "Result: src/rufus" || info "Build finished; check src/ for output."
