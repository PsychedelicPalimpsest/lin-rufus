#!/usr/bin/env bash
#
# build-rufus-mingw.sh
#
# Helper script to build Rufus for Windows using MinGW on Linux.
#
# This script assumes you have MinGW-w64 installed with at least:
#   - x86_64-w64-mingw32-gcc
#   - x86_64-w64-mingw32-windres
#   - x86_64-w64-mingw32-dlltool
#
# It performs the two required steps:
#   1) Build the custom delay-load libraries in .mingw
#   2) Build rufus.exe using the specified MinGW toolchain
#
# Usage:
#   ./build-rufus-mingw.sh
#
# Optional environment overrides:
#   CC=...        (default: x86_64-w64-mingw32-gcc)
#   WINDRES=...   (default: x86_64-w64-mingw32-windres)
#   DLLTOOL=...   (default: x86_64-w64-mingw32-dlltool)
#   JOBS=...      (default: 8)
#
# Example:
#   CC=x86_64-w64-mingw32-gcc \
#   WINDRES=x86_64-w64-mingw32-windres \
#   DLLTOOL=x86_64-w64-mingw32-dlltool \
#   JOBS=16 \
#   ./build-rufus-mingw.sh
#
set -euo pipefail

# -------- configuration --------

: "${CC:=x86_64-w64-mingw32-gcc}"
: "${WINDRES:=x86_64-w64-mingw32-windres}"
: "${DLLTOOL:=x86_64-w64-mingw32-dlltool}"
: "${JOBS:=8}"

# -------- helpers --------

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

info() {
  printf '==> %s\n' "$*"
}

# -------- sanity checks --------

# Ensure we are in the project root (directory containing this script and .mingw)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
cd "${SCRIPT_DIR}"

[ -d ".mingw" ] || die "This script must be run from the Rufus source tree root (missing .mingw directory)."

command -v "${CC}" >/dev/null 2>&1 || die "C compiler not found: ${CC}"
command -v "${WINDRES}" >/dev/null 2>&1 || die "windres not found: ${WINDRES}"
command -v "${DLLTOOL}" >/dev/null 2>&1 || die "dlltool not found: ${DLLTOOL}"

info "Using toolchain:"
info "  CC      = ${CC}"
info "  WINDRES = ${WINDRES}"
info "  DLLTOOL = ${DLLTOOL}"
info "  JOBS    = ${JOBS}"

# -------- step 1: build delay-load libs --------

info "Configuring for Windows target ..."
./configure --with-os=windows CC="${CC}" WINDRES="${WINDRES}" DLLTOOL="${DLLTOOL}"

info "Building delay-load libraries in .mingw ..."
make -C .mingw clean all DLLTOOL="${DLLTOOL}"

info "Delay-load libraries present:"
ls .mingw/*.lib 2>/dev/null || die "No *.lib files produced in .mingw"

# -------- step 2: build rufus.exe --------

info "Building Rufus with MinGW ..."
make CC="${CC}" WINDRES="${WINDRES}" -j"${JOBS}"

info "Build completed."

# Try to locate the resulting rufus.exe
if [ -f "src/rufus.exe" ]; then
  info "Result: src/rufus.exe"
else
  # Depending on the environment, the produced binary may be just 'rufus'
  if [ -f "src/rufus" ]; then
    info "Result: src/rufus (rename to rufus.exe if needed)"
  else
    info "Build finished, but output binary location is not obvious. Check src/ directory."
  fi
fi
