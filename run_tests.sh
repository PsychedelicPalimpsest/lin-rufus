#!/usr/bin/env bash
#
# run_tests.sh - Build and run the Rufus test suite
#
# Usage:
#   ./run_tests.sh [options]
#
# Options:
#   --linux-only   Only run Linux (native) tests
#   --wine-only    Only run Windows tests via Wine
#   --no-wine      Skip Wine tests even if wine is available
#   --help         Show this message
#
# Toolchain overrides (environment variables):
#   CC       - Linux C compiler          (default: gcc)
#   CC_WIN   - Windows C compiler        (default: x86_64-w64-mingw32-gcc)
#   JOBS     - Parallel build jobs       (default: $(nproc))

set -euo pipefail

: "${CC:=gcc}"
: "${CC_WIN:=x86_64-w64-mingw32-gcc}"
: "${JOBS:=$(nproc 2>/dev/null || echo 4)}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
TESTS_DIR="${SCRIPT_DIR}/tests"

RUN_LINUX=1
RUN_WINE=1

for arg in "$@"; do
  case "$arg" in
    --linux-only) RUN_WINE=0 ;;
    --wine-only)  RUN_LINUX=0 ;;
    --no-wine)    RUN_WINE=0 ;;
    --help)
      sed -n '2,/^$/p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 1
      ;;
  esac
done

die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '\n==> %s\n' "$*"; }

[ -d "${TESTS_DIR}" ] || die "tests/ directory not found (expected: ${TESTS_DIR})"

MAKE_ARGS=(-C "${TESTS_DIR}" -j"${JOBS}" CC="${CC}" CC_WIN="${CC_WIN}")

overall_failed=0

if [ "${RUN_LINUX}" -eq 1 ]; then
  info "Building Linux tests ..."
  command -v "${CC}" >/dev/null 2>&1 || die "C compiler not found: ${CC}"
  make "${MAKE_ARGS[@]}" linux

  info "Running Linux tests ..."
  make "${MAKE_ARGS[@]}" run-linux || overall_failed=$((overall_failed + 1))
fi

if [ "${RUN_WINE}" -eq 1 ]; then
  if ! command -v wine >/dev/null 2>&1; then
    info "wine not found - skipping Windows tests (use --linux-only to suppress this message)"
  elif ! command -v "${CC_WIN}" >/dev/null 2>&1; then
    info "${CC_WIN} not found - skipping Windows tests (install mingw-w64 to enable)"
  else
    info "Building Windows tests (MinGW) ..."
    make "${MAKE_ARGS[@]}" windows

    info "Running Windows tests via Wine ..."
    make "${MAKE_ARGS[@]}" run-wine || overall_failed=$((overall_failed + 1))
  fi
fi

echo ""
if [ "${overall_failed}" -eq 0 ]; then
  echo "All tests passed."
else
  echo "${overall_failed} test target(s) FAILED."
  exit 1
fi
