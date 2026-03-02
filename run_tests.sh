#!/usr/bin/env bash
#
# run_tests.sh - Build and run the Rufus test suite
#
# Usage:
#   ./run_tests.sh [options]
#
# Options:
#   --linux-only       Only run Linux (native) tests
#   --wine-only        Only run Windows tests via Wine
#   --no-wine          Skip Wine tests even if wine is available
#   --root-only        Only run tests that require root (e.g. loopback)
#   --container        Run root-requiring tests inside a privileged Docker/Podman
#                      container (mirrors the GitHub CI environment: ubuntu:22.04)
#   --full-container   Run the complete test suite (linux + ASAN + cppcheck + root)
#                      inside a privileged Docker/Podman container.  Requires all
#                      deps from tests/install-deps.sh to be baked into the image.
#   --help             Show this message
#
# Toolchain overrides (environment variables):
#   CC       - Linux C compiler          (default: gcc)
#   CC_WIN   - Windows C compiler        (default: x86_64-w64-mingw32-gcc)
#   JOBS     - Parallel build jobs       (default: $(nproc))
#   CONTAINER_RUNTIME - docker or podman (default: auto-detected)

set -euo pipefail

: "${CC:=gcc}"
: "${CC_WIN:=x86_64-w64-mingw32-gcc}"
: "${JOBS:=$(nproc 2>/dev/null || echo 4)}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
TESTS_DIR="${SCRIPT_DIR}/tests"

RUN_LINUX=1
RUN_WINE=1
RUN_ROOT=0
RUN_CONTAINER=0
RUN_FULL_CONTAINER=0

for arg in "$@"; do
  case "$arg" in
    --linux-only)       RUN_WINE=0 ;;
    --wine-only)        RUN_LINUX=0; RUN_ROOT=0 ;;
    --no-wine)          RUN_WINE=0 ;;
    --root-only)        RUN_LINUX=0; RUN_WINE=0; RUN_ROOT=1 ;;
    --container)        RUN_LINUX=0; RUN_WINE=0; RUN_ROOT=0; RUN_CONTAINER=1 ;;
    --full-container)   RUN_LINUX=0; RUN_WINE=0; RUN_ROOT=0; RUN_FULL_CONTAINER=1 ;;
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

# ---------------------------------------------------------------------------
# Container runtime detection (shared by --container and --full-container)
# Sets CONTAINER_RUNTIME (string), CONTAINER_BUILD_CMD and CONTAINER_RUN_CMD
# (arrays).  When rootless podman is detected:
#   - CONTAINER_BUILD_CMD stays as plain "podman" (no sudo needed for builds)
#   - CONTAINER_RUN_CMD is "sudo podman" (real root needed for loop devices)
#   - CONTAINER_ROOTLESS=1 triggers a "podman image scp" to copy the freshly
#     built image into root's podman storage before running.
# ---------------------------------------------------------------------------
_detect_container_runtime() {
  if [ -z "${CONTAINER_RUNTIME:-}" ]; then
    if command -v docker >/dev/null 2>&1; then
      CONTAINER_RUNTIME=docker
    elif command -v podman >/dev/null 2>&1; then
      CONTAINER_RUNTIME=podman
    else
      die "No container runtime found. Install docker or podman."
    fi
  fi
  CONTAINER_BUILD_CMD=("${CONTAINER_RUNTIME}")
  CONTAINER_RUN_CMD=("${CONTAINER_RUNTIME}")
  CONTAINER_ROOTLESS=0
  if [[ "${CONTAINER_RUNTIME}" == "podman" ]] && \
     podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null | grep -q "^true"; then
    CONTAINER_RUN_CMD=(sudo "${CONTAINER_RUNTIME}")
    CONTAINER_ROOTLESS=1
  fi
}

# Copy the image from rootless podman storage into root podman storage so that
# "sudo podman run" can find it.  Uses "podman image scp" which is fast on
# repeat runs because already-present blobs are skipped automatically.
# Note: "podman image scp" may return exit code 125 even on success (podman
# bug); we therefore verify that the image actually arrived in root's store.
_sync_image_to_root() {
  # Skip the (expensive) copy if root podman already has the exact same image.
  local user_id root_id
  user_id=$(podman image inspect localhost/rufus-test-env --format '{{.Id}}' 2>/dev/null || true)
  root_id=$(sudo podman image inspect localhost/rufus-test-env --format '{{.Id}}' 2>/dev/null || true)
  if [[ -n "${user_id}" && "${user_id}" == "${root_id}" ]]; then
    return 0
  fi
  info "Copying image to root podman storage (needed for loop-device access) ..."
  podman image scp localhost/rufus-test-env root@ || true
  sudo podman image exists rufus-test-env || \
    die "Failed to copy rufus-test-env to root podman storage"
}

# ---------------------------------------------------------------------------
# --container: run root-requiring tests inside a privileged container.
# Uses tests/Dockerfile (ubuntu:22.04 + all deps pre-baked) so that
# repeated runs skip the apt-install layer.  The source tree is bind-mounted
# read-write so test binaries are built fresh inside the container but the
# rest of the checkout remains on the host.  Supports docker and podman.
# ---------------------------------------------------------------------------
if [ "${RUN_CONTAINER}" -eq 1 ]; then
  _detect_container_runtime
  info "Building container image rufus-test-env (cached after first run) ..."
  "${CONTAINER_BUILD_CMD[@]}" build -t rufus-test-env "${SCRIPT_DIR}/tests"
  [ "${CONTAINER_ROOTLESS}" -eq 1 ] && _sync_image_to_root
  info "Running root tests in privileged ${CONTAINER_RUNTIME} container ..."
  exec "${CONTAINER_RUN_CMD[@]}" run --rm --privileged \
    -v "${SCRIPT_DIR}:/src" \
    -w /src \
    rufus-test-env \
    bash -c "
      set -euo pipefail
      ./configure --with-os=linux
      find . -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'configure' | xargs touch
      rm -f src/bled/libbled.a src/ext2fs/libext2fs.a tests/test_loopback_linux
      make -j\$(nproc) -C src/bled
      make -j\$(nproc) -C src/ext2fs
      make -C tests test_loopback_linux
      make -C tests run-root
    "
fi

# ---------------------------------------------------------------------------
# --full-container: build + run the complete test suite inside a privileged
# container.  Runs Linux tests, ASAN+UBSan, cppcheck, and root tests.
# Requires tests/Dockerfile with all deps from tests/install-deps.sh.
# ---------------------------------------------------------------------------
if [ "${RUN_FULL_CONTAINER}" -eq 1 ]; then
  _detect_container_runtime
  info "Building container image rufus-test-env (cached after first run) ..."
  "${CONTAINER_BUILD_CMD[@]}" build -t rufus-test-env "${SCRIPT_DIR}/tests"
  [ "${CONTAINER_ROOTLESS}" -eq 1 ] && _sync_image_to_root
  info "Running full test suite in privileged ${CONTAINER_RUNTIME} container ..."
  exec "${CONTAINER_RUN_CMD[@]}" run --rm --privileged \
    -v "${SCRIPT_DIR}:/src" \
    -w /src \
    rufus-test-env \
    bash -c "
      set -euo pipefail

      echo '--- Configure ---'
      ./configure --with-os=linux
      find . -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'configure' | xargs touch

      echo '--- Build ---'
      make clean
      make -j\$(nproc)

      echo '--- Build sub-libraries ---'
      make -j\$(nproc) -C src/bled
      make -j\$(nproc) -C src/ext2fs

      echo '--- Linux tests ---'
      make -j\$(nproc) -C tests linux
      make -C tests run-linux

      echo '--- ASAN + UBSan tests ---'
      make -j\$(nproc) -C tests check-asan

      echo '--- cppcheck static analysis ---'
      make -C tests check-cppcheck || echo 'cppcheck: warnings found (non-fatal)'

      echo '--- Root-requiring tests ---'
      rm -f tests/test_loopback_linux
      make -C tests test_loopback_linux
      make -C tests run-root

      echo '--- All tests complete ---'
    "
fi

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

if [ "${RUN_ROOT}" -eq 1 ]; then
  info "Building root-requiring tests ..."
  command -v "${CC}" >/dev/null 2>&1 || die "C compiler not found: ${CC}"
  make "${MAKE_ARGS[@]}" linux

  info "Running root-requiring tests ..."
  make "${MAKE_ARGS[@]}" run-root || overall_failed=$((overall_failed + 1))
fi

echo ""
if [ "${overall_failed}" -eq 0 ]; then
  echo "All tests passed."
else
  echo "${overall_failed} test target(s) FAILED."
  exit 1
fi
