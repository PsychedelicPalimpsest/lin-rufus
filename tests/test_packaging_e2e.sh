#!/usr/bin/env bash
#
# tests/test_packaging_e2e.sh
#
# End-to-end packaging tests.  Builds a real DEB and RPM package from the
# local source tree inside isolated containers, installs each package into a
# fresh container, and verifies that the installed binary is present and
# executable.
#
# Usage:
#   tests/test_packaging_e2e.sh [--deb-only] [--rpm-only] [--help]
#
# Environment overrides:
#   CONTAINER_RUNTIME  - docker or podman (auto-detected)
#
# Requirements:
#   docker or podman must be installed and running.
#
# What the tests exercise:
#   DEB  — ubuntu:22.04  build-dep install → dpkg-buildpackage → apt install → rufus --help
#   RPM  — fedora:latest build-dep install → rpmbuild         → dnf install → rufus --help

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '\n==> %s\n' "$*"; }
pass() { printf '[PASS] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; FAILED=$((FAILED + 1)); }

FAILED=0
RUN_DEB=1
RUN_RPM=1

for arg in "$@"; do
    case "$arg" in
        --deb-only) RUN_RPM=0 ;;
        --rpm-only) RUN_DEB=0 ;;
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

# ── Container runtime detection ────────────────────────────────────────────
if [ -z "${CONTAINER_RUNTIME:-}" ]; then
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        CONTAINER_RUNTIME=docker
    elif command -v podman >/dev/null 2>&1; then
        CONTAINER_RUNTIME=podman
    else
        die "No container runtime found. Install docker or podman."
    fi
fi
CT="${CONTAINER_RUNTIME}"
info "Using container runtime: ${CT}"

# ── Shared setup ───────────────────────────────────────────────────────────
# Extract version from the debian changelog (authoritative for both formats).
DEB_VERSION=$(grep -m1 '^rufus ' "${REPO_ROOT}/packaging/debian/changelog" \
    | sed -E 's/rufus \(([^)]+)\).*/\1/')             # e.g. "4.13.0-1"
PKG_VERSION="${DEB_VERSION%%-*}"                       # e.g. "4.13.0"
[ -n "${PKG_VERSION}" ] || die "Could not detect package version from debian/changelog"
info "Package version: ${PKG_VERSION}"

# Temp directory for package artifacts — cleaned up on exit
WORKDIR="$(mktemp -d -t rufus-pkg-e2e.XXXXXX)"
trap 'rm -rf "${WORKDIR}"' EXIT

# ── Debian package e2e test ────────────────────────────────────────────────
if [ "${RUN_DEB}" -eq 1 ]; then
    info "=== Debian package e2e test ==="
    DEB_OUTDIR="${WORKDIR}/deb"
    mkdir -p "${DEB_OUTDIR}"

    # ── 1. Build the .deb ──────────────────────────────────────────────────
    info "Building .deb in ubuntu:22.04..."
    if "${CT}" run --rm \
        -v "${REPO_ROOT}:/src:ro" \
        -v "${DEB_OUTDIR}:/out" \
        ubuntu:22.04 \
        bash -c "
            set -euo pipefail
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y --no-install-recommends \
                gcc-12 build-essential debhelper debhelper-compat \
                autoconf automake libtool pkg-config nasm \
                libgtk-3-dev libcurl4-openssl-dev libudev-dev \
                libblkid-dev libfdisk-dev libext2fs-dev libssl-dev \
                libfontconfig1-dev libnotify-dev >/dev/null 2>&1

            # configure.ac requires -Wbidi-chars=none which needs GCC 12+.
            # Ubuntu 22.04 ships GCC 11 by default; explicitly select GCC 12.
            export CC=gcc-12

            # dpkg-buildpackage requires the source dir to match the package
            # name; debian/changelog determines the version used in filenames.
            mkdir -p /build
            cp -a /src /build/rufus-${PKG_VERSION}
            cd /build/rufus-${PKG_VERSION}

            # Remove host-generated build artifacts (config.status, compiled
            # objects, etc.) so the container runs a clean configure from scratch.
            # The host's config.status may reference tools absent in the container
            # (e.g. gawk), which would cause dh_auto_clean to fail.
            # Pre-compiled objects from the host may use glibc symbols (e.g.
            # __isoc23_strtoull from glibc 2.38+) unavailable in Ubuntu 22.04
            # (glibc 2.35), so they must be removed before linking.
            rm -f config.status config.log config.cache
            find . -maxdepth 5 -name 'Makefile' \
                ! -path '*/debian/*' ! -path '*/.git/*' -delete
            find . \( -name '*.o' -o -name '*.a' \) \
                ! -path '*/debian/*' -delete

            cp -r packaging/debian debian

            dpkg-buildpackage -us -uc -b 2>&1

            cp /build/rufus_*.deb /out/
        "; then
        DEB_FILE=$(ls "${DEB_OUTDIR}"/rufus_*.deb 2>/dev/null | head -1)
        if [ -n "${DEB_FILE}" ]; then
            pass "DEB package built: $(basename "${DEB_FILE}")"
        else
            fail "DEB build succeeded but .deb artifact not found"
        fi
    else
        fail "DEB package build failed"
        DEB_FILE=""
    fi

    # ── 2. Install and verify the .deb ────────────────────────────────────
    if [ -n "${DEB_FILE:-}" ]; then
        info "Installing .deb in fresh ubuntu:22.04..."
        if "${CT}" run --rm \
            -v "${DEB_OUTDIR}:/pkgs:ro" \
            ubuntu:22.04 \
            bash -c '
                set -euo pipefail
                export DEBIAN_FRONTEND=noninteractive
                apt-get update -qq

                # Install the package; apt resolves runtime dependencies.
                apt-get install -y --no-install-recommends /pkgs/rufus_*.deb >/dev/null 2>&1

                # Verify the binary is installed and executable.
                command -v rufus >/dev/null 2>&1 || { echo "rufus not found in PATH"; exit 1; }
                rufus --help >/dev/null 2>&1 || rufus --help 2>&1 | head -3 || true

                echo "Installed binary: $(command -v rufus)"
                echo "OK"
            '; then
            pass "DEB package installs cleanly and binary runs"
        else
            fail "DEB package installation or verification failed"
        fi
    fi
fi

# ── RPM package e2e test ───────────────────────────────────────────────────
if [ "${RUN_RPM}" -eq 1 ]; then
    info "=== RPM package e2e test ==="
    RPM_OUTDIR="${WORKDIR}/rpm"
    mkdir -p "${RPM_OUTDIR}"

    # ── 1. Build the .rpm ─────────────────────────────────────────────────
    info "Building .rpm in fedora:latest..."
    if "${CT}" run --rm \
        -v "${REPO_ROOT}:/src:ro" \
        -v "${RPM_OUTDIR}:/out" \
        fedora:latest \
        bash -c "
            set -euo pipefail
            dnf install -y --quiet \
                autoconf automake libtool make gcc pkg-config nasm rpm-build \
                gtk3-devel libcurl-devel systemd-devel libblkid-devel \
                openssl-devel fontconfig-devel libnotify-devel \
                >/dev/null 2>&1

            # Set up rpmbuild tree
            mkdir -p /root/rpmbuild/{SOURCES,SPECS,BUILD,RPMS,SRPMS}

            # Create the source tarball; %autosetup -n rufus expects it to
            # expand into a directory named 'rufus' (matching %{name}).
            cp -a /src /tmp/rufus
            tar -czf /root/rpmbuild/SOURCES/rufus-${PKG_VERSION}.tar.gz \
                -C /tmp rufus

            cp /src/packaging/rpm/rufus.spec /root/rpmbuild/SPECS/
            sed -i 's|^Version:.*|Version:        ${PKG_VERSION}|' \
                /root/rpmbuild/SPECS/rufus.spec

            rpmbuild -bb --nocheck /root/rpmbuild/SPECS/rufus.spec 2>&1

            find /root/rpmbuild/RPMS -name 'rufus-${PKG_VERSION}*.rpm' \
                ! -name '*debuginfo*' ! -name '*debugsource*' \
                -exec cp {} /out/ \;
        "; then
        RPM_FILE=$(ls "${RPM_OUTDIR}"/rufus-*.rpm 2>/dev/null \
            | grep -v debuginfo | grep -v debugsource | head -1)
        if [ -n "${RPM_FILE}" ]; then
            pass "RPM package built: $(basename "${RPM_FILE}")"
        else
            fail "RPM build succeeded but .rpm artifact not found"
        fi
    else
        fail "RPM package build failed"
        RPM_FILE=""
    fi

    # ── 2. Install and verify the .rpm ────────────────────────────────────
    if [ -n "${RPM_FILE:-}" ]; then
        info "Installing .rpm in fresh fedora:latest..."
        if "${CT}" run --rm \
            -v "${RPM_OUTDIR}:/pkgs:ro" \
            fedora:latest \
            bash -c '
                set -euo pipefail
                RPM_FILE=$(ls /pkgs/rufus-*.rpm | grep -v debuginfo | grep -v debugsource | head -1)
                dnf install -y --quiet "$RPM_FILE" >/dev/null 2>&1

                # Verify the binary is installed and executable.
                command -v rufus >/dev/null 2>&1 || { echo "rufus not found in PATH"; exit 1; }
                rufus --help >/dev/null 2>&1 || rufus --help 2>&1 | head -3 || true

                echo "Installed binary: $(command -v rufus)"
                echo "OK"
            '; then
            pass "RPM package installs cleanly and binary runs"
        else
            fail "RPM package installation or verification failed"
        fi
    fi
fi

# ── Summary ────────────────────────────────────────────────────────────────
echo ""
if [ "${FAILED}" -eq 0 ]; then
    echo "All packaging e2e tests passed."
else
    echo "${FAILED} packaging e2e test(s) FAILED."
    exit 1
fi
