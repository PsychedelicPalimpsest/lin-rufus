#!/usr/bin/env bash
# build-appimage.sh — Build a Rufus AppImage using linuxdeploy + linuxdeploy-plugin-gtk
#
# Usage: packaging/appimage/build-appimage.sh [--prefix PREFIX] [--version VER]
#
# Prerequisites:
#   • The Rufus binary must already be built (./configure --with-os=linux && make)
#   • linuxdeploy and linuxdeploy-plugin-gtk are downloaded automatically if absent.
#
# Output: Rufus-<VERSION>-x86_64.AppImage in the current directory.
#
# References:
#   https://docs.appimage.org/packaging-guide/from-source/linuxdeploy-user-guide.html
#   https://github.com/linuxdeploy/linuxdeploy
#   https://github.com/linuxdeploy/linuxdeploy-plugin-gtk
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── defaults ──────────────────────────────────────────────────────────────────
PREFIX="${1:-/usr}"
VERSION="$(grep 'AC_INIT' "$REPO_ROOT/configure.ac" \
          | sed -E 's/.*\[([0-9]+\.[0-9]+\.[0-9]*)\].*/\1/')"
VERSION="${VERSION:-$(grep 'RUFUS_LINUX_VERSION' "$REPO_ROOT/src/linux/version.h" \
          | awk '/MAJOR/{ma=$NF}/MINOR/{mi=$NF}/PATCH/{pa=$NF} END{print ma"."mi"."pa}')}"
ARCH="${ARCH:-x86_64}"
OUTNAME="Rufus-${VERSION}-${ARCH}.AppImage"

echo "Building Rufus ${VERSION} AppImage (arch=${ARCH})..."

# ── locate the Rufus binary ───────────────────────────────────────────────────
RUFUS_BIN=""
for candidate in \
    "$REPO_ROOT/src/rufus" \
    "$REPO_ROOT/rufus" \
    "$(command -v rufus 2>/dev/null || true)"; do
    if [ -x "$candidate" ]; then
        RUFUS_BIN="$candidate"
        break
    fi
done

if [ -z "$RUFUS_BIN" ]; then
    echo "ERROR: Rufus binary not found. Run 'make' first." >&2
    exit 1
fi
echo "  Binary: $RUFUS_BIN"

# ── download helpers ──────────────────────────────────────────────────────────
TOOLS_DIR="$REPO_ROOT/packaging/appimage/.tools"
mkdir -p "$TOOLS_DIR"

fetch_tool() {
    local url="$1"
    local dst="$2"
    if [ ! -x "$dst" ]; then
        echo "  Downloading $(basename "$dst")..."
        curl -fsSL "$url" -o "$dst"
        chmod +x "$dst"
    fi
}

# linuxdeploy
fetch_tool \
    "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage" \
    "$TOOLS_DIR/linuxdeploy-x86_64.AppImage"

# linuxdeploy-plugin-gtk
fetch_tool \
    "https://raw.githubusercontent.com/linuxdeploy/linuxdeploy-plugin-gtk/master/linuxdeploy-plugin-gtk.sh" \
    "$TOOLS_DIR/linuxdeploy-plugin-gtk.sh"

# Export plugin location for linuxdeploy
export PATH="$TOOLS_DIR:$PATH"

# ── create AppDir skeleton ────────────────────────────────────────────────────
APPDIR="$(mktemp -d -t rufus-appdir.XXXXXX)"
trap 'rm -rf "$APPDIR"' EXIT

mkdir -p \
    "$APPDIR/usr/bin" \
    "$APPDIR/usr/share/applications" \
    "$APPDIR/usr/share/metainfo" \
    "$APPDIR/usr/share/rufus" \
    "$APPDIR/usr/share/man/man1" \
    "$APPDIR/usr/share/icons/hicolor/256x256/apps" \
    "$APPDIR/usr/share/icons/hicolor/128x128/apps" \
    "$APPDIR/usr/share/icons/hicolor/48x48/apps" \
    "$APPDIR/usr/share/icons/hicolor/32x32/apps"

# Binary
cp "$RUFUS_BIN" "$APPDIR/usr/bin/rufus"
chmod 755 "$APPDIR/usr/bin/rufus"

# Desktop file
if [ -f "$REPO_ROOT/res/ie.akeo.rufus.desktop" ]; then
    cp "$REPO_ROOT/res/ie.akeo.rufus.desktop" "$APPDIR/usr/share/applications/ie.akeo.rufus.desktop"
fi

# AppStream metainfo
if [ -f "$REPO_ROOT/res/ie.akeo.rufus.appdata.xml" ]; then
    cp "$REPO_ROOT/res/ie.akeo.rufus.appdata.xml" "$APPDIR/usr/share/metainfo/ie.akeo.rufus.appdata.xml"
fi

# Icons
for sz in 256 128 48 32; do
    ico="$REPO_ROOT/res/icons/rufus_${sz}px.png"
    if [ -f "$ico" ]; then
        cp "$ico" "$APPDIR/usr/share/icons/hicolor/${sz}x${sz}/apps/ie.akeo.rufus.png"
    fi
done

# Embedded locale data
if [ -f "$REPO_ROOT/res/loc/embedded.loc" ]; then
    cp "$REPO_ROOT/res/loc/embedded.loc" "$APPDIR/usr/share/rufus/"
fi

# Man page
if [ -f "$REPO_ROOT/doc/rufus.1" ]; then
    cp "$REPO_ROOT/doc/rufus.1" "$APPDIR/usr/share/man/man1/"
    gzip -f "$APPDIR/usr/share/man/man1/rufus.1" || true
fi

# ── run linuxdeploy ───────────────────────────────────────────────────────────
# Disable FUSE — AppImages may be extracted rather than run with FUSE in CI.
APPIMAGE_EXTRACT_AND_RUN=1 \
DEPLOY_GTK_VERSION=3 \
OUTPUT="$OUTNAME" \
"$TOOLS_DIR/linuxdeploy-x86_64.AppImage" \
    --appdir "$APPDIR" \
    --executable "$APPDIR/usr/bin/rufus" \
    --desktop-file "$APPDIR/usr/share/applications/ie.akeo.rufus.desktop" \
    --plugin gtk \
    --output appimage

echo ""
echo "AppImage built: $(pwd)/$OUTNAME"
echo "Size: $(du -h "$OUTNAME" | cut -f1)"
