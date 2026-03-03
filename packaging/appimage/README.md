# Rufus AppImage Packaging

This directory contains the build script for producing a self-contained
`Rufus-<VERSION>-x86_64.AppImage`.

## Requirements

- A built Rufus binary (run `./configure --with-os=linux && make` first)
- `curl` (to fetch linuxdeploy on first run)
- `libfuse2` (for running the resulting AppImage)

## Building

```bash
# From the repo root
make appimage

# Or directly:
packaging/appimage/build-appimage.sh
```

The script:
1. Downloads `linuxdeploy-x86_64.AppImage` and `linuxdeploy-plugin-gtk.sh`
   into `packaging/appimage/.tools/` on the first run (cached for subsequent runs).
2. Creates a temporary AppDir with the binary, desktop file, AppStream metainfo,
   icons (256/128/48/32 px), locale data, and man page.
3. Calls `linuxdeploy --plugin gtk` to bundle GTK 3 and all shared-library
   dependencies.
4. Outputs `Rufus-<VERSION>-x86_64.AppImage` in the current working directory.

## Running

```bash
chmod +x Rufus-4.13-x86_64.AppImage
sudo ./Rufus-4.13-x86_64.AppImage          # root required for block-device access
```

On systems without FUSE 2 installed:
```bash
./Rufus-4.13-x86_64.AppImage --appimage-extract-and-run
```

## Permissions

The AppImage runs as a normal ELF executable; root access (or polkit) is
required for the actual USB formatting operations just as with the installed
binary.
