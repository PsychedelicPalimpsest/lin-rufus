# Rufus Linux Port — Architecture Overview

This document describes the layered architecture of the Rufus Linux port,
the source layout, and the data flow from user action to device write.

---

## Layer diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    User Interface Layer                         │
│   src/linux/ui_gtk.c  ·  src/linux/ui_combo_logic.c           │
│   src/linux/stdlg.c   ·  src/linux/combo_bridge.c             │
│   src/linux/cli.c     (non-GTK / headless)                     │
└─────────────────────────┬───────────────────────────────────────┘
                          │  PostMessage / SendMessage (msg_dispatch)
                          │  g_idle_add for GTK thread safety
┌─────────────────────────▼───────────────────────────────────────┐
│                  Core Business Logic                            │
│   src/linux/format.c    · FormatThread                         │
│   src/linux/iso.c       · ExtractISO, DumpFatDir               │
│   src/linux/image_scan.c· ImageScanThread                      │
│   src/linux/hash.c      · HashThread, Secure Boot checks       │
│   src/linux/net.c       · DownloadToFileOrBufferEx (libcurl)   │
│   src/linux/vhd.c       · VhdMountImageAndGetSize (qemu-nbd)   │
│   src/linux/wue.c       · CreateUnattendXml, SetupWinToGo      │
└─────────────────────────┬───────────────────────────────────────┘
                          │  calls
┌─────────────────────────▼───────────────────────────────────────┐
│               Portable Common Logic (src/common/)               │
│   stdfn.c       · htab, StrArray, CompareGUID                  │
│   stdio.c       · TimestampToHumanReadable, GuidToString        │
│   drive.c       · GetMBRPartitionType, GetGPTPartitionType      │
│   format_fat32.c· fat32_default_cluster_size                   │
│   format_ext.c  · error_message, GetExtFsLabel                 │
│   bootloader_scan.c · GetBootladerInfo                         │
│   iso_scan.c    · GetGrubVersion, GetGrubFs, GetEfiBootInfo    │
│   iso_config.c  · iso_patch_config_file                        │
│   iso_check.c   · check_iso_props                              │
│   iso_report.c  · log_iso_report                               │
│   hash_pe.c     · PE256Buffer, efi_image_parse                 │
│   hash_db.c     · IsFileInDB, IsBufferInDB                     │
│   localization.c· lmprintf, get_locale_from_*                  │
│   parser.c      · token CRUD, GetSbatEntries, PE parsing       │
└─────────────────────────┬───────────────────────────────────────┘
                          │  via compat headers
┌─────────────────────────▼───────────────────────────────────────┐
│            Windows API Compat Layer (src/linux/compat/)         │
│   windows.h     · BOOL, DWORD, HANDLE, CreateThread, …        │
│   shlwapi.h     · PathFileExistsA, PathCombineA, StrStrIA      │
│   shellapi.h    · ShellExecuteA → xdg-open                     │
│   commctrl.h    · CB_ADDSTRING, CB_GETCURSEL (combo_bridge)    │
│   winioctl.h    · IOCTL_* constants, ioctls                    │
│   wincrypt.h    · OpenSSL typedef shims                        │
│   …                                                             │
└─────────────────────────┬───────────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────────┐
│               Linux OS / System Libraries                       │
│   libudev  · device enumeration, hot-plug                      │
│   libblkid · partition/filesystem probing                      │
│   libfdisk  · partition table creation (MBR, GPT)              │
│   libcurl  · HTTP downloads                                    │
│   libext2fs · ext2/3/4 formatting (bundled)                    │
│   libcdio  · ISO9660 / UDF reading (bundled)                   │
│   wimlib   · WIM image handling (bundled)                      │
│   bled     · compression (bundled)                             │
│   OpenSSL  · SHA, RSA, PKCS7, certificate parsing              │
│   fontconfig· font availability checks                         │
│   GTK3     · graphical user interface                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Source file index

### `src/common/` — portable logic

| File | Purpose |
|------|---------|
| `stdfn.c` | Hash table (`htab`), string arrays (`StrArray`), GUID helpers |
| `stdio.c` | `TimestampToHumanReadable`, `GuidToString` |
| `drive.c` | `GetMBRPartitionType`, `GetGPTPartitionType`, partition type tables |
| `format_fat32.c` | `fat32_default_cluster_size` lookup table |
| `format_ext.c` | `error_message`, `ext2fs_print_progress`, `GetExtFsLabel` |
| `bootloader_scan.c` | `GetBootladerInfo` — detects bootloader type from ISO scan results |
| `iso_scan.c` | `GetGrubVersion`, `GetGrubFs`, `GetEfiBootInfo` — buffer scanners |
| `iso_config.c` | `iso_patch_config_file` — Syslinux/GRUB config patching |
| `iso_check.c` | `check_iso_props` — per-file property detection during ISO scan |
| `iso_report.c` | `log_iso_report` — structured log output of ISO properties |
| `hash_pe.c` | `PE256Buffer`, `efi_image_parse`, PE region helpers |
| `hash_db.c` | `IsFileInDB`, `IsBufferInDB`, `StringToHash`, `FileMatchesHash` |
| `hash_algos.c` | MD5, SHA-1, SHA-256, SHA-512 pure-C implementations |
| `localization.c` | `lmprintf`, `dispatch_loc_cmd`, locale lookup |
| `parser.c` | Token CRUD, `GetSbatEntries`, `GetThumbprintEntries`, PE parsing |
| `cregex_*.c` | Minimal regex engine (compile, parse, VM) |
| `xml.c` | Lightweight ezxml wrapper |

### `src/linux/` — Linux implementations

| File | Purpose |
|------|---------|
| `rufus.c` | `main()` for the non-GTK / CLI build |
| `ui_gtk.c` | GTK window, all signal handlers, `g_idle_add` bridges |
| `ui_combo_logic.c` | Combo-box selection logic (FS, partition, target) |
| `combo_bridge.c` | `CB_*` message dispatch → GTK `GtkComboBoxText` |
| `cli.c` | Non-GTK argument parsing and format harness |
| `dev.c` | `GetDevices()` via sysfs; `CycleDevice`, `GetDriveLabel`, … |
| `drive.c` | `MountVolume`, `CreatePartition`, `InitializeDisk` (libfdisk) |
| `format.c` | `FormatThread`, `FormatPartition`, UEFI:NTFS partition |
| `format_fat32.c` | `FormatLargeFAT32` — direct cluster-level FAT32 writer |
| `format_ext.c` | `FormatExtFs` — ext2/3/4 via bundled `ext2fs` |
| `format_ext_tools.c` | `format_ntfs_build_cmd`, `format_exfat_build_cmd` (mkntfs/mkfs.exfat) |
| `iso.c` | `ExtractISO`, `DumpFatDir`, `ReadISOFileToBuffer` (libcdio) |
| `image_scan.c` | `ImageScanThread` — posts `UM_IMAGE_SCANNED` |
| `hash.c` | `HashFile`, `HashThread`, `IsSignedBySecureBootAuthority`, `IsBootloaderRevoked` |
| `net.c` | `DownloadToFileOrBufferEx` (libcurl), `CheckForUpdates`, `DownloadISO` |
| `pki.c` | `ValidateOpensslSignature`, PE parsing for cert info |
| `stdfn.c` | `GetResource`, `GetExecutableVersion`, `SetThreadAffinity` |
| `stdio.c` | `uprintf`, `WindowsErrorString`, `RunCommandWithProgress` |
| `stdlg.c` | `FileDialog` (GTK native), `NotificationEx`, `CustomSelectionDialog`, `ListDialog` |
| `dos.c` | `ExtractFreeDOS`, `ExtractDOS` |
| `dos_locale.c` | `SetDOSLocale` |
| `syslinux.c` | `InstallSyslinux` (mcopy + libfat) |
| `process.c` | `GetPPID`, `StartProcessSearch` via `/proc` |
| `badblocks.c` | `BadBlocks` via `pread`/`pwrite` |
| `smart.c` | `ScsiPassthroughDirect` via `SG_IO` ioctl |
| `hash.c` | OpenSSL-based secure boot checks |
| `vhd.c` | `VhdMountImageAndGetSize` via qemu-nbd |
| `wue.c` | `CreateUnattendXml`, `SetupWinToGo`, `ApplyWindowsCustomization` |
| `xdg.c` | `GetXdgUserDir` — XDG user-dirs.dirs parser |
| `notify.c` | `rufus_notify` — desktop notification (libnotify / notify-send) |
| `polkit.c` | `rufus_try_pkexec` — privilege escalation |
| `crash_handler.c` | `install_crash_handlers` — SIGSEGV/SIGABRT backtrace |
| `device_monitor.c` | udev netlink monitor, hot-plug debounce, `UM_MEDIA_CHANGE` |
| `device_combo.c` | Right-click context menu for device combo |
| `status_history.c` | Ring buffer of recent status messages (tooltip) |
| `system_info.c` | `GetTPMVersion`, `IsSecureBootEnabled` via sysfs |
| `timezone.c` | `IanaToWindowsTimezone` — IANA → Windows timezone name |
| `img_info.c` | `format_img_info` — image info panel formatter |
| `download_resume.c` | Partial-download state management |
| `csm_help.c` | CSM/UEFI help indicator logic |
| `hyperlink.c` | Pango markup hyperlink builder |
| `localization.c` | Linux-specific locale helpers |
| `parser.c` | Linux-specific token data file helpers |
| `window_text_bridge.c` | Thread-safe `GetWindowTextA`/`SetWindowTextA` registry |
| `settings.h` | `ReadSetting*`/`WriteSetting*` → `~/.config/rufus/rufus.ini` |
| `globals.c` | Definitions of shared globals (`fs_type`, `boot_type`, …) |
| `freedos_data.c` | FreeDOS boot files embedded as `const uint8_t[]` arrays |

### `src/linux/compat/` — Windows API shims (header-only)

| Header | Windows API surface |
|--------|-------------------|
| `windows.h` | Core types, `CreateThread`, `WaitForSingleObject`, `PostMessage`, … |
| `shlwapi.h` | `PathFileExistsA`, `PathCombineA`, `StrStrIA`, `StrCmpIA` |
| `shellapi.h` | `ShellExecuteA` → `xdg-open` |
| `commctrl.h` | `CB_*` constants, list-view stubs |
| `winioctl.h` | `IOCTL_STORAGE_*`, `IOCTL_DISK_*` constants |
| `setupapi.h` | Compilation stub (not called on Linux) |
| `wincrypt.h` | OpenSSL typedef shims |
| `wintrust.h` | Compilation stub |
| `shlobj.h` | Compilation stub |
| `cfgmgr32.h` | Compilation stub |
| `dbt.h` | `UM_MEDIA_CHANGE` replaces `WM_DEVICECHANGE` |
| `psapi.h` | Compilation stub |
| `msg_dispatch.c/.h` | `PostMessage`/`SendMessage` bridge (pthread condvar + g_idle_add) |

---

## Threading model

All long-running operations run in worker threads created via
`CreateThread` (which wraps `pthread_create` on Linux).  The UI thread
(GTK main loop) never blocks.

```
GTK main thread
  └── on_start_clicked()
        └── CreateThread(FormatThread, ...)
              │
              │  uprintf()        → g_idle_add(idle_append_log, ...)   → GTK
              │  UpdateProgress() → g_idle_add(idle_update_progress, ...)→ GTK
              │  PostMessage()    → g_idle_add(dispatch_msg_idle, ...) → GTK
              │
              └── FormatThread completes
                    └── PostMessage(hMainDialog, UM_FORMAT_COMPLETED, ...)
                          └── main_dialog_handler() on GTK thread
```

`SendMessage` blocks the calling thread until the GTK thread has processed
the message (implemented with a `pthread_cond_wait` / `pthread_cond_signal`
pair in `msg_dispatch.c`).

`PostMessage` is fire-and-forget: the message is queued via `g_idle_add`
and processed on the next GTK main-loop iteration.

---

## Message constants

Custom window messages use the `UM_*` prefix (user messages, analogous to
`WM_USER + N` on Windows):

| Constant | Purpose |
|----------|---------|
| `UM_FORMAT_COMPLETED` | FormatThread finished |
| `UM_IMAGE_SCANNED` | ImageScanThread finished |
| `UM_MEDIA_CHANGE` | Hot-plug event from device_monitor |
| `UM_NEW_VERSION` | New Rufus version available |
| `UM_HASH_COMPLETED` | HashThread finished |
| `UM_ENABLE_DOWNLOAD_ISO` | Fido check succeeded; show Download ISO button |
| `UM_DOWNLOAD_PROGRESS` | Progress update from download thread |

---

## Settings

User preferences are stored in `~/.config/rufus/rufus.ini` (respects
`XDG_CONFIG_HOME`).  The `src/linux/settings.h` header provides:

```c
ReadSettingStr(key, default)   → char*
ReadSetting32(key)             → DWORD
ReadSetting64(key)             → uint64_t
ReadSettingBool(key)           → BOOL
WriteSettingStr(key, value)
WriteSetting32(key, value)
WriteSetting64(key, value)
WriteSettingBool(key, value)
```

These macros expand to `ReadIniKey*` / `WriteIniKey*` calls that operate
on the INI file via `get_token_data_file` / `set_token_data_file` from
`src/linux/parser.c`.

---

## Resource loading

On Windows, binary resources (syslinux files, UEFI:NTFS image, FreeDOS
boot files, etc.) are embedded in the PE executable as RT_RCDATA resources
and accessed via `FindResource` / `LoadResource`.

On Linux:

| Resource | How loaded |
|----------|-----------|
| FreeDOS files (IDR_FD_*) | Embedded `const uint8_t[]` in `src/linux/freedos_data.c`; accessed via `GetResource()` |
| Syslinux ldlinux.sys/bss | Loaded from `res/syslinux/ldlinux_v{4,6}.{sys,bss}` on disk |
| UEFI:NTFS image | Loaded from `res/uefi/uefi-ntfs.img` on disk via `load_uefi_ntfs_data()` |
| GRUB core.img | Loaded from `res/grub2/core.img` on disk |
| Embedded locale | Loaded from `res/loc/embedded.loc` on disk |

The `RUFUS_DATADIR` environment variable overrides the data directory
search path (default: `$(prefix)/share/rufus`).

---

## Build system

The project uses Autotools.  The OS target is selected at configure time:

```sh
./configure --with-os=linux    # Linux build (default on Linux hosts)
./configure --with-os=windows  # MinGW cross-compile
```

Key `Makefile.am` variables:

| Variable | Purpose |
|----------|---------|
| `AM_CFLAGS` | Common compiler flags + pkg-config output |
| `TARGET_LINUX` | Automake conditional; set when `--with-os=linux` |
| `rufus_SOURCES` | Source files for the `rufus` binary |

Bundled libraries (ext2fs, libcdio, wimlib, bled, ms-sys, syslinux) are
built as static archives and linked into the final binary.

---

## Test system

Tests live in `tests/` and are discovered automatically by `tests/Makefile`
via `$(wildcard test_*.c)`.  Each test file produces:

- `test_<name>_linux` — native Linux binary
- `test_<name>_linux_asan` — AddressSanitizer build
- `test_<name>.exe` — Windows binary (MinGW, unless in `WIN_EXCLUDE_SRCS`)

See `CONTRIBUTING.md` for test writing conventions.

---

## Relationship to upstream Rufus

This repository is a fork of [pbatard/rufus](https://github.com/pbatard/rufus).
The Windows source files in `src/windows/` and `src/windows/` are kept
close to upstream.  The Linux port adds:

- `src/linux/` — Linux implementations of all platform-specific functions
- `src/linux/compat/` — Windows API compat headers
- `src/common/` — portable logic extracted from both platforms
- `tests/` — test suite
- `doc/` — documentation
- `packaging/` — distribution packaging files

Changes to `src/common/` are designed to be back-portable to Windows.
Changes to `src/windows/` are kept minimal to reduce merge conflicts with
upstream.
