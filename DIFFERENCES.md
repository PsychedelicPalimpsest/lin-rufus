# Rufus Linux Port — Differences from Upstream (Windows)

This document describes the differences between the Linux port and the original
Windows version of Rufus. The goal of this port is feature parity; most core
functionality is implemented. Some Windows-specific features are permanently N/A
on Linux.

**Linux port by:** PsychedelicPalimpsest  
**Original Rufus by:** Pete Batard (https://rufus.ie)

---

## UI Framework

| Aspect | Windows | Linux |
|--------|---------|-------|
| UI toolkit | Win32/MFC resource dialogs | GTK3 |
| Window management | Windows HWND/DIALOG | GtkWindow |
| Toolbar | ToolbarWindow32 | GTK toolbar buttons |
| Device detection | `WM_DEVICECHANGE` + polling timer | libudev netlink (real-time) |
| Elapsed time display | Status bar right section | Right-aligned label in status row |
| Dark mode | Windows DWM | GTK `gtk-application-prefer-dark-theme` |

---

## Features Implemented on Linux

- **Full format support**: FAT12/16/32, exFAT, NTFS, UDF, ext2/3/4
- **Bootable ISO writing**: ISO9660, UDF, ISOHybrid, DD-mode
- **Persistence partition**: Casper/overlay for Ubuntu/Kali/Tails etc.
- **Windows installer images**: Standard + Windows To Go (WTG)
- **Windows Unattended Experience (WUE)**: TPM bypass, account bypass, locale,
  data collection settings, MS2023 bootloaders, Force S-mode
- **GPT + UEFI:NTFS bridge**: EFI System Partition written with 1 MiB NTFS stub
- **MBR + BIOS compatibility**: Rufus MBR, GRUB4DOS secondary boot sectors,
  BIOS compatibility (`XP_COMPAT`) placeholder partition
- **GRUB2**: via system `grub-install` (rather than downloaded `core.img`)
- **Syslinux/Isolinux**: via bundled libinstaller; version auto-detected from ISO
- **FreeDOS**: extracted from embedded resources
- **KolibriOS**: USB loader installation
- **VHD/VHDX DD write**: via `qemu-nbd`
- **Hash verification**: MD5/SHA-1/SHA-256/SHA-512 with dialog
- **Write-and-verify pass**: re-reads and compares written data
- **Signature verification**: RSA-SHA256 via OpenSSL for downloaded files
- **Fido/download integration**: ISO download via libcurl
- **Update checking**: version check + new-version dialog
- **Localization**: same `.loc` file as Windows; language menu works
- **Settings persistence**: same INI format via `WritePrivateProfileString`
- **Keyboard shortcuts**: full Alt+key cheat-mode parity
- **Log dialog**: scrollable log window
- **About dialog**: GTK about dialog

---

## Behavioral Differences

### Device Refresh
- **Windows**: polls every 1 s via `RefreshTimer`
- **Linux**: event-driven via libudev netlink (`device_monitor.c`) — more
  responsive and CPU-friendly

### GRUB2 Core Image
- **Windows**: downloads a matching `core.img` from `files.rufus.ie` when the
  ISO's GRUB2 version differs from the embedded version
- **Linux**: calls `grub-install` which generates the correct `core.img`
  automatically — no download required

### Syslinux Component Download
- **Windows**: offers to download old `.c32` replacement files for Syslinux < v5
- **Linux**: uses the embedded Syslinux from `libinstaller`; old `.c32` download
  is not implemented (rarely needed in practice)

### Process-Holds-Drive Check (`GetProcessSearch`)
- **Windows**: enumerates open file handles to warn if another process has the
  target drive open
- **Linux**: not implemented — the format thread handles unmounting via
  `umount`/`fuser`, which is equivalent in practice

### Extended Label (`IDC_EXTENDED_LABEL`)
- **Windows**: checkbox to toggle `autorun.inf` creation
- **Linux**: stub (`SetAutorun` returns FALSE) — no `autorun.inf` is created
  (irrelevant on Linux since autorun is a Windows concept)

### Autorun / Icon
- **Windows**: creates `autorun.inf` + embeds Rufus icon in drive root
- **Linux**: not applicable

### WDAC Policy (`CopySKUSiPolicy`)
- **Windows**: copies Windows Defender Application Control policy
- **Linux**: no-op stub — WDAC is a Windows-only feature

### Bad Blocks Check
- **Windows**: custom bad-blocks scan with multiple passes
- **Linux**: implemented via `badblocks` utility

---

## Not Implemented on Linux (Permanently N/A)

| Feature | Reason |
|---------|--------|
| `WM_DEVICECHANGE` integration | Win32-only; replaced by libudev |
| `SetAlertPromptHook` / format-disk system dialog | Win32 hook API |
| `GetProcessSearch` (open handle scan) | Win32 `NtQuerySystemInformation` |
| `CopySKUSiPolicy` (WDAC) | Windows Defender feature |
| `SetAutorun` / autorun.inf | Not applicable on Linux |
| `IDD_FORMAT` / `IDD_LOG` dialog resources | Win32 DIALOG resources |
| Setup API (`setupapi.h`) | Win32-only device enumeration |
| SBP2 / Thunderbolt quirks | Handled by kernel on Linux |
| `_chdir` / `_mkdir` to Windows-path UAC workarounds | Not needed on Linux |
| Registry key writes (`HKLM`) | Linux uses INI/XDG config |
| COM/WMI interfaces | Win32-only |

---

## Build Notes

- Requires GTK3, libcurl, OpenSSL, libext2fs (e2fsprogs), wimlib, libcdio
- All dependencies listed in `tests/install-deps.sh`
- Build: `./configure && make -C src rufus` (non-GTK CLI mode also available)
- Tests: `./run_tests.sh --linux-only` (all Linux tests, no Wine needed)
- Container tests: `./run_tests.sh --container` (root-required loop device tests)
- CLI mode: `./rufus --device /dev/sdX --image path.iso`
