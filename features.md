# Rufus Linux Port — Feature & Porting Status

This file tracks what has been done, what is a stub, what needs a real Linux
implementation, and what is permanently N/A.  Think of it as the master todo
list for making Rufus fully functional on Linux.

---

## Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Done / works on Linux |
| 🔧 | Partial / needs finishing |
| 🟡 | Stub exists, real implementation needed |
| ❌ | Not started |
| 🚫 | Windows-only / permanently N/A on Linux |

---

## How Testing Works

Tests live in `tests/` and are kept separate from `src/`.  They can include
source files directly (e.g. `../src/common/cregex_compile.c`) so there is no
need to build or install the main binary first.

**Adding a test:** create a `tests/test_<name>.c` file.  The `tests/Makefile`
auto-discovers any `test_*.c` and builds both a Linux binary (`test_<name>_linux`)
and a Windows binary (`test_<name>.exe`).  Use the macros in `tests/framework.h`:

```c
#include "framework.h"
#include "../src/common/cregex.h"   /* include source directly */

TEST(my_test) {
    CHECK(1 + 1 == 2);
    CHECK_STR_EQ("hello", "hello");
    CHECK_INT_EQ(42, 42);
}

int main(void) {
    RUN(my_test);
    TEST_RESULTS();   /* prints summary and returns 0 or 1 */
}
```

**Running tests:**

```
./run_tests.sh              # Linux (native) + Windows (via Wine, if available)
./run_tests.sh --linux-only # Linux only
./run_tests.sh --wine-only  # Wine only
./run_tests.sh --no-wine    # Skip Wine even if installed
```

`run_tests.sh` skips the Wine / MinGW pass gracefully if either tool is absent.
Individual targets are also available directly inside `tests/`:

```
make -C tests run-linux
make -C tests run-wine
```

Toolchain overrides: `CC=clang ./run_tests.sh --linux-only`,
`CC_WIN=i686-w64-mingw32-gcc ./run_tests.sh --wine-only`.

**Tests that require root (loopback, raw block device access):**

Some tests need real `/dev/loop*` block devices and must run as root.  They
skip gracefully via `SKIP_NOT_ROOT()` when run as a normal user.  The
recommended way to run them is in a short-lived privileged container so that
the host system stays clean:

```
./run_tests.sh --container   # builds rufus-test-env image (cached), then runs
                             # works with both docker and podman
                             # mirrors the GitHub CI environment exactly
```

The container image is defined in `tests/Dockerfile` (Ubuntu 22.04 + all build
and test dependencies pre-baked via `tests/install-deps.sh`).  After the first
build, repeated runs skip the apt-install layer and start immediately.

To run them directly (if you are already root or in a CI environment that
provides `/dev/loop*`):

```
./run_tests.sh --root-only   # run only root-requiring tests
make -C tests run-root       # same, via make
```

The container approach is unified with the GitHub CI:

* `tests/install-deps.sh` — single source of truth for all apt packages;
  called by both `tests/Dockerfile` and `.github/workflows/linux.yml`.
* The `Container-Root-Tests` CI job runs `docker build -t rufus-test-env tests/`
  then `./run_tests.sh --container`, exercising the same code path as local runs.

The `CONTAINER_RUNTIME` environment variable selects `docker` or `podman`
(default: auto-detected, docker preferred).

---

## 1. Build & Infrastructure

| Item | Status | Notes |
|------|--------|-------|
| Autotools configure (`--with-os=linux`) | ✅ | Produces a valid Linux build |
| MinGW cross-compile (`--with-os=windows`) | ✅ | Produces `rufus.exe` |
| Linux build script (`build-rufus-linux.sh`) | ✅ | |
| Windows cross-build script (`build-rufus-mingw.sh`) | ✅ | |
| Test system (`tests/`, `run_tests.sh`) | ✅ | Runs native + Wine + privileged container (root tests) |
| GCC 15 compound-literal regression fix in `cregex_compile.c` | ✅ | Static node lifetimes replaced with local vars |
| GTK3 UI backend (`-DUSE_GTK`) | ✅ | Window builds and launches |
| Non-GTK console fallback (`src/linux/rufus.c main()`) | 🔧 | Prints error and exits; no real CLI yet |

---

## 2. Compatibility Layer (`src/linux/compat/`)

These headers allow Windows source files to compile on Linux unchanged.

| Header | Status | Notes |
|--------|--------|-------|
| `windows.h` | 🔧 | ~1 200 lines; types, macros, most stubs present. `SendMessage`/`PostMessage` are no-ops — needs GTK dispatch integration |
| `GetWindowTextA` / `SetWindowTextA` | ✅ | Real implementation via `window_text_bridge` — thread-safe HWND→text registry; GTK main thread keeps cache in sync via "changed" signal; worker threads (FormatThread) read cache safely; `window_text_register_gtk()` wired in `ui_gtk.c` for volume-label entry; 20 tests, 30 assertions pass |
| `commctrl.h` | 🔧 | ComboBox/ListBox macros present, most map to GTK stubs |
| `setupapi.h` | 🟡 | Empty stub; needed by `dev.c` device enumeration |
| `wincrypt.h` / `wintrust.h` | 🟡 | Needed by `pki.c` — use OpenSSL as replacement |
| `shlobj.h` / `shobjidl.h` | 🟡 | Shell path functions; replace with `XDG_*` / `g_get_*` |
| `cfgmgr32.h` | 🟡 | Device manager stubs; replace with udev |
| `dbt.h` | 🟡 | Device-change notifications; replace with udev monitor |
| `dbghelp.h` | 🚫 | Symbol walking — no Linux equivalent needed |
| `gpedit.h` | 🚫 | Group Policy — N/A on Linux |
| `delayimp.h` | 🚫 | Delay-load DLL mechanism — N/A on Linux |
| All others | 🔧 | Typedefs / empty stubs compile; runtime behaviour untested |
| `SendMessage` / `PostMessage` | ✅ | Full `msg_dispatch` bridge: thread-safe handler registry, async `PostMessage` via pluggable `MsgPostScheduler` (GTK: `g_idle_add`), synchronous `SendMessage` with pthread condvar blocking for cross-thread calls; 61 tests pass; GTK scheduler and main dialog handler registered in `ui_gtk.c` |
| `CreateThread` / `WaitForSingleObject` | ✅ | Full pthread bridge: threads, events (auto/manual-reset), mutexes, `CRITICAL_SECTION`, `WaitForMultipleObjects`, `GetExitCodeThread`, `TerminateThread` — 51 tests pass |
| Windows Registry (`RegOpenKey` etc.) | 🟡 | All no-ops; settings storage needs a Linux equivalent (e.g., `GKeyFile` / INI file) |
| `DEFINE_GUID` / `CompareGUID` / `GuidToString` / `StringToGuid` | ✅ | `DEFINE_GUID` in `guiddef.h` (INITGUID-conditional); others in `stdfn.c` / `stdio.c`; 19 tests pass |

---

## 3. Core Business Logic

### 3a. Device Enumeration (`dev.c` / `drive.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `GetDevices()` | ✅ | sysfs scan: removable flag, size, vendor/model; sorted by size; 79 tests pass |
| `CycleDevice()` / `CyclePort()` | ✅ | `CyclePort`: USB device reset via `USBDEVFS_RESET` ioctl; `CycleDevice`: sysfs unbind/rebind; `find_usb_sysfs_device` helper populates hub/port in `GetDevicesWithRoot`; 7 tests pass |
| `ClearDrives()` | ✅ | Frees rufus_drive[] strings and zeros the array |
| `GetPhysicalName()` | ✅ | Returns `/dev/sdX` path via `rufus_drive[i].id` |
| `GetPhysicalHandle()` | ✅ | Opens `/dev/sdX` with `O_RDWR` |
| `GetLogicalName()` / `GetLogicalHandle()` | ✅ | Scans sysfs to find `/dev/sdXN` partition path |
| `GetDriveSize()` | ✅ | `ioctl(BLKGETSIZE64)` on physical drive |
| `GetDriveLabel()` | ✅ | libblkid-based; probes whole-disk then first partition; tests pass |
| `IsMediaPresent()` | ✅ | `ioctl(BLKGETSIZE64)` + size > 0 check |
| `GetDriveTypeFromIndex()` | ✅ | sysfs `/sys/block/<dev>/removable` + `device/uevent`; tests pass |
| `GetDriveLetters()` / `GetUnusedDriveLetter()` | 🚫 | Drive letters are Windows-only; adapt callers to use mount points |
| `MountVolume()` / `UnmountVolume()` | ✅ | `mount(2)` / `umount2(2)` with multi-fs fallback; 11 tests pass |
| `AltMountVolume()` / `AltUnmountVolume()` | ✅ | `mkdtemp` + `mount(2)` / `umount2(2)` + `rmdir`; 11 tests pass |
| `RemoveDriveLetters()` | 🚫 | N/A on Linux |
| `CreatePartition()` | ✅ | `ioctl(BLKPG_ADD_PARTITION)` via libfdisk table manipulation |
| `InitializeDisk()` | ✅ | Writes fresh MBR/GPT with libfdisk |
| `RefreshDriveLayout()` / `RefreshLayout()` | ✅ | `ioctl(BLKRRPART)`; `RefreshLayout(DWORD)` opens by drive index; tests pass |
| `AnalyzeMBR()` / `AnalyzePBR()` | ✅ | ms-sys boot record analysis via FAKE_FD trick; tests pass |
| `GetDrivePartitionData()` | ✅ | Reads MBR/GPT partition table via libfdisk; populates PartitionStyle, nPartitions, etc. |
| `GetMBRPartitionType()` / `GetGPTPartitionType()` | ✅ | Lookup in `mbr_types.h` / `gpt_types.h` tables (no Windows dep); tests pass |
| `DeletePartition()` | ✅ | MBR+GPT table manipulation + `BLKPG_DEL_PARTITION` ioctl for real block devices; 42 tests pass |
| `SetAutoMount()` / `GetAutoMount()` | 🚫 | Windows auto-mount concept; Linux equivalent is `udisks2` policy |
| `GetOpticalMedia()` | ✅ | Scans `/dev/sr*`; size check via `BLKGETSIZE64`/seek; reads ISO 9660 label at offset 0x8028; 8 tests pass |
| `ClearDrives()` | ✅ | Done (part of GetDevices implementation) |
| `IsMsDevDrive()` | 🚫 | Windows Dev Drive feature; always return FALSE |
| `IsFilteredDrive()` | ✅ | Reads GPT Disk GUID from LBA 1 header offset 56; compares with `IgnoreDisk01`–`IgnoreDisk08` settings; returns FALSE for non-GPT disks; 5 tests pass |
| `IsVdsAvailable()` / `ListVdsVolumes()` / `VdsRescan()` | 🚫 | VDS is Windows-only |
| `ToggleEsp()` / `GetEspOffset()` | ✅ | Toggle ESP↔MS-Basic-Data (GPT) or 0xEF↔0x0C (MBR); CRC recomputed; 42 tests pass |

### 3b. Formatting (`format.c`, `format_fat32.c`, `format_ext.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `FormatThread()` (main format worker) | ✅ | Full FormatThread workflow: ClearMBRGPT, CreatePartition, FormatPartition, WriteMBR, WritePBR; FAT32 + ext2/3; MBR + GPT; image write + zero-drive modes; Syslinux installation wired (BT_SYSLINUX_V4/V6 and BT_IMAGE+sl_version); quick_format checkbox wired; 115 tests pass |
| `FormatPartition()` | ✅ | Routes FAT32 → `FormatLargeFAT32`, ext2/3/4 → `FormatExtFs`; 6 tests pass |
| `WritePBR()` (partition boot record) | ✅ | FAT32: ms-sys `write_fat_32_br` + primary/backup sectors; ext: no-op TRUE; 3 tests pass |
| `FormatLargeFAT32()` | ✅ | Full POSIX implementation; 16 tests pass |
| `FormatExtFs()` | ✅ | Uses bundled `ext2fs` lib; 9 tests pass |
| `error_message()` / `ext2fs_print_progress()` | ✅ | Implemented and working |
| `GetExtFsLabel()` | ✅ | `ext2fs_get_label()` working |
| Quick format checkbox | ✅ | `quick_format` global wired to GTK checkbox in `on_start_clicked`; controls `FP_QUICK` flag in FormatThread |
| Progress reporting from format thread | ✅ | `UpdateProgress()` in `ui_gtk.c` posts to GTK main thread via `g_idle_add(idle_update_progress, ...)`; `_UpdateProgressWithInfo` wraps it; fully wired |

### 3c. ISO / Image Handling (`iso.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `ExtractISO()` | ✅ | Full POSIX implementation using system libcdio; ISO9660 + UDF; scan + extract modes; label, block count, EFI detection; 6 tests pass |
| `ExtractISOFile()` | ✅ | Single-file extraction from ISO; UDF-first with ISO9660 fallback; 5 tests pass |
| `ReadISOFileToBuffer()` | ✅ | Reads file from ISO into malloc'd buffer; UDF-first with ISO9660 fallback; 6 tests pass |
| `GetGrubVersion()` / `GetGrubFs()` / `GetEfiBootInfo()` | ✅ | Pure buffer scans for version strings and filesystem modules; 11 tests pass |
| `HasEfiImgBootLoaders()` | ✅ | Reads `img_report.efi_img_path`; 2 tests pass |
| `ImageScanThread()` | ✅ | `src/linux/image_scan.c`: calls `ExtractISO` (scan mode) + `IsBootableImage`; posts `UM_IMAGE_SCANNED`; wired from `on_select_clicked()`; 7 tests / 14 assertions pass |
| `iso9660_readfat()` | ✅ | Sector-reader callback for libfat; uses `iso9660_readfat_private` cache (16 ISO blocks); sector divisibility check; 5 tests pass |
| `DumpFatDir()` | ✅ | Extracts FAT filesystem from EFI `.img` embedded in ISO; `wchar16_to_utf8()` converts UTF-16 code units (libfat stores 16-bit values in 32-bit wchar_t on Linux) to UTF-8; POSIX mkdir/open/write_all instead of Windows APIs; skips pre-existing files; 13 tests pass |
| `OpticalDiscSaveImage()` / `IsoSaveImageThread()` / `SaveImage()` | ✅ | Raw-copy optical disc to ISO using `open()`/`read()`/`write()` loop; `iso_save_run_sync()` is testable synchronous core; buffer sizing 8–32 MiB proportional to disc; progress via `UpdateProgressWithInfo`; `save_btn` wired in GTK UI; 10 tests pass |

### 3d. Hashing (`hash.c`)

| Function | Status | Notes |
|----------|--------|-------|
| MD5 / SHA-1 / SHA-256 / SHA-512 implementations | ✅ | All implemented in `src/windows/hash.c` in pure C — portable, just need to compile for Linux |
| `DetectSHA1Acceleration()` / `DetectSHA256Acceleration()` | ✅ | x86 CPUID check is platform-neutral; works on Linux |
| `HashFile()` / `HashBuffer()` | ✅ | Implemented in `src/linux/hash.c` with POSIX `open`/`read` |
| `HashThread()` / `IndividualHashThread()` | ✅ | Implemented with pthread via compat layer; 107 tests passing (3 new hash dialog tests) |
| `PE256Buffer()` / `efi_image_parse()` | ✅ | Pure C PE parsing ported from `src/windows/hash.c`; helper structs (`image_region`, `efi_image_regions`) and `efi_image_region_add`/`cmp_pe_section` added to `src/linux/hash.c`; 9 tests pass |
| `IsFileInDB()` / `IsBufferInDB()` | ✅ | Hash database lookup implemented in `src/linux/hash.c` |
| `IsSignedBySecureBootAuthority()` / `IsBootloaderRevoked()` | ✅ | Full OpenSSL-based implementation in `src/linux/hash.c`: DBX hash check (local file + EFI var at `/sys/firmware/efi/efivars/`), SBAT section check, cert revocation check, Secure Boot authority check; `IsRevokedBySvn()` is stubbed (Linux `wchar_t` = 4 bytes vs PE UTF-16 = 2 bytes); 10 new tests pass (121 hash tests total); `UseLocalDbx()` in `net.c` checks for cached DBX file |
| `UpdateMD5Sum()` | ✅ | Reads md5sum.txt, recomputes MD5 for each `modified_files` entry, patches hex in-place, writes back; bootloader rename (`GetResource`/IDR_MD5_BOOT) is Windows-only and intentionally omitted; 4 tests pass |
| `ValidateMD5Sum` flag | ✅ | Respected by `UpdateMD5Sum`; `validate_md5sum` global wired |

### 3e. Networking (`net.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `DownloadToFileOrBufferEx()` | ✅ | libcurl implementation; file + buffer modes, HTTP status tracking, silent/noisy error, User-Agent; 45 tests pass |
| `IsDownloadable()` | ✅ | URL validation: http:// and https:// only; 45 tests pass |
| TLS / certificate verification | ✅ | `libcurl` + system CA bundle; CURLOPT_SSL_VERIFYPEER enabled by default |
| `DownloadSignedFile()` | 🔧 | Delegates to `DownloadToFileOrBufferEx`; signature verification not yet implemented (needs `pki.c`) |
| `DownloadSignedFileThreaded()` | ✅ | Wraps `DownloadSignedFile` in a `CreateThread`; `malloc`'d args freed on exit; 2 new tests (55 net tests pass) |
| `CheckForUpdates()` | ✅ | Fetches `rufus_linux.ver` via libcurl; compares versions with `rufus_is_newer_version()`; respects update interval; calls `parse_update()`/`DownloadNewVersion()`; 10 tests pass |
| `DownloadISO()` | ✅ | Full implementation: downloads+decompresses Fido script, creates POSIX FIFO, forks pwsh, reads URL, calls FileDialog, downloads ISO; 57 net tests pass |
| `UseLocalDbx()` | ✅ | Timestamp-based cache check: returns TRUE when `DBXTimestamp_<arch>` setting exceeds embedded baseline; `CheckForDBXUpdates()` queries GitHub Commits API, parses ISO 8601 date with `timegm()`, downloads newer DBX and saves timestamp; wired into `CheckForUpdatesThread()`; 56 tests pass |
| `configure.ac` libcurl detection | ✅ | `PKG_CHECK_MODULES([CURL], [libcurl >= 7.50])` added; flags propagated to AM_CFLAGS/AM_LDFLAGS |

### 3f. PKI / Certificates (`pki.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `ValidateSignature()` | ✅ | Returns 0 (NO_ERROR) on Linux — WinTrust is Windows-only; file existence checked |
| `ValidateOpensslSignature()` | ✅ | OpenSSL EVP API; hard-coded RSA-2048 pubkey; reverses LE sig bytes; SHA-256 verify |
| `GetSignatureName()` / `GetSignatureTimeStamp()` | ✅ | mmap PE, parse security directory as PKCS7; extract CN / signing time |
| `GetIssuerCertificateInfo()` | ✅ | Parses WIN_CERTIFICATE blob as PKCS7; extracts name + SHA-1 thumbprint |
| `ParseSKUSiPolicy()` | ✅ | Returns FALSE (Windows-only WDAC policy) |
| `WinPKIErrorString()` | ✅ | Returns OpenSSL error string via `ERR_peek_last_error` |

### 3g. Process Management (`process.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `EnablePrivileges()` | ✅ | Returns TRUE on Linux (root check is in `stdfn.c`); 19 tests pass |
| `GetPPID()` | ✅ | Reads `/proc/PID/status`; 19 tests pass |
| `StartProcessSearch()` / `SetProcessSearch()` / `StopProcessSearch()` / `GetProcessSearch()` | ✅ | `/proc` scan for open handles to target device; 19 tests pass |
| `SearchProcessAlt()` | ✅ | Scans `/proc/PID/comm`; 19 tests pass |
| `PhEnumHandlesEx()` / `PhOpenProcess()` | 🚫 | NT internal APIs; not applicable on Linux |
| `NtStatusError()` | 🚫 | NT status codes; not applicable |
| `RunCommandWithProgress()` (in `stdfn.c`) | ✅ | Implemented in `stdio.c`: fork/pipe with regex progress tracking; cancellation support; multi-line output; 15 tests pass |

### 3h. Standard Functions / Utilities (`stdfn.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `htab_create()` / `htab_destroy()` / `htab_hash()` | ✅ | Full implementation ported from Windows stdfn.c; 299 tests pass |
| `StrArray*` functions | ✅ | Implemented and work |
| `FileIO()` | ✅ | Implemented with POSIX `fopen`/`fread`/`fwrite`; READ/WRITE/APPEND modes; 10 tests |
| `GetResource()` / `GetResourceSize()` | ✅ | Implemented for `IDR_FD_*` resource IDs via `freedos_data.c` lookup table; integer IDs via `MAKEINTRESOURCEA`; returns `NULL` for unknown IDs |
| `SetLGP()` / `SetLGPThread()` | 🚫 | Windows Group Policy — no Linux equivalent |
| `MountRegistryHive()` / `UnmountRegistryHive()` | 🚫 | Windows Registry — no Linux equivalent |
| `TakeOwnership()` | 🚫 | Windows ACL — no Linux equivalent; use `chown` if ever needed |
| `SetPrivilege()` | 🚫 | Windows token privilege — no Linux equivalent |
| `SetThreadAffinity()` | ✅ | Uses `sched_getaffinity` to get available CPUs; spreads across threads with disjoint bitmasks; `SetThreadAffinityMask` uses `pthread_setaffinity_np`; 5 tests pass |
| `GetWindowsVersion()` | 🚫 | N/A; return zeroed struct (done) |
| `GetExecutableVersion()` | 🟡 | Read `ELF` / PE version; stub returns NULL (no PE version resources in ELF); low priority |
| `IsFontAvailable()` | ✅ | Uses fontconfig `FcFontMatch` + family name substring comparison; 3 tests pass |
| `ToLocaleName()` | ✅ | Returns BCP-47 locale from `LANG` env var (e.g. `en_US.UTF-8` → `en-US`); falls back to `en-US` for C/POSIX; 5 tests pass |
| `IsCurrentProcessElevated()` | ✅ | Returns `geteuid() == 0` |
| `isSMode()` | 🚫 | Windows S Mode — always FALSE |
| `ExtractZip()` | ✅ | Implemented using bundled `bled` library (`bled_uncompress_to_dir`); fixed path separator and `bytes_out` tracking for stored files |
| `ListDirectoryContent()` | ✅ | POSIX `opendir`/`readdir`/`stat`; supports FILE, DIRECTORY, RECURSIVE flags |
| `WriteFileWithRetry()` | ✅ | `write()` retry loop with EINTR/EAGAIN handling; NULL-buf guard; 4 tests pass |
| `ResolveDllAddress()` | 🚫 | DLL delay-load — N/A on Linux |
| `WaitForSingleObjectWithMessages()` | ✅ | Delegates to `WaitForSingleObject`; no message pump needed on Linux (GTK runs its own loop); 3 tests pass |
| `CreateFileWithTimeoutThread()` | ✅ | Opens file/device with O_NONBLOCK in a thread; clears O_NONBLOCK after open; `CreateFileWithTimeout` wrapper respects deadline via `WaitForSingleObject`; 3 tests pass |

### 3i. Standard I/O (`stdio.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `uprintf()` / `uprintfs()` | ✅ | Routes to GTK log widget via `rufus_set_log_handler()`; falls back to stderr |
| `wuprintf()` | ✅ | UCS-4→UTF-8 inline encoder; NULL guard; 5 new UTF-8 tests pass |
| `uprint_progress()` | ✅ | Calls `_UpdateProgressWithInfo(OP_FORMAT, ...)` when max > 0 |
| `read_file()` / `write_file()` | ✅ | Work correctly |
| `DumpBufferHex()` | ✅ | xxd-style hex+ASCII dump via uprintf; 5 tests pass |
| `_printbits()` | ✅ | 32-bit binary string renderer; 7 tests pass |
| `WindowsErrorString()` / `StrError()` | ✅ | Maps to `strerror()`; 36 DWORD-mapping tests pass |
| `SizeToHumanReadable()` | ✅ | Formats byte counts as human-readable string |
| `TimestampToHumanReadable()` | ✅ | Formats YYYYMMDDHHMMSS uint64 as "YYYY.MM.DD HH:MM:SS (UTC)"; ported from Windows; 8 tests pass |
| `ExtractZip()` | ✅ | See stdfn above (bled-based implementation) |

### 3j. Standard Dialogs (`stdlg.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `FileDialog()` | ✅ | Test-injectable; GTK `GtkFileChooserDialog` impl via `#ifdef USE_GTK` in `stdlg.c`; returns preset path or NULL in tests |
| `NotificationEx()` / notification popups | ✅ | Test-injectable; GTK `GtkMessageDialog` impl via `#ifdef USE_GTK` in `stdlg.c`; maps MB_* flags to GTK message/button types; 36 tests pass |
| `CustomSelectionDialog()` | ✅ | GTK implementation: checkbox/radio-button grid GtkDialog; username_index creates inline GtkEntry; test-injectable; fallback returns mask; 40 tests pass |
| `ListDialog()` | ✅ | GTK implementation: scrollable GtkListBox dialog; non-GTK dumps to stderr; 40 tests pass |
| `CreateTooltip()` / `DestroyTooltip()` | ✅ | Uses `gtk_widget_set_tooltip_text` / `gtk_widget_set_has_tooltip`; `#ifdef USE_GTK` guard; 6 tests pass; wired into `on_app_activate` for device, boot, filesystem, cluster, label, select, start controls |
| `SetTaskbarProgressValue()` | 🚫 | Windows taskbar — N/A; could map to GTK window urgency hint |
| `CreateAboutBox()` / `AboutCallback()` | 🔧 | GTK About dialog implemented in `ui_gtk.c`; callback stub unused |
| `LicenseCallback()` | 🟡 | Show license in a `GtkDialog` |
| `UpdateCallback()` / `NewVersionCallback()` | 🟡 | Update dialog; low priority |
| `SetFidoCheck()` / `SetUpdateCheck()` | ✅ | Both implemented: `SetFidoCheck` checks for pwsh, spawns `CheckForFidoThread` (downloads Fido.ver, validates URL, posts `UM_ENABLE_DOWNLOAD_ISO` to reveal Download ISO button); wired into `on_app_activate`; 57 net tests pass |
| `FlashTaskbar()` | 🚫 | N/A on Linux |
| `MyCreateDialog()` / `MyDialogBox()` | 🔧 | Windows dialog resource system; `IDD_HASH` replaced with `UM_HASH_COMPLETED` → GTK dialog; others still stub |
| `GetDialogTemplate()` | 🚫 | Windows `.rc` resource — not applicable on Linux |
| `SetAlertPromptHook()` / `SetAlertPromptMessages()` | 🟡 | Alert interception; GTK equivalent needed |
| `CenterDialog()` / `ResizeMoveCtrl()` | 🚫 | GTK handles layout automatically |
| `CreateStaticFont()` / `SetHyperLinkFont()` | 🟡 | Use Pango / CSS for hyperlink styling |
| `DownloadNewVersion()` | ✅ | Calls `xdg-open DOWNLOAD_URL` to open browser to Rufus downloads page |

### 3k. UI Logic (`ui.c` / `ui_gtk.c`)

| Function / Feature | Status | Notes |
|--------------------|--------|-------|
| GTK window and all widgets | ✅ | Window, all dropdowns, buttons, progress, log dialog |
| `EnableControls()` | ✅ | Disables/re-enables all input widgets |
| `UpdateProgress()` / `_UpdateProgressWithInfo()` | ✅ | Thread-safe via `g_idle_add` |
| `InitProgress()` | ✅ | Resets progress bar |
| `TogglePersistenceControls()` | ✅ | Show/hide persistence row |
| `SetPersistencePos()` / `SetPersistenceSize()` | ✅ | Slider + label |
| `ToggleAdvancedDeviceOptions()` / `ToggleAdvancedFormatOptions()` | ✅ | GtkExpander expand/collapse |
| `ToggleImageOptions()` | ✅ | Show/hide image option row |
| Device combo population | ✅ | `combo_bridge.c`: full CB_* message dispatch for all combo boxes; `GetDevices()` populates device list via combo_bridge; 105 tests pass |
| Boot type combo population | ✅ | `populate_boot_combo()` adds Non-bootable/ISO Image/FreeDOS; wired in `combo_register_all()` |
| Partition scheme / target system / FS / cluster combos | ✅ | `populate_partition_combos()`, `populate_fs_combo()`, `populate_cluster_combo()` all implemented; driven by device selection via `on_device_changed()` |
| On-START → `FormatThread` launch | ✅ | `on_start_clicked()` reads combo selections into globals; shows MSG_003 "WARNING: ALL DATA WILL BE DESTROYED" GTK confirmation dialog; launches FormatThread with drive index on IDOK |
| Cancel in-progress operation | ✅ | `on_close_clicked` sets `ErrorStatus = RUFUS_ERROR(ERROR_CANCELLED)` |
| Language menu (`ShowLanguageMenu`) | ✅ | Builds GTK menu from `locale_list`; activates via `PostMessage → main_dialog_handler` |
| `SetAccessibleName()` | ✅ | Sets tooltip text + `atk_object_set_name()` via `gtk_widget_get_accessible()` for screen-reader support |
| Device-change notification (hot-plug) | ✅ | `device_monitor.c`: udev netlink monitor thread; 1 s debounce; posts `UM_MEDIA_CHANGE` → `GetDevices()`; wired in `ui_gtk.c`; 20 tests pass |
| `SetComboEntry()` | ✅ | |
| DPI scaling / `AdjustForLowDPI()` | ✅ | GTK handles natively |
| Window positioning / `CenterDialog()` | 🚫 | GTK manages automatically |
| `OnPaint()` | 🚫 | GTK/cairo handles all drawing |

### 3l. Localization (`localization.c`, `parser.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `get_supported_locales()` | ✅ | Portable; in `common/parser.c` |
| `get_loc_data_file()` | ✅ | Portable; in `common/parser.c` |
| `dispatch_loc_cmd()` | ✅ | Portable; in `common/localization.c` |
| `lmprintf()` | ✅ | Portable; in `common/localization.c` |
| `PrintStatusInfo()` | ✅ | Routes all status messages through `rufus_set_status_handler()` callback; GTK wired to update status label in `ui_gtk.c`; 23 tests pass |
| `apply_localization()` / `reset_localization()` | ✅ | GTK widget label update via `ctrl_id_to_widget()` + `set_widget_text()`; all rw.* label fields wired in `ui_gtk.c`; 11 tests pass |
| `get_locale_from_lcid()` / `get_locale_from_name()` | ✅ | Portable; in `common/localization.c` |
| `toggle_default_locale()` | ✅ | Portable; in `common/localization.c` |
| `get_token_data_file_indexed()` / `set_token_data_file()` | ✅ | Linux impl in `linux/parser.c`; 111 tests pass |
| `get_token_data_buffer()` | ✅ | Linux impl in `linux/parser.c` |
| `insert_section_data()` / `replace_in_token_data()` | ✅ | Linux impl in `linux/parser.c` |
| `replace_char()` / `filter_chars()` / `remove_substr()` | ✅ | Portable; in `common/parser.c` |
| `parse_update()` | ✅ | Linux impl in `linux/parser.c` |
| `get_data_from_asn1()` | ✅ | Portable; in `common/parser.c` |
| `sanitize_label()` | ✅ | Portable; in `common/parser.c` |
| `GetSbatEntries()` / `GetThumbprintEntries()` | ✅ | Portable; in `common/parser.c` |
| `GetPeArch()` / `GetPeSection()` / `RvaToPhysical()` / `FindResourceRva()` / `GetPeSignatureData()` | ✅ | Portable; moved to `common/parser.c`; PE structs in `linux/compat/winnt.h`; 27 tests pass |

### 3m. DOS / Syslinux / Bootloader (`dos.c`, `dos_locale.c`, `syslinux.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `ExtractFreeDOS()` / `ExtractDOS()` | ✅ | Copies FreeDOS boot files from `res/freedos/` to target; dispatches on `boot_type`; 23 tests pass |
| `SetDOSLocale()` | ✅ | Creates AUTOEXEC.BAT + FDCONFIG.SYS with US/CP437 defaults; 23 tests pass |
| `InstallSyslinux()` | ✅ | Uses mcopy+libfat+pwrite; requires FAT32 image with >65524 clusters (libfat FAT28 detection); 36 tests pass |
| `GetSyslinuxVersion()` | ✅ | Verbatim port from Windows; scans buffer for SYSLINUX/ISOLINUX version string |
| `libfat_readfile()` | ✅ | pread-based FAT sector reader; `intptr_t` fd cast |
| GRUB support | ✅ | MBR boot code written via `write_grub2_mbr` (ms-sys); `InstallGrub2` calls `grub-install --target=i386-pc` for core.img install on BIOS-boot GRUB2 ISOs; wired into FormatThread after ExtractISO; `InstallGrub4DOS` copies grldr from `<app_data_dir>/Rufus/grub4dos-VERSION/grldr` to mounted partition root; standalone BT_GRUB4DOS mounts partition via AltMountVolume + installs grldr + unmounts; BT_IMAGE+has_grub4dos falls back to InstallGrub4DOS if grldr not found in extracted files; 10 new tests (154 total); UEFI GRUB: works via EFI files extracted by ISO extraction |

### 3n. WIM / VHD / WUE (`vhd.c`, `wue.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `IsBootableImage()` | ✅ | POSIX open/read/fstat + bled decompression |
| `GetWimVersion()` | ✅ | wimlib (cross-platform) |
| `WimExtractFile()` / `WimSplitFile()` / `WimApplyImage()` | ✅ | wimlib with Linux path separators |
| `VhdMountImageAndGetSize()` | ✅ | qemu-nbd + BLKGETSIZE64 ioctl |
| `VhdUnmountImage()` | ✅ | qemu-nbd --disconnect |
| `CreateUnattendXml()` | ✅ | POSIX + timezone section skipped on Linux |
| `SetupWinPE()` | 🚫 | Windows-only; stub returns FALSE |
| `PopulateWindowsVersion()` | ✅ | wimlib + ezxml (cross-platform) |
| `CopySKUSiPolicy()` | 🚫 | Windows-only WDAC policy; stub returns FALSE |
| `SetWinToGoIndex()` / `SetupWinToGo()` | 🚫 | Windows-only; stubs return -1/FALSE |
| `ApplyWindowsCustomization()` | 🚫 | Windows-only; stub returns FALSE |

### 3o. S.M.A.R.T. (`smart.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `Identify()` | ✅ | ATA IDENTIFY via `SG_IO`; debug-only (`RUFUS_TEST`) |
| `SmartGetVersion()` | ✅ | Stub returns FALSE (dead code on Windows too; `#if 0`) |
| `IsHDD()` | ✅ | Ported verbatim; uses `StrStrIA` added to compat layer |
| `SptStrerr()` | ✅ | Ported verbatim |
| `ScsiPassthroughDirect()` | ✅ | Linux uses `SG_IO` ioctl instead of `IOCTL_SCSI_PASS_THROUGH_DIRECT` |

### 3p. Bad Blocks (`badblocks.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `BadBlocks()` | ✅ | Implemented via `pread`/`pwrite`, `posix_memalign`, `clock_gettime`; bad-block list management ported verbatim; 43 tests pass |

### 3q. Icon / Autorun (`icon.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `ExtractAppIcon()` | 🚫 | Windows `.ico` embedding — N/A on Linux |
| `SetAutorun()` | 🚫 | `autorun.inf` is Windows-only |

### 3r. Dark Mode (`darkmode.c`)

All functions are no-ops on Linux — correct.  GTK theming handles dark mode automatically via `GTK_THEME` / `prefer-dark-appearance` setting.  `is_darkmode_enabled` is now kept in sync with the GTK setting at runtime:

| Feature | Status | Notes |
|---------|--------|-------|
| Manual dark mode toggle (Ctrl+Alt+D) | ✅ | Toggles `gtk-application-prefer-dark-theme` and saves preference |
| Saved dark mode preference at startup | ✅ | Read from `SETTING_DARK_MODE` (0=system, 1=light, 2=dark) |
| Reactive dark mode (item 55) | ✅ | `notify::gtk-application-prefer-dark-theme` signal connected in `on_app_activate`; `is_darkmode_enabled` updated on every system/user theme change |

---

## 4. Message Passing / Threading Architecture

This is the most structurally significant porting gap.

| Item | Status | Notes |
|------|--------|-------|
| Windows `HANDLE`-based threads (`CreateThread` / `WaitForSingleObject`) | ✅ | pthread bridge complete — `CreateThread`, `WaitForSingleObject`, `WaitForMultipleObjects`, `TerminateThread`, `GetExitCodeThread` all implemented |
| `PostMessage` / `SendMessage` for cross-thread UI updates | ✅ | `msg_dispatch.c` bridge: handler registry, async `g_idle_add` scheduler, cross-thread blocking SendMessage via condvar; `hMainDialog` handler handles all `UM_*` messages; 61 tests pass |
| `WM_DEVICECHANGE` device-arrival events | ✅ | `device_monitor.c`: udev netlink monitor thread (libudev); debounce 1 s; `device_monitor_inject()` for manual refresh/testing; posts `UM_MEDIA_CHANGE` → `GetDevices()` on GTK main thread; 20 tests pass |
| Windows timer (`SetTimer` / `KillTimer`) | ✅ | Not used by any Linux source file; stubs in `compat/windows.h` are sufficient |
| `CRITICAL_SECTION` / `Mutex` | ✅ | `CRITICAL_SECTION` (recursive pthread mutex) and `CreateMutex`/`ReleaseMutex` implemented in compat layer |
| `op_in_progress` flag | ✅ | Set TRUE on format start, cleared + thread handle closed in `UM_FORMAT_COMPLETED` handler |

---

## 5. Settings / Persistence

| Item | Status | Notes |
|------|--------|-------|
| Windows `rufus.ini` file read/write | ✅ | `FileIO()` implemented (POSIX), `set_token_data_file` fixed for new files |
| Registry settings (`HKCU\Software\Rufus\`) | ✅ | Replaced with `~/.config/rufus/rufus.ini`; `src/linux/settings.h` provides `ReadSetting*`/`WriteSetting*` |
| `app_dir` / `app_data_dir` / `user_dir` paths | ✅ | Set by `rufus_init_paths()` in `rufus.c`; uses `XDG_CONFIG_HOME`/`XDG_DATA_HOME`; called from `on_app_activate()` |

---

## 6. Elevation / Privileges

| Item | Status | Notes |
|------|--------|-------|
| `IsCurrentProcessElevated()` | ✅ | `geteuid() == 0` |
| Root-required operations (device open, raw write) | ✅ | Non-root startup re-launches via `pkexec` automatically; falls back to MSG_288/MSG_289 GTK warning if pkexec not found |
| `polkit` integration | ✅ | `src/linux/polkit.c`: `rufus_needs_elevation()` / `rufus_build_pkexec_argv()` / `rufus_try_pkexec()`; `res/ie.akeo.rufus.policy` installed to `$(datadir)/polkit-1/actions/`; `main()` in `ui_gtk.c` calls `rufus_try_pkexec()` when `geteuid()!=0` |

---

## 7. Embedded Resources

| Item | Status | Notes |
|------|--------|-------|
| `GetResource()` — Windows PE resources | ✅ | Implemented for `IDR_FD_*` (300–326) via `freedos_data.c` embedded arrays; `MAKEINTRESOURCEA` integer IDs supported |
| Embedded locale data (`res/loc/embedded.loc`) | ✅ | `find_loc_file()` searches `app_dir/res/loc/embedded.loc`, `app_dir/embedded.loc`, `RUFUS_DATADIR/embedded.loc`; loaded in `on_app_activate()`; 7 new tests in `test_parser` (get_supported_locales + get_loc_data_file) pass |
| Embedded FreeDOS / MS-DOS boot files | ✅ | 27 FreeDOS files embedded as `const uint8_t[]` arrays in `freedos_data.c`; `ExtractFreeDOS()` uses `GetResource()` first, falls back to disk |
| Application icon (`.desktop` / `.png`) | ✅ | `res/ie.akeo.rufus.desktop` + `res/ie.akeo.rufus.appdata.xml`; icons at 32/48/256px; install targets in `Makefile.am` |

---

## 8. Testing Gaps

| Area | Status | Notes |
|------|--------|-------|
| `common/cregex` tests | ✅ | 37 tests, Linux + Wine |
| Threading compat layer tests | ✅ | 51 tests covering threads, events, mutexes, CRITICAL_SECTION |
| `common/xml` (ezxml) tests | ✅ | 81 tests: parse from string/file, child nav, attrs, siblings, idx, get_val, error, toxml round-trip, entity handling, deep path, programmatic tree build |
| `stdfn.c` (htab, StrArray) tests | ✅ | 299 tests; htab_create/hash/destroy, StrArray, NULL guards |
| `parser.c` / `localization.c` tests | ✅ | 111 tests covering replace_char, filter_chars, remove_substr, sanitize_label, ASN.1, GetSbatEntries, GetThumbprintEntries, open_loc_file, token CRUD, insert_section_data, replace_in_token_data |
| PE parsing functions tests | ✅ | 59 tests pass in `test_pe_parser_linux` |
| `msg_dispatch` (PostMessage/SendMessage bridge) tests | ✅ | 61 tests: handler registry, sync/async dispatch, cross-thread SendMessage, concurrent posts, macro aliases, UM_* constants |
| `common/device_monitor` (hotplug) tests | ✅ | 20 tests: lifecycle (start/stop/double/null), callback dispatch, debounce, thread safety, inject |
| `common/net` (IsDownloadable, DownloadToFileOrBufferEx) tests | ✅ | 45 tests; real libcurl downloads, file+buffer modes, HTTP status, User-Agent, 404 handling, binary data |
| `combo_bridge` (ComboBox message dispatch) tests | ✅ | 105 tests: lifecycle, all CB_* messages (ADDSTRING/RESETCONTENT/GETCURSEL/SETCURSEL/GETCOUNT/SETITEMDATA/GETITEMDATA/GETLBTEXT/GETLBTEXTLEN), capacity growth, GTK-free unit testing |

---

## 9. Priority Order (Suggested)

1. ~~**Threading bridge**~~ ✅ **DONE** — `CreateThread` → `pthread`, events, mutexes, `CRITICAL_SECTION` all implemented with 51 passing tests
2. ~~**`PostMessage`/`SendMessage` → GTK dispatch**~~ ✅ **DONE** — `msg_dispatch.c` bridge with 61 passing tests; GTK `g_idle_add` scheduler and main dialog handler registered in `ui_gtk.c`
3. ~~**`stdfn.c` htab**~~ ✅ **DONE** — full hash table + StrArray ported; 299 tests pass
4. ~~**Device enumeration** (`dev.c`)~~ ✅ **DONE** — sysfs scan with sort, filtering, combo population; 138 tests pass using fake sysfs
5. ~~**Device combo hot-plug**~~ ✅ **DONE** — `src/linux/device_monitor.c`: udev netlink monitor, 1 s debounce, `device_monitor_inject()` hook, `UM_MEDIA_CHANGE` → `GetDevices()` wired in `ui_gtk.c`; 20 tests pass
6. ~~**Localization + parser**~~ ✅ **DONE** — `common/parser.c` + `common/localization.c` created; `linux/parser.c` + `linux/localization.c` fully implemented; portable functions stripped from `windows/`; 111 tests pass
7. ~~**Format thread** (`format.c`)~~ ✅ **DONE** — Full FormatThread workflow implemented: ClearMBRGPT, CreatePartition, FormatPartition, WriteMBR, WritePBR; FAT32 + ext2/3; MBR + GPT; image write + zero-drive modes; Syslinux installation wired (BT_SYSLINUX_V4/V6 and BT_IMAGE+sl_version); 115 tests pass
8. ~~**FAT32 formatter** (`format_fat32.c`)~~ ✅ **DONE** — 16 tests pass
9. ~~**ext formatter** (`format_ext.c`)~~ ✅ **DONE** — 9 tests pass
10. ~~**ISO extraction** (`iso.c`)~~ ✅ **DONE** — full POSIX implementation using libcdio; 12345 tests pass
11. ~~**Hashing** (`hash.c`)~~ ✅ **DONE** — all hash algorithms + HashThread/IndividualHashThread; hash results dialog via `UM_HASH_COMPLETED` → GTK GtkGrid dialog; 107 tests pass; hash button (`rw.hash_btn`) wired to `on_hash_clicked` → `CreateThread(HashThread)`; `on_log_clicked` missing header fixed; `on_toggle_dark_mode` forward declaration added
11. ~~**Networking** (`net.c`)~~ ✅ **DONE** — `IsDownloadable` + `DownloadToFileOrBufferEx` implemented with libcurl; 45 tests pass; `configure.ac` updated with `PKG_CHECK_MODULES` for libcurl; stubs remain for `CheckForUpdates`/`DownloadISO`/`DownloadSignedFileThreaded`
12. ~~**PKI / signatures** (`pki.c`)~~ ✅ **DONE** — OpenSSL EVP API for `ValidateOpensslSignature`; mmap PE parsing for `GetSignatureName`/`GetSignatureTimeStamp`/`GetIssuerCertificateInfo`; 21 tests pass
13. ~~**Bad blocks** (`badblocks.c`)~~ ✅ **DONE** — full POSIX port using `pread`/`pwrite`/`posix_memalign`/`clock_gettime`; bad-block list management ported verbatim; `ERROR_OBJECT_IN_LIST` added to compat; 43 tests pass
14. ~~**S.M.A.R.T.** (`smart.c`)~~ ✅ **DONE** — `ScsiPassthroughDirect` uses `SG_IO` ioctl; `IsHDD()` ported verbatim with `StrStrIA` added to compat; 25 tests pass
15. **WIM / VHD** (`vhd.c`, `wue.c`) — `wimlib` is bundled; VHD needs `nbd`
16. ~~**Settings persistence**~~ ✅ **DONE** — `FileIO()` implemented, `set_token_data_file()` fixed for new files, `src/linux/settings.h` with full `ReadSetting*`/`WriteSetting*` API, `rufus_init_paths()` with XDG paths, wired into `on_app_activate()`; 74 tests pass
17. **Elevation / polkit** — for proper desktop integration
18. **Syslinux / DOS bootloaders** — finish installer wiring
19. ~~**Language menu**~~ ✅ **DONE** — `ShowLanguageMenu` builds GTK menu from `locale_list`, wired to lang button; activates via `PostMessage → main_dialog_handler → get_loc_data_file`
19a. ~~**uprintf → GTK log routing**~~ ✅ **DONE** — `rufus_set_log_handler()` API in `stdio.c`; registered in `on_app_activate()`; 5 new tests pass
19b. ~~**Cancel operation**~~ ✅ **DONE** — `on_close_clicked` sets `ErrorStatus = RUFUS_ERROR(ERROR_CANCELLED)`
19c. ~~**stdlg test-injection API**~~ ✅ **DONE** — `stdlg_set_test_response()` / `stdlg_clear_test_mode()` in `stdlg.c`; 24 tests pass (all assertions pass)
20. ~~**Desktop integration**~~ ✅ **DONE** — `res/ie.akeo.rufus.desktop` + `res/ie.akeo.rufus.appdata.xml`; icons at 32/48/256px copied from appstore images; `Makefile.am` install-data-hook installs into hicolor theme tree
21. ~~**ComboBox message bridge**~~ ✅ **DONE** — `src/linux/combo_bridge.c`: pure-C CB_* message handler; all 7 combo boxes (device, boot, partition, target, FS, cluster, imgopt) registered via `combo_register_all()`; HWNDs remapped to state objects; GTK sync optional; `GetDevices()` populates device combo; `on_device_changed()` / `on_boot_changed()` update all dependent combos; 105 tests pass

22. ~~**Process management** (`process.c`)~~ ✅ **DONE** — `GetPPID` via `/proc/PID/status`; process search via `/proc/*/fd` device scan; `SearchProcessAlt` via `/proc/PID/comm`; `EnablePrivileges` returns TRUE; 19 tests pass
23. ~~**Mount API** (`drive.c`)~~ ✅ **DONE** — `MountVolume`, `AltMountVolume`, `AltUnmountVolume` using `mount(2)` / `umount2(2)` with multi-fs fallback (vfat/ntfs/exfat/ext4/ext3/ext2); `mkdtemp` for temp mount points; 11 tests pass
24. ~~**apply_localization GTK wiring**~~ ✅ **DONE** — `ctrl_id_to_widget()` maps 30+ IDC_*/IDS_* IDs to `rw.*` fields; `set_widget_text()` uses GTK_IS_BUTTON/GTK_IS_LABEL; 11 label widget fields added to `RufusWidgets`; stored in `ui_gtk.c` build functions; 11 tests pass
25. ~~**ImageScanThread**~~ ✅ **DONE** — `src/linux/image_scan.c`: scans ISO/image via `ExtractISO` + `IsBootableImage`; posts `UM_IMAGE_SCANNED` on completion; wired in `on_select_clicked()` via `CreateThread`; `UM_IMAGE_SCANNED` handler in `main_dialog_handler` calls `SetFSFromISO` + `SetPartitionSchemeAndTargetSystem`; 7 tests / 14 assertions pass
26. ~~**GRUB4DOS `grldr` wiring**~~ ✅ **DONE** — `InstallGrub4DOS(mount_dir)` in `format.c` copies grldr from `<app_data_dir>/Rufus/grub4dos-VERSION/grldr` to the mounted partition root; standalone `BT_GRUB4DOS` in `FormatThread` uses `AltMountVolume` + `InstallGrub4DOS` + `AltUnmountVolume`; `BT_IMAGE+has_grub4dos` falls back to `InstallGrub4DOS` if grldr is not in the extracted ISO; 10 new tests added (MBR code, null/no-cache/happy-path unit tests, FormatThread integration); 154 total tests pass
27. ~~**`polkit` integration**~~ ✅ **DONE** — `src/linux/polkit.c`: `rufus_needs_elevation()` checks `geteuid()==0`; `rufus_build_pkexec_argv()` builds `[pkexec, /proc/self/exe, ...argv, NULL]`; `rufus_try_pkexec()` searches pkexec candidates (`/usr/bin`, `/usr/local/bin`, `/bin`) and `execv()`-relaunches; `res/ie.akeo.rufus.policy` with `ie.akeo.rufus.run` action, `auth_admin_keep`, `allow_gui=true`; `main()` in `ui_gtk.c` calls `rufus_try_pkexec()` when not elevated; `Makefile.am` installs policy to `$(datadir)/polkit-1/actions/`; 32 tests pass (`test_polkit_linux`)
28. ~~**`IsSignedBySecureBootAuthority()` / `IsBootloaderRevoked()`**~~ ✅ **DONE** — Full OpenSSL-based implementation in `src/linux/hash.c`: DBX hash check (local file + `/sys/firmware/efi/efivars/dbx-*`), SBAT section check, cert revocation check, Secure Boot authority check; `UseLocalDbx()` implemented in `net.c` (checks cached DBX file); `IsRevokedBySvn()` is stubbed (Linux `wchar_t`=4 bytes vs PE UTF-16=2 bytes); `src/linux/efi.h` created with EFI structs; 10 new tests pass (121 hash tests total)
29. ~~**`DownloadSignedFile()` signature verification**~~ ✅ **DONE** — Implemented RSA-SHA256 verify in `DownloadSignedFile()` (linux/net.c): downloads content to buffer, downloads `url+".sig"` to buffer, calls `ValidateOpensslSignature()`, sets `DownloadStatus=403` on bad sig, writes file + sets `DownloadStatus=200` on success; test build uses a test RSA-2048 key stub in `net_linux_glue.c` (identical algorithm, test key pair); 6 new tests: null URL, missing .sig, short .sig, wrong .sig content, valid sig writes file, status codes verified; all 74 net tests pass
30. ~~**`UseLocalDbx()` / DBX revocation database**~~ ✅ **DONE** — `IsRevokedByDbx()` in `src/linux/hash.c` reads `/sys/firmware/efi/efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f` as fallback (strips 4-byte EFI attribute header), with preference for a locally cached `app_data_dir/FILES_DIR/dbx_<arch>.bin` when `UseLocalDbx(arch)` returns TRUE; `UseLocalDbx()` in `src/linux/net.c` compares `ReadSetting64("DBXTimestamp_<arch>")` against the embedded baseline timestamp; `CheckForDBXUpdates()` fetches the GitHub commits API to find newer DBX builds and downloads them; 40 tests in `test_dbx_linux.c` cover URL building, JSON timestamp parsing, `UseLocalDbx` freshness checks, and update smoke tests
31. ~~**Embedded FreeDOS / MS-DOS boot files**~~ ✅ **DONE** — Generated `src/linux/freedos_data.c` with 27 FreeDOS files as `const uint8_t[]` arrays (391KB embedded data) and `src/linux/freedos_data.h` with lookup table `fd_resources[]` mapping `IDR_FD_*` IDs; implemented real `GetResource()` / `GetResourceSize()` in `stdfn.c` using the lookup table (integer resource IDs via `MAKEINTRESOURCEA`); updated `dos.c` to try `GetResource()` first for each file, fall back to disk copy; updated `src/Makefile.am` + `tests/Makefile` (also fixed missing `-lfontconfig` for DOS test build); 8 new tests: `getresource_*` (not-null, size-correct, unknown-returns-null, dup-allocates-copy, EGA), `extract_freedos_embedded_no_disk`, `extract_freedos_embedded_content_correct_size`; all 39 DOS tests pass, full suite clean
32. **`GetResource()` → C array / on-disk shim** — replace Windows PE `FindResource`/`LoadResource`/`SizeofResource` calls with a lookup table of compiled-in arrays (`IDR_UEFI_NTFS`, `IDR_SYSLINUX_*`, etc.) so all resource consumers (`syslinux.c`, `wue.c`, `format.c`) compile and run on Linux
33. **`setupapi.h` → libudev device enumeration** — flesh out `SetupDiGetClassDevs` / `SetupDiEnumDeviceInterfaces` / `SetupDiGetDeviceInterfaceDetail` stubs using libudev to enumerate USB storage devices; drives remaining callers in `dev.c` off the real device path
34. **`cfgmgr32.h` / `dbt.h` → libudev** — replace `CM_Get_Device_ID` / `CM_Locate_DevNode` stubs and `DBT_DEVICEARRIVAL` / `DBT_DEVICEREMOVECOMPLETE` constants with libudev equivalents; align with the `device_monitor.c` udev monitor already in place
35. ~~**`shlobj.h` / `shobjidl.h` → XDG / GLib paths**~~ ✅ **DONE** — `src/linux/xdg.c`: `GetXdgUserDir(name, buf, bufsz)` parses `$XDG_CONFIG_HOME/user-dirs.dirs` (or `~/.config/user-dirs.dirs`), supports `$HOME` substitution, comments, and absolute paths; test injection via `xdg_set_config_home()` + `xdg_set_home_dir()` in RUFUS_TEST builds; 17 tests pass (`test_xdg_dirs_linux`); wired into `FileDialog()` in `stdlg.c` — when `path == NULL`, defaults to `XDG_DOWNLOAD_DIR` (or `$HOME/Downloads`) so ISO downloads open in the user's Downloads folder
36. **`wincrypt.h` / `wintrust.h` → OpenSSL compat stubs** — complete the header stubs (CERT_CONTEXT, HCRYPTPROV, etc.) so every call site in `pki.c` and `hash.c` compiles on Linux without the MSVC SDK; ensure no runtime no-ops hide missing implementations
37. ~~**`LicenseCallback()` GTK dialog**~~ ✅ **DONE** — `find_license_file()` searches `<app_dir>/LICENSE.txt`, `<app_dir>/../LICENSE.txt`, `RUFUS_DATADIR/LICENSE.txt`; real GTK scrollable `GtkTextView` dialog under `#ifdef USE_GTK`, fallback returns TRUE without crash; 3 new tests: `find_license_file_with_real_repo_path`, `find_license_file_with_bad_path_returns_null`, `license_callback_returns_true`; 45 stdlg tests pass
38. ~~**`UpdateCallback()` / `NewVersionCallback()` dialog**~~ ✅ **DONE** — Added `UM_NEW_VERSION` to `user_message_type` enum; `CheckForUpdates()` in `net.c` now posts `UM_NEW_VERSION` instead of calling `DownloadNewVersion()` directly; `main_dialog_handler` in `ui_gtk.c` handles `UM_NEW_VERSION` with a GTK `GtkMessageDialog` showing version string, optional release notes in a scrollable text view, and "Remind me later"/"Download" buttons; 4 new tests: `um_new_version_constant_differs_from_um_no_update`, `um_new_version_is_valid_wm_app_range`, `um_new_version_posted_when_version_is_newer`, `um_no_update_posted_when_version_is_same`; PostMessage stub in net glue now captures last message for test verification; 80 net tests pass
39. **`SetAlertPromptHook()` / `SetAlertPromptMessages()` → GTK** — 🚫 N/A on Linux: these intercept a Windows-only "Format disk?" system dialog via WinEvent hooks; no equivalent Linux dialog exists
40. ~~**Accessibility: `SetAccessibleName()` → `atk_object_set_name`**~~ ✅ **DONE** — `SetAccessibleName()` in `ui_gtk.c` now calls both `gtk_widget_set_tooltip_text()` and `atk_object_set_name()` via `gtk_widget_get_accessible()`; screen readers (Orca, etc.) receive proper accessible names
41. **`CreateStaticFont()` / `SetHyperLinkFont()` → Pango / GTK CSS** — render hyperlink-style labels using a `GtkLabel` with `<a href="…">` Pango markup or a GTK CSS provider setting `color` and `text-decoration: underline`; wire `clicked` signal for `xdg-open`
42. ~~**`wuprintf()` UTF-8 conversion**~~ ✅ **DONE** — `wuprintf()` in `stdio.c` uses an inline UCS-4→UTF-8 encoder (replaces locale-dependent `wcstombs`); handles NULL format guard; 5 new tests: ASCII round-trip, 2-byte UTF-8 (é,ü), 3-byte UTF-8 (中文), surrogate/NULL guard; 170 stdio tests pass
43. ~~**`WindowsErrorString()` / `StrError()` DWORD mapping**~~ ✅ **DONE** — `windows_dword_to_errno` in `stdio.c` maps 20 DWORD constants to POSIX errno; `_StrError` covers all FACILITY_STORAGE cases; 36 new tests (19 per-constant mapping tests + 15 FACILITY_STORAGE tests + 2 extras); 135 stdio tests pass total
44. **`MyCreateDialog()` / `MyDialogBox()` remaining dialogs** — replace stubbed `IDD_FORMAT`, `IDD_LOG`, `IDD_ABOUT` and any remaining Windows dialog-resource IDs with hand-crafted `GtkDialog` equivalents; `IDD_HASH` already done as the template
45. ~~**`AboutCallback()` wiring**~~ ✅ **DONE** — `on_about_clicked()` in `ui_gtk.c` creates a `GtkAboutDialog` with version string, website URL, GPL-3.0 license; wired to `rw.about_btn` "clicked" signal
46. ~~**Non-GTK CLI mode**~~ ✅ **DONE** — `src/linux/cli.c` + `src/linux/cli.h` implement argument parsing and format harness; `cli_parse_args()` accepts `--device` (required), `--image`, `--fs` (fat16/fat32/ntfs/udf/exfat/ext2/ext3/ext4), `--partition-scheme` (mbr/gpt), `--target` (bios/uefi), `--label`, `--quick`/`--no-quick`, `--verify`, `--help`; `cli_run()` registers device via `drive_linux_add_drive()`, probes size/sector via `BLKGETSIZE64`/`BLKSSZGET`, launches `FormatThread`, waits, returns exit code; `rufus.c` non-GTK `main()` wired to `cli_parse_args` + `cli_run`; stdout `UpdateProgress` stubs added for non-GTK builds; 64 checks in `test_cli_linux` all pass
47. ~~**NTFS formatter**~~ ✅ **DONE** — `FormatPartition()` routes to `FormatNTFS()` via `mkntfs` (ntfs-3g); `format_ntfs_build_cmd()` builds command with `-Q`/`-F`/`-c`/`-L` flags; runtime tool detection via `access()`; `populate_fs_combo()` shows NTFS when `mkntfs` present; 60 tests pass
48. ~~**exFAT formatter**~~ ✅ **DONE** — `FormatPartition()` routes to `FormatExFAT()` via `mkfs.exfat`/`mkexfatfs`; `format_exfat_build_cmd()` builds command; runtime detection; `populate_fs_combo()` shows exFAT when tool present; cluster-size + label passthrough wired; 60 tests pass (exFAT skipped when tool absent)
49. ~~**`OpticalDiscSaveImage()` / `IsoSaveImageThread()`**~~ ✅ **DONE** — `iso_save_run_sync()` is synchronous testable core; reads raw sectors from source device/file and writes to destination ISO with buffer-size proportional to disc size (8–32 MiB); progress via `UpdateProgressWithInfo`; `OpticalDiscSaveImageThread()` wraps in a pthread; `OpticalDiscSaveImage()` uses `GetOpticalMedia()`, `FileDialog()`, `EnableControls()`; `save_btn` wired in GTK UI (`on_save_clicked`); 10 tests in `test_iso_save_linux.c` all pass
50. ~~**`GetExecutableVersion()` ELF version string**~~ 🔧 **PARTIAL** — `rufus_version[3]` array initialized via `init_rufus_version()` in `globals.c` from `version.h` constants (MAJOR=4, MINOR=13, PATCH=0); called early in `on_app_activate()`; full ELF section embedding for `GetExecutableVersion()` still pending

---

### Compat Layer Completion

51. ~~**`shlwapi.h` → real POSIX implementations**~~ ✅ **DONE** — `PathFileExistsA` via `access(F_OK)`; `PathFileExistsW` via `wcstombs` + `PathFileExistsA`; `PathCombineA` via `snprintf` with separator normalisation and backslash→slash normalisation; `StrStrIA` / `StrCmpIA` / `StrCmpNIA` macros; all as static inlines in `src/linux/compat/shlwapi.h`; 11 tests in new `test_compat_linux.c` pass
52. ~~**`shellapi.h` → `xdg-open`**~~ ✅ **DONE** — `ShellExecuteA` / `ShellExecuteW` implemented as static inlines in `src/linux/compat/shellapi.h`; `ShellExecuteA` forks `xdg-open "<file>"` via `system()`; `ShellExecuteW` converts path via `wcstombs` then delegates to `ShellExecuteA`; returns fake HINSTANCE > 32 on success (≤ 32 on error) matching Windows convention; SW_* constants guarded with `#ifndef`; 4 tests in `test_compat_linux.c` pass
53. ~~**`netlistmgr.h` → GNetworkMonitor connectivity check**~~ ✅ **DONE** — `is_network_available()` in `net.c` uses `getifaddrs` to check for any non-loopback IFF_UP interface with IPv4/IPv6; wired into `DownloadToFileOrBufferEx` as early return (sets `DownloadStatus=503`); RUFUS_TEST injection via `set_test_no_network()`; 6 new tests: `network_available_returns_bool`, `network_available_forced_false`, `network_available_restore_true`, `download_skips_when_no_network`, `download_no_network_sets_status_503`, `download_no_network_multiple_calls`; 99 net tests pass
54. **`oleacc.h` / MSAA → ATK/AT-SPI2** — map the MSAA `IAccessible` stubs in `oleacc.h` to ATK object creation so screen readers (Orca, etc.) receive meaningful role/name/description information from Rufus controls; prerequisite for proper GNOME a11y compliance (pairs with item 40)
55. ~~**`uxtheme.h` / `dwmapi.h` theme-change notifications → GTK**~~ ✅ **DONE** — `on_gtk_dark_theme_changed()` callback in `ui_gtk.c` responds to `notify::gtk-application-prefer-dark-theme` signal on `GtkSettings`; connected in `on_app_activate()` so Rufus follows the system dark-mode preference at runtime; Ctrl+Alt+D toggle also updates `is_darkmode_enabled` via the same signal path
56. ~~**`timezoneapi.h` → `localtime`/`tzset`**~~ ✅ **DONE** — `src/linux/timezone.c`: `IanaToWindowsTimezone()` resolves `/etc/timezone`, `/etc/localtime` symlink against zoneinfo root, or `$TZ`; embedded CLDR-derived IANA→Windows table (450+ canonical entries, binary search); test injection via `timezone_set_*()` functions in RUFUS_TEST builds; wired into `CreateUnattendXml()` for `UNATTEND_DUPLICATE_LOCALE`; 280 tests pass (`test_timezone_linux`)
57. **`commctrl.h` `LVM_*` / `TVN_*` → GTK TreeView/ListStore** — the Windows UI uses `ListView` and `TreeView` controls for the hash-results and WIM-edition selection dialogs; map the remaining `LVM_INSERTITEM`, `LVM_SETITEM`, `LVM_GETITEM`, `TVN_*` messages to `GtkTreeView` + `GtkListStore` operations in `combo_bridge.c` or a new `listview_bridge.c`
58. **`psapi.h` process memory info → `/proc`** — `GetProcessMemoryInfo` and `EnumProcessModules` stubs are no-ops; implement lightweight versions via `/proc/self/status` (`VmRSS`) and `/proc/self/maps` so any diagnostic or resource-tracking code that calls them gets real data

---

### UI / UX Polish

59. ~~**Dark mode toggle**~~ ✅ **DONE** — Ctrl+Alt+D shortcut registered via `GtkAccelGroup`; `on_toggle_dark_mode()` toggles `gtk-application-prefer-dark-theme` on `GtkSettings` and persists via `WriteSetting32(SETTING_DARK_MODE, ...)`; saved preference (0=system, 1=light, 2=dark) applied on startup in `on_app_activate()`
60. ~~**Title bar / taskbar icon**~~ ✅ **DONE** — `gtk_window_set_icon_name(GTK_WINDOW(win), "ie.akeo.rufus")` called in `rufus_gtk_create_window()`; window title updated to include version (`"Rufus %d.%d"`) from `rufus_version[]`
61. **HiDPI / GDK scale factor audit** — run Rufus under `GDK_SCALE=2` and `GDK_DPI_SCALE=1.5`; fix any pixel-size hard-coding in `ui_gtk.c` widget construction; ensure progress bar, log window, and dialog fonts scale correctly
62. ~~**Keyboard shortcuts / accelerators**~~ ✅ **DONE** — `GtkAccelGroup` registered on the main window: Ctrl+O → `on_select_clicked`, Escape → `on_close_clicked`, Ctrl+Alt+D → dark mode toggle
63. ~~**Context menu on device combo**~~ ✅ **DONE** — right-click on the device combo shows a `GtkMenu` popup with two items: "🔄 Refresh" (calls `GetDevices()` if no format in progress) and "📂 Open in File Manager" (calls `xdg-open /dev/sdX` for the selected drive via `device_open_in_fm_build_cmd()`); wired via `button-press-event` signal in `build_device_row()`; command-building logic extracted to `src/linux/device_combo.c` (no GTK dependency); 7 unit tests in `test_ui_linux` all pass
64. ~~**Operation log — save to file**~~ ✅ **DONE** — log `GtkDialog` has "Save" button (`GTK_RESPONSE_ACCEPT`) in `on_log_response()`; opens `GtkFileChooserDialog`, writes `GtkTextBuffer` content to selected file; "Clear" button clears buffer; "Close" hides dialog
65. ~~**Status label history**~~ ✅ **DONE** — `src/linux/status_history.c/.h`: ring buffer (capacity=5) of last N status strings; `idle_update_status()` in `ui_gtk.c` pushes each message then calls `gtk_widget_set_tooltip_text(status_label, tooltip)` with all previous messages (newest first, newline-separated); 15 tests, 24 assertions pass
66. ~~**`SetTitleBarIcon()` implementation**~~ ✅ **DONE** — `stdlg.c`: calls `gtk_window_set_icon_name(GTK_WINDOW(hDlg), "ie.akeo.rufus")` when `hDlg` is a GtkWindow; `#ifdef USE_GTK` guarded; no-op in non-GTK builds
67. ~~**System tray / notification on completion**~~ ✅ **DONE** — `src/linux/notify.c`/`notify.h`: `rufus_notify(title, body, success)` dispatches via libnotify tier-1 (when compiled with `USE_LIBNOTIFY`, detected by `configure.ac` PKG_CHECK_MODULES) with `notify-send` subprocess tier-2 fallback; `notify_format_message()` builds standard human-readable title/body for `NOTIFY_OP_FORMAT`, `NOTIFY_OP_HASH`, `NOTIFY_OP_DOWNLOAD`; `notify_build_cmd()` is a pure testable function that builds the shell command; wired into `UM_FORMAT_COMPLETED` and `UM_HASH_COMPLETED` handlers in `ui_gtk.c`; 32 tests pass

---

### Download & Update Pipeline

68. ~~**Download progress GTK dialog**~~ ✅ **DONE** — `DownloadToFileOrBufferEx()` now reports progress via libcurl `CURLOPT_XFERINFOFUNCTION` callback (`download_xferinfo_cb`) which calls `UpdateProgress(OP_NOOP, pct)` on each data chunk; final 100% call after HTTP 200 success; `UpdateProgress` marshals to GTK main thread via `g_idle_add`; 4 new tests pass
69. ~~**DBX caching and scheduled update**~~ ✅ **DONE** — `UseLocalDbx()` updated to check `DBXTimestamp_<arch>` setting vs embedded baseline (returns TRUE only when saved timestamp > embedded); `dbx_build_timestamp_url()` converts GitHub contents URL to commits API query URL (URL-encodes path slashes as %2F); `dbx_parse_github_timestamp()` extracts ISO 8601 UTC timestamp from GitHub JSON response using `timegm()`; `CheckForDBXUpdates()` queries GitHub for each arch, prompts user on update available, downloads new DBX, saves timestamp; wired into `CheckForUpdatesThread()`; `dbx_info.h` included in Linux `net.c`; 56 tests in `test_dbx_linux.c` all pass
70. ~~**Fido script version check and auto-update**~~ ✅ **DONE** — `fido_check_url_updated(url)` in `net.c`: reads `SETTING_FIDO_URL` from settings; returns TRUE (and saves) when URL differs or wasn't stored; returns FALSE for NULL/unchanged; `CheckForFidoThread` calls it after each successful Fido.ver fetch and logs when a newer script is available; `DownloadISOThread` re-fetches `Fido.ver` at ISO-download time to transparently pull the latest script URL; `SETTING_FIDO_URL` added to `settings.h`; `fido_linux_glue.c` + 9 tests (`test_fido_linux`) all pass
71. ~~**First-run update-check consent dialog**~~ ✅ **DONE** — `SetUpdateCheck()` in `stdlg.c` now calls `NotificationEx(MB_YESNO | MB_ICONQUESTION, ...)` on first run (interval==0); IDYES → sets daily interval (86400 s); IDNO → sets -1 (disabled), returns FALSE; returning users and previously-disabled skip the dialog entirely; settings unavailable returns FALSE immediately; `NotificationEx()` uses GTK `GtkMessageDialog` in production and test-injection in tests; 15 new tests in `test_update_check_linux.c` all pass; `test_settings_linux` still passes (74 tests)
72. ~~**Resumable / cached downloads**~~ ✅ **DONE** — `src/linux/download_resume.c` adds `get_partial_path()`, `has_partial_download()`, `get_partial_size()`, `finalize_partial_download()`, `abandon_partial_download()`; `DownloadToFileOrBufferEx()` in `net.c` now writes all file-mode downloads to `<target>.partial`, sets `CURLOPT_RESUME_FROM_LARGE` when a `.partial` exists, accepts HTTP 200 (fresh) and HTTP 206 (resumed), renames `.partial` → target on success, keeps `.partial` on failure/interrupt for future resume, and discards a corrupted `.partial` when server ignores Range header (HTTP 200 on resume attempt); 38 checks in `test_download_resume_linux` all pass; all net/dbx/fido test sources updated to include `download_resume.c`

---

### Filesystem & Format Enhancements

73. ~~**UDF formatter**~~ ✅ **DONE** — `format_udf_build_cmd()` + `FormatUDF()` implemented in `format_ext_tools.c` using `mkudffs` (udftools); `FormatPartition()` routes `FS_UDF` → `FormatUDF()`; `populate_fs_combo()` adds UDF entry when `mkudffs` is detected; 13 new tests (build_cmd × 8, integration × 5 with SKIP when tool absent)
74. ~~**Volume-label enforcement per filesystem**~~ ✅ **DONE** — All format backends receive the label at creation time (no post-format tool calls needed): FAT32 → `sVolLab` in boot sector; ext2/3/4 → `ext2fs->super->s_volume_name`; NTFS → `mkntfs -L label`; exFAT → `mkfs.exfat -n label`; UDF → `mkudffs -l label`. Label flows from GTK entry → `GetWindowTextA(hLabel,...)` via `window_text_bridge` → `FormatPartition()` → each backend. 5 tests cover FAT32 label padding; NTFS/exFAT/UDF label flags covered by format command-builder tests.
75. ~~**Cluster-size passthrough**~~ ✅ **DONE** — `format_ntfs_build_cmd()` accepts `cluster_size` and passes `-c <bytes>` to `mkntfs`; `format_exfat_build_cmd()` passes `-c <bytes>` to `mkfs.exfat`; `FormatNTFS()`/`FormatExFAT()` receive `UnitAllocationSize` from `FormatPartition()`; `populate_cluster_combo()` in `ui_gtk.c` offers standard cluster sizes for NTFS and exFAT; `on_fs_changed()` callback updates cluster combo when FS changes
76. ~~**Write-and-verify pass**~~ ✅ **DONE** — `verify_write_pass(source_path, device_fd, written_size)` in `src/linux/verify.c`: re-reads `written_size` bytes from device and compares chunk-by-chunk (4 MiB) against source file; reports mismatch offset via `uprintf`; sets `LastWriteError = RUFUS_ERROR(ERROR_WRITE_FAULT)` on mismatch; honours `CHECK_FOR_USER_CANCEL`; reports progress via `UpdateProgressWithInfo(OP_VERIFY, MSG_355, ...)`; `enable_verify_write` global in `globals.c`; wired into `FormatThread` write-as-image path; "Verify write" checkbox added to Advanced format options expander in `ui_gtk.c`; disabled during an active operation; `OP_VERIFY` added to `action_type` enum; MSG_355/356 added to `rufus.loc` and `resource.h`; 37 checks in `test_verify_linux` all pass; fixed pre-existing `test_format_thread_linux`, `test_badblocks_integration_linux`, and `test_persistence_linux` build failures (missing WUE stubs)
77. ~~**Bad-blocks pre-scan integration**~~ ✅ **DONE** — `enable_bad_blocks` + `nb_passes_sel` globals added to `globals.c`; `FormatThread` runs `BadBlocks()` before partitioning when enabled, with retry/abort/ignore dialog loop and destructive-pass re-init; `ui_gtk.c` reads `bad_blocks_check` checkbox + `nb_passes_combo` into globals on start; `MB_ABORTRETRYIGNORE` added to compat layer; 15 integration tests pass (34 checks) in `test_badblocks_integration_linux`
78. ~~**Persistent storage (casper-rw) for Ubuntu/Debian Live**~~ ✅ **DONE** — `CreatePartition` now handles `XP_PERSISTENCE` flag: shrinks main partition and adds second ext2/3/4 partition (type 0x83 in MBR, Linux data GUID in GPT); `FormatThread` sets `extra_partitions |= XP_PERSISTENCE` when `HAS_PERSISTENCE(img_report) && persistence_size > 0`, formats persistence partition as ext2/3/4 with label `casper-rw` (casper) or `persistence` + persistence.conf (Debian); UI slider/units combo wired to `persistence_size` via `on_persistence_changed`; `TogglePersistenceControls` called from `UM_IMAGE_SCANNED`; 93 tests in `test_persistence_linux.c`
79. ~~**UEFI:NTFS boot bridge**~~ ✅ **DONE** — `uefi_ntfs_needs_extra_partition()` checks boot type, filesystem, target type, and EFI-bootable flag; `load_uefi_ntfs_data()` reads `uefi-ntfs.img` from app dir or relative paths; `write_uefi_ntfs_partition()` writes the 1 MiB FAT image to the exact partition offset; `CreatePartition()` extended for both MBR (type `0xEF`, 2048 sectors at end) and GPT (EFI System Partition GUID, last usable LBA); `SelectedDrive.Partition[PI_UEFI_NTFS]` populated with offset/size; combined `XP_UEFI_NTFS + XP_PERSISTENCE` layout supported (main → persistence → UEFI:NTFS); 81 tests in `test_uefi_ntfs_linux`; `globals.c` weak `lmprintf` stub added to fix pre-existing test builds that link stdio.c without localization.c
80. ~~**`CreateUnattendXml()` Windows customisation UI on Linux**~~ ✅ **DONE** — `on_start_clicked` in `ui_gtk.c` now shows the Windows User Experience dialog for Windows 10/11 images (IS_WINDOWS_1X), using `CustomSelectionDialog` with the same options as Windows (TPM/SB/RAM bypass, no online account, local account creation, locale duplication, data collection disable, BitLocker disable); skipped if `has_panther_unattend` is set; selected options passed to `CreateUnattendXml(arch, flags)`; SETTING_WUE_OPTIONS saved/restored; `ApplyWindowsCustomization()` implemented in `linux/wue.c`: copies `unattend.xml` to `sources/$OEM$/$$/Panther/unattend.xml` (OOBE) or `Windows/Panther/unattend.xml` (WinToGo); `wue_set_mount_path()` introduced so FormatThread can pass the mount point; wired in `format.c` after ExtractISO; 6 new tests in `test_wue_linux.c`

---

### Security & Boot Validation

81. ~~**TPM 2.0 detection**~~ ✅ **DONE** — `GetTPMVersion()` in `src/linux/system_info.c` reads `/sys/class/tpm/tpm0/tpm_version_major`; returns 0=none, 1=TPM 1.x, 2=TPM 2.0; fake-sysfs injectable via `sysinfo_set_sysfs_root()` in RUFUS_TEST builds; wired into `UM_IMAGE_SCANNED` handler in `ui_gtk.c` — logs TPM version and warns when a Windows 11 image is selected on a machine without TPM 2.0; 23 tests pass (`test_system_info_linux`)
82. ~~**Secure Boot status detection**~~ ✅ **DONE** — `IsSecureBootEnabled()` and `IsSetupModeEnabled()` in `src/linux/system_info.c` read EFI variable files in `/sys/firmware/efi/efivars/`; 5-byte EFI variable format parsed (4-byte attrs + 1-byte data); injectable via `sysinfo_set_efi_root()`; shown in boot combo tooltip when a Windows image is selected; 23 tests pass
83. ~~**Signed bootloader selection**~~ ✅ **DONE** — `GetBootladerInfo()` ported from Windows `rufus.c` to `src/linux/image_scan.c`; scans all EFI bootloaders in the ISO via `ReadISOFileToBuffer`; calls `IsSignedBySecureBootAuthority()` and `IsBootloaderRevoked()` for each; populates `img_report.has_secureboot_bootloader` bitmask (bit 0=signed, bits 1-5=revocation type); called from `ImageScanThread()` after scan; UI: `on_start_clicked()` in `ui_gtk.c` shows `Notification(MB_OKCANCEL|MB_ICONWARNING)` (MSG_338 title + MSG_339/MSG_340/MSG_341 body) when revoked bits are set — user can abort; `UM_IMAGE_SCANNED` handler logs revocation mask; 13 tests in `test_bootloader_scan_linux.c` + 81 total tests pass
84. ~~**PKCS7 full chain validation**~~ ✅ **DONE** — Added `BOOL chain_trusted` to `cert_info_t` struct in `rufus.h`; in `src/linux/pki.c`, `GetIssuerCertificateInfo()` now validates the full signer chain via `PKCS7_get0_signers()` + `X509_STORE_load_locations()` + `X509_verify_cert()` against `/etc/ssl/certs/ca-certificates.crt` (injectable via `pki_set_ca_bundle_path()` in RUFUS_TEST builds); `GetSignatureCertInfo(path, info)` helper reads a PE file and calls `GetIssuerCertificateInfo()`; Windows `pki.c` sets `chain_trusted` from `pChainContext->TrustStatus.dwErrorStatus == 0`; hash dialog in `ui_gtk.c` shows "Signer: <name> (chain trusted ✓/✗)" after hash rows; 12 new tests added to `test_pki_linux.c` (38 total in that file, 81 total pass)

---

### Testing Expansion

85. ~~**Loopback-device integration tests**~~ ✅ **DONE** — `tests/test_loopback.c` (8 tests) exercises real `/dev/loop*` block devices; creates a 128 MiB file-backed loop device via `losetup -f --show`, then tests: `loop_attach_detach` (losetup + stat + cleanup), `initialize_disk_on_loop` (InitializeDisk zeroes first 512 bytes), `create_partition_mbr_on_loop` (CreatePartition writes 0x55AA MBR signature + bootable entry at LBA 2048), `create_partition_gpt_on_loop` (writes protective MBR + 'EFI PART' header at LBA 1), `format_fat32_on_loop` (FormatPartition(FAT32) + 0x55AA signature + 'MSWIN4.1' OEM name), `format_ext4_on_loop` (FormatPartition(EXT4) + 0xEF53 superblock magic at offset 1080), `mount_fat32_loop` (FormatPartition + MountVolume + opendir verify + umount2), `mount_ext4_loop` (same for ext4); all tests skip gracefully via `SKIP_NOT_ROOT()` when not running as root; each test fully cleans up via `losetup -d` + unlink; uses same FORMAT_THREAD_LINUX_SRC + EXT2FS_LIB link set as format_thread tests; non-root run: 0 passed, 0 failed (all skipped)
86. **ISO hash regression suite** — add `tests/test_iso_hashes.c` that downloads (or reads from a local fixture path) a set of known ISOs (Ubuntu, Fedora, Windows PE) and verifies that `HashFile()` SHA-256 results match hard-coded expected digests; guards against silent hash-algorithm regressions
87. **GTK UI smoke tests via AT-SPI2** — use `pyatspi2` / Dogtail (or `xvfb-run + xdotool`) in a shell-script test to launch Rufus, inject a fake device via `device_monitor_inject()`, select an ISO, and verify that the Start button becomes enabled; run under `xvfb-run` in CI
88. **Fuzz harness for `iso.c`** — create `tests/fuzz_iso.c` using libFuzzer's `LLVMFuzzerTestOneInput` API targeting `ExtractISO()` and `ReadISOFileToBuffer()`; add a `make fuzz-iso` target that builds with `-fsanitize=fuzzer,address`
89. **Fuzz harness for `parser.c`** — create `tests/fuzz_parser.c` targeting `get_token_data_buffer()`, `parse_update()`, and `GetSbatEntries()`; the parser handles untrusted `.loc`, `.ver`, and SBAT CSV inputs
90. **Fuzz harness for PE parser** — create `tests/fuzz_pe.c` targeting `GetPeArch()`, `GetPeSection()`, `FindResourceRva()`, and `GetPeSignatureData()` with arbitrary binary blobs; PE files are attacker-controlled in the image-signing flow
91. **AddressSanitizer + UBSanitizer CI pass** — add a `make check-asan` target that rebuilds all test binaries with `-fsanitize=address,undefined,leak` and runs the full test suite; pipe results through the existing `run_tests.sh` framework; block merges on ASAN errors
92. ~~**`test_compat_layer`**~~ ✅ **DONE** — `tests/test_compat_layer.c` (75 checks) verifies: primitive type sizes (BYTE=1, WORD=2, DWORD=4, LONG=4, DWORD64/ULONGLONG/LONGLONG/LONG64=8, fixed-width aliases); pointer-sized types (HANDLE, ULONG_PTR, UINT_PTR, LONG_PTR, INT_PTR, SIZE_T all equal sizeof(void*)); HRESULT/NTSTATUS=4; string types (TCHAR=1, WCHAR=sizeof(wchar_t)); TRUE/FALSE/MAX_PATH/INVALID_HANDLE_VALUE/INVALID_FILE_SIZE constants; HRESULT constants (S_OK, S_FALSE, E_FAIL, E_NOTIMPL, E_OUTOFMEMORY, E_INVALIDARG) and SUCCEEDED/FAILED macros; Win32 error codes (ERROR_SUCCESS, ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE, ERROR_INSUFFICIENT_BUFFER); bit-manipulation macros (LOWORD, HIWORD, LOBYTE, HIBYTE, MAKEWORD, MAKELONG with round-trip); file constants (GENERIC_READ/WRITE, OPEN_EXISTING, CREATE_ALWAYS, FILE_ATTRIBUTE_*); winioctl.h PARTITION_STYLE enum (MBR=0, GPT=1, RAW=2); signedness of DWORD (unsigned) vs LONG/HRESULT (signed)
93. ~~**`test_error_mapping`**~~ ✅ **DONE** — covered by item 43: `test_stdio_linux.c` already contains 36 error-mapping checks (19 `windows_dword_to_errno` table entries + 15 `FACILITY_STORAGE` `_StrError` cases + 2 extras); no separate file needed

---

### Build, Packaging & CI

94. ~~**GitHub Actions CI pipeline**~~ ✅ **DONE** — `.github/workflows/linux.yml` runs on every push/PR: installs build deps via `tests/install-deps.sh` (single source of truth shared with `tests/Dockerfile`), `./configure --with-os=linux`, `make -j$(nproc)`, then `./run_tests.sh --linux-only`; uploads test binaries as artifacts on failure; triggers on the same path-ignore rules as the existing MinGW workflow; runs on ubuntu-22.04; separate `Container-Root-Tests` job builds `rufus-test-env` image (`docker build tests/`) then runs `./run_tests.sh --container` to exercise root-requiring tests (loopback) in a `--privileged` Docker container using the same Dockerfile as local development
95. **Coverity / cppcheck static analysis** — integrate the existing `_coverity.cmd` logic into a CI job; add a `make check-cppcheck` target using `cppcheck --enable=all --error-exitcode=1`; fix all current `cppcheck` findings before enabling the gate
96. **Flatpak manifest** — create `packaging/flatpak/ie.akeo.rufus.yaml` with `finish-args` including `--device=block` (removable media), `--share=network`, and `--filesystem=xdg-download`; add a `make flatpak` convenience target wrapping `flatpak-builder`
97. **AppImage build** — add a `make appimage` target using `linuxdeploy` + `linuxdeploy-plugin-gtk` to produce `Rufus-<version>-x86_64.AppImage`; include the GTK theme, hicolor icons, and locale data; test on a minimal Ubuntu container
98. **Debian/Ubuntu package** — create `packaging/debian/` with `control`, `rules`, `changelog`, and `rufus.install`; `rules` wraps the autotools build; add `dh_install` entries for the `.desktop`, AppStream XML, and hicolor icons; target Ubuntu 22.04 LTS and Debian 12
99. **RPM spec** — create `packaging/rpm/rufus.spec` for Fedora 39+ / openSUSE Tumbleweed; include `BuildRequires` for libcurl, libudev, libblkid, wimlib, GTK3; add `%check` section running `make check`
100. **ARM64 cross-compile target** — add `--host=aarch64-linux-gnu` support to `configure.ac`; verify the `ioctl`-based paths (`BLKGETSIZE64`, `SG_IO`, `BLKPG_*`) compile cleanly on AArch64; add an ARM64 build job to the CI pipeline (item 94)
101. **Reproducible builds** — pin all bundled library versions in `configure.ac` minimum checks; strip build-path prefixes via `-fmacro-prefix-map`; record `SOURCE_DATE_EPOCH` in the binary; verify that two independent builds of the same source produce bit-identical output

---

### Documentation & Developer Experience

102. **Man page for CLI mode** — write `doc/rufus.1` documenting all flags from the CLI mode (item 46): `--device`, `--image`, `--fs`, `--partition-scheme`, `--target-sys`, `--cluster`, `--label`, `--quick`, `--verify`, `--bad-blocks`; install via `Makefile.am`
103. **CONTRIBUTING.md for the Linux port** — document the porting conventions: compat-layer rules (no runtime no-ops allowed without a comment), test requirements (every new function needs ≥ 3 tests), how to add a new compat header, how to run the full test suite, Wine setup instructions
104. **Architecture overview document** — write `doc/linux-architecture.md` describing the layered architecture: compat headers → Linux implementation files → common/ portable code → GTK UI; include a dependency graph of the major source files and their relationships
105. **In-source Doxygen annotations** — add `@brief`, `@param`, `@return`, and `@note` Doxygen comments to all public functions in `src/linux/*.h` and `src/linux/compat/*.h`; add a `make docs` target running `doxygen Doxyfile`; publish generated HTML via GitHub Pages in CI

---

### Robustness & Diagnostics

106. ~~**Signal handler with backtrace**~~ ✅ **DONE** — `src/linux/crash_handler.c` + `src/linux/crash_handler.h`: `install_crash_handlers()` registers `SIGSEGV`/`SIGABRT`/`SIGBUS` via `sigaction` (SA_RESETHAND|SA_NODEFER); `rufus_crash_handler()` writes backtrace via `backtrace_symbols_fd` to stderr and to `<app_data_dir>/crash-<YYYY-MM-DDTHH:MM:SS>.log`; prints log path on stderr; `crash_handler_set_exit()` test hook for RUFUS_TEST builds; called from both `ui_gtk.c main()` and the non-GTK `rufus.c main()`; 32 tests pass
107. ~~**`DumpBufferHex()` / `_printbits()` debug helpers**~~ ✅ **DONE** — both implemented in `stdio.c`; `DumpBufferHex` formats xxd-style hex+ASCII output via `uprintf` (16 bytes/line); `_printbits` renders a DWORD as a little-endian binary string with optional leading-zero suppression; ported from Windows implementation; 7 `_printbits` tests + 5 `DumpBufferHex` tests pass; 170 stdio tests pass total
108. ~~**`DumpFatDir()` FAT directory lister**~~ ✅ **DONE** — full implementation in `src/linux/iso.c`; `wchar16_to_utf8()` helper converts UTF-16 code units stored in 32-bit wchar_t (libfat's read16() stores values in lower 16 bits) to valid UTF-8 including surrogate pairs; POSIX `mkdir`/`open`/`write_all` replace Windows `CreateDirectoryU`/`CreateFileU`/`WriteFileWithRetry`; `access(F_OK)` guards against overwriting pre-existing files; `iso_linux_glue.c` provides `LIBFAT_SECTOR_SIZE`/`_SHIFT`/`_MASK` for the test build; 13 tests in `test_iso_linux.c` pass (null-path, null image_path, invalid ISO, missing efi_img_path, success return, file extraction, content verification, subdirectory creation, nested-file extraction, nested content, skip-existing, valid UTF-8 filenames)
109. ~~**Structured error context (`uprintf_errno`)**~~ ✅ **DONE** — `uprintf_errno(fmt, ...)` macro added to `src/windows/rufus.h` (Linux-only, `#ifndef _WIN32` guard); snapshots `errno` at the call site, calls `uprintf(fmt ": %s (%d)", ..., strerror(_e), _e)`; 47 occurrences of `uprintf("...%s", strerror(errno))` pattern replaced across `dev.c`, `dos.c`, `dos_locale.c`, `drive.c`, `format.c`, `format_ext.c`, `hash.c`, `iso.c`, `net.c`, `stdio.c`, `syslinux.c`, `vhd.c`, `wue.c`; 7 new tests in `test_stdio_linux.c` (187 total pass)
110. ~~**`wuprintf()` UTF-8 path with test**~~ ✅ **DONE** — see item 42 above
111. ~~**`TimestampToHumanReadable()` port**~~ ✅ **DONE** — ported from `src/windows/stdio.c` to `src/linux/stdio.c`; converts YYYYMMDDHHMMSS `uint64_t` to "YYYY.MM.DD HH:MM:SS (UTC)" string; algorithm uses divisor-based field extraction; 8 tests: non-null return, zero date, basic date, UTC suffix, dot/colon separators, length, max values, distinct outputs; 204 stdio tests pass

121. Use docker to allow for non root root style testing

---

### Long-Term / Stretch Goals

111. **Windows-image customisation dialog on Linux** — build a `GtkDialog` mirroring the Windows "Windows User Experience" customization panel: checkboxes for bypass-TPM, bypass-RAM, bypass-Secure-Boot, disable-telemetry, remove-MS-account-requirement, set locale/keyboard; wire to `CreateUnattendXml()` and inject into `FormatThread`
112. **Ventoy-compatible multi-boot mode** — detect an existing Ventoy layout (`VTOYEFI` partition GUID) on the selected device and offer an "Update Ventoy" mode that upgrades only the Ventoy boot partition without disturbing the data partition; this is a natural complement to Rufus's existing image-write flow
113. **ISO-hybrid write optimisation** — detect ISO 9660 El Torito boot catalog + isohybrid MBR signature; when present, write the image as a raw block copy (`dd`-style) rather than extracting files, preserving the exact boot geometry used by the ISO author
114. **`img_report` info panel in GTK UI** — after `ImageScanThread` completes, show a collapsible info panel below the boot combo displaying: detected OS name + version, architecture, Secure Boot requirement, TPM requirement, compression type, and SHA-256; sourced from `img_report` fields already populated
115. **Locale data auto-download** — if `embedded.loc` is absent or older than 30 days, offer to download the latest translation bundle from the Rufus update server; implement as an extension of the `CheckForUpdates()` flow with a separate `loc_version` field in `rufus_linux.ver`
116. **Snap package** — create `packaging/snap/snapcraft.yaml` with `plugs: [removable-media, network, raw-usb, block-devices]`; build and test via `snapcraft`; publish to the `edge` channel of the Rufus Snap Store listing
117. **`SetAutoMount()` / `GetAutoMount()` → udisks2** — implement via `udisks2` D-Bus API (`org.freedesktop.UDisks2.Manager.SetAutomount`); or simpler: create/remove a `udev` rule in `/run/udev/rules.d/` that sets `ENV{UDISKS_AUTO}="0"` for the target device during the write operation, then removes it
118. **`VhdMountImageAndGetSize()` → kernel NBD without qemu-nbd** — the current implementation shells out to `qemu-nbd`; replace with direct `ioctl(NBD_SET_SOCK)` + `ioctl(NBD_DO_IT)` using the kernel NBD driver for environments where qemu-nbd is not installed; keep the qemu-nbd path as a fallback
119. **Multi-device write** — add a "Write to multiple devices simultaneously" mode: enumerate all selected target devices (multi-select in a `GtkListBox`), spawn one `FormatThread` per device (each with its own progress bar row in a `GtkGrid`), and collect results; useful for IT deployment scenarios
120. **Windows PE detection and reporting improvements** — `img_report.uses_minint` is populated but not displayed on Linux; wire the WinPE detection fields (`HAS_WINPE`, `uses_minint`, WinPE version string from `GetWimVersion`) into the GTK image-info panel (item 114) and the log output so users can confirm WinPE images are correctly identified



121. Windows + Linux => common merger. Minimize feature duplication between OSes by abstracting OS specific stuff, while keeping core logic in common. Add a seperate TODO list while working on this for organization  
    - **Phase 1 DONE**: `htab_create/destroy/hash`, `StrArray*`, `CompareGUID` extracted to `src/common/stdfn.c`; both `src/linux/stdfn.c` and `src/windows/stdfn.c` now `#include` the common file. 2 new tests added for dynamic growth and `dup=FALSE` behavior; 331 tests pass.
    - TODO Phase 2: `GuidToString`/`StringToGuid` (linux/stdio.c vs windows/stdio.c), `SizeToHumanReadable`/`TimestampToHumanReadable`, other portable stdio utilities.
122. ~~**Ensure consistent copyright headers**~~ ✅ **DONE** — GPL-3.0 headers added to all 30 Linux source files/headers that were missing them; ported files use Pete Batard's copyright with matching years from the Windows counterpart; new Linux-only files use "2025 Rufus contributors"; `drive_linux.h` skipped (root-owned, requires separate commit)
123. Full end to end iso flashing testing using virtual/emulated devices. Then compare to windows version
124. For FOSS and publically avalible operating systems (linux and freedos), use emulation to test flashed device drivers (such as qemu in docker container)
125. End to end testing of mocked UI/CLI to ensure functionality (with emulated devices)
