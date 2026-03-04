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
                             # works with docker, root podman, and rootless podman
                             # mirrors the GitHub CI environment exactly
```

The container image is defined in `tests/Dockerfile` (Ubuntu 22.04 + all build
and test dependencies pre-baked via `tests/install-deps.sh`).  After the first
build, repeated runs skip the apt-install layer and start immediately.

**Rootless podman** is handled automatically: the image is built with plain
`podman build`, then `podman image scp` copies it into root's podman store, and
the tests run under `sudo podman run --privileged` so that `/dev/loop*` devices
work.  The copy is skipped on subsequent runs when the image digest already
matches in both stores.

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
(default: auto-detected, docker preferred).  When rootless podman is detected
automatically the run step is transparently escalated via `sudo podman`.

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
| Non-GTK console fallback (`src/linux/rufus.c main()`) | ✅ | Full CLI mode via `cli.c`; `cli_parse_args` + `cli_run`; flags: `--device`, `--image`, `--fs`, `--partition-scheme`, `--target`, `--boot-type`, `--cluster-size`, `--persistence`, `--bad-blocks`, `--nb-passes`, `--unattend-xml`, `--include-hdds`, `--zero-drive`, `--force-large-fat32`, `--ntfs-compression`, `--win-to-go`/`-W`, `--write-as-image`/`-w`, `--fast-zeroing`/`-Z`, `--old-bios-fixes`/`-o`, `--allow-dual-uefi-bios`/`-A`, `--preserve-timestamps`/`-e`, `--validate-md5sum`/`-m`, `--no-rufus-mbr`/`-R`, `--no-extended-label`/`-x`, `--no-size-check`/`-s`, `--ignore-boot-marker`/`-I`, `--file-indexing`/`-n`, `--detect-fakes`/`-D`, `--expert-mode`/`-E`, `--usb-debug`/`-g`, `--enable-vmdk`/`-G`, `--advanced-format`/`-a`, `--list-devices`/`-L` (tab-sep drive table), `--json`/`-j`, `--label`, `--quick`/`--no-quick`, `--verify`, `--no-prompt`, `--version`, `--help`; all relevant globals wired via `cli_apply_options()`; `optind=0` re-entrant reset; `cli_print_devices()` calls `GetDevices(0)` + prints tab-separated drive table; 297 tests pass |

---

## 2. Compatibility Layer (`src/linux/compat/`)

These headers allow Windows source files to compile on Linux unchanged.

| Header | Status | Notes |
|--------|--------|-------|
| `windows.h` | 🔧 | ~1 800 lines; types, macros, most stubs present. `SendMessage`/`PostMessage` delegate to `msg_dispatch.c` bridge. `GetCurrentThreadId` returns real TID via `SYS_gettid`; `GetCurrentThread` returns pseudo-handle -2; `SetEnvironmentVariableA(NULL)` calls `unsetenv()` (Windows semantics); `GetSystemInfo` fills `dwNumberOfProcessors`/`dwPageSize`/`wProcessorArchitecture` from real OS; `GlobalMemoryStatusEx` reads `/proc/meminfo`; `MultiByteToWideChar`/`WideCharToMultiByte` size-query mode (sz=0) fixed; `InterlockedIncrement/Decrement/Exchange/CompareExchange` use GCC `__sync_*` — all tested |
| `GetWindowTextA` / `SetWindowTextA` | ✅ | Real implementation via `window_text_bridge` — thread-safe HWND→text registry; GTK main thread keeps cache in sync via "changed" signal; worker threads (FormatThread) read cache safely; `window_text_register_gtk()` wired in `ui_gtk.c` for volume-label entry; 20 tests, 30 assertions pass |
| `commctrl.h` | ✅ | Defines `PBS_MARQUEE`; CB_* macros live in `windows.h` and route through `combo_bridge.c` (105 tests pass) |
| `setupapi.h` | ✅ | Compilation stub only; Linux `dev.c` uses sysfs/libudev directly, not setupapi |
| `wincrypt.h` / `wintrust.h` | ✅ | Compilation stubs; Linux `hash.c` uses OpenSSL directly |
| `shlobj.h` / `shobjidl.h` | ✅ | `src/linux/xdg.c`: `GetXdgUserDir` parses `user-dirs.dirs`; 17 tests pass (item 35) |
| `cfgmgr32.h` | ✅ | Compilation stub; `device_monitor.c` handles device events via libudev netlink |
| `dbt.h` | ✅ | `UM_MEDIA_CHANGE` replaces `WM_DEVICECHANGE`; `device_monitor.c` handles all device events via libudev; 20 tests pass |
| `dbghelp.h` | 🚫 | Symbol walking — no Linux equivalent needed |
| `gpedit.h` | 🚫 | Group Policy — N/A on Linux |
| `delayimp.h` | 🚫 | Delay-load DLL mechanism — N/A on Linux |
| All others | 🔧 | Typedefs / empty stubs compile; `setupapi.h`, `wincrypt.h`, `wintrust.h` are compilation-only stubs (Linux code uses direct API calls) |
| `SendMessage` / `PostMessage` | ✅ | Full `msg_dispatch` bridge: thread-safe handler registry, async `PostMessage` via pluggable `MsgPostScheduler` (GTK: `g_idle_add`), synchronous `SendMessage` with pthread condvar blocking for cross-thread calls; 61 tests pass; GTK scheduler and main dialog handler registered in `ui_gtk.c` |
| `CreateThread` / `WaitForSingleObject` | ✅ | Full pthread bridge: threads, events (auto/manual-reset), mutexes, `CRITICAL_SECTION`, `WaitForMultipleObjects`, `GetExitCodeThread`, `TerminateThread` — 51 tests pass |
| Windows Registry (`RegOpenKey` etc.) | ✅ | Settings use INI-file backend via `src/linux/settings.h`; `ReadSetting*`/`WriteSetting*` macros map to `ReadIniKey*`/`WriteIniKey*`; 80 tests pass |
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
| `AnalyzeMBR()` / `AnalyzePBR()` | ✅ | Extracted to `src/common/drive.c`; ms-sys boot record analysis via FAKE_FD trick; unified impl honors `bSilent`, NULL TargetName guard, SectorSize=0 fallback; 39 tests pass |
| `GetDrivePartitionData()` | ✅ | Reads MBR/GPT partition table via libfdisk; populates PartitionStyle, nPartitions, etc. |
| `GetMBRPartitionType()` / `GetGPTPartitionType()` | ✅ | Lookup in `mbr_types.h` / `gpt_types.h` tables (no Windows dep); tests pass |
| `DeletePartition()` | ✅ | MBR+GPT table manipulation + `BLKPG_DEL_PARTITION` ioctl for real block devices; 42 tests pass |
| `SetAutoMount()` / `GetAutoMount()` | ✅ | udev rule `/run/udev/rules.d/99-rufus-noauto.rules` (UDISKS_AUTO=0, UDISKS_IGNORE=1); `udevadm control --reload-rules` on change; RUFUS_TEST path injection; 9 tests pass |
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
| `ExtractISO()` | ✅ | Full POSIX implementation using bundled libcdio; ISO9660 + UDF; scan + extract modes; label, block count, EFI detection; 6 tests pass |
| `ExtractISOFile()` | ✅ | Single-file extraction from ISO; UDF-first with ISO9660 fallback; 5 tests pass |
| `ReadISOFileToBuffer()` | ✅ | Reads file from ISO into malloc'd buffer; UDF-first with ISO9660 fallback; 6 tests pass |
| `is_in_md5sum()` / `md5sum_totalbytes` | ✅ | Tracks bytes of md5sum-listed files during extraction; only accumulates when validating an existing md5sum.txt (not when creating); 3 tests pass |
| `GetGrubVersion()` / `GetGrubFs()` / `GetEfiBootInfo()` | ✅ | Pure buffer scans for version strings and filesystem modules; 11 tests pass |
| `HasEfiImgBootLoaders()` | ✅ | Reads `img_report.efi_img_path`; 2 tests pass |
| `ImageScanThread()` | ✅ | `src/linux/image_scan.c`: calls `ExtractISO` (scan mode) + `IsBootableImage`; posts `UM_IMAGE_SCANNED`; wired from `on_select_clicked()`; 7 tests / 14 assertions pass |
| `iso9660_readfat()` | ✅ | Sector-reader callback for libfat; uses `iso9660_readfat_private` cache (16 ISO blocks); sector divisibility check; 5 tests pass |
| WIM FAT32 auto-split (`iso_check.c` — `has_4GB_file` path) | ✅ | Removed `#ifdef _WIN32` guard; `print_split_file` macro + `WimSplitFile` now run on both platforms; wimlib `open_iso_wim_file()` supports `"iso|path"` format on Linux; 3 new unit tests (print_split_file_restores_path, print_split_file_null_is_safe, wim_not_split_for_small_file) |
| `DumpFatDir()` | ✅ | Extracts FAT filesystem from EFI `.img` embedded in ISO; `wchar16_to_utf8()` converts UTF-16 code units (libfat stores 16-bit values in 32-bit wchar_t on Linux) to UTF-8; POSIX mkdir/open/write_all instead of Windows APIs; skips pre-existing files; 13 tests pass |
| `OpticalDiscSaveImage()` / `IsoSaveImageThread()` / `SaveImage()` | ✅ | Raw-copy optical disc to ISO using `open()`/`read()`/`write()` loop; `iso_save_run_sync()` is testable synchronous core; buffer sizing 8–32 MiB proportional to disc; progress via `UpdateProgressWithInfo`; `save_btn` wired in GTK UI; 10 tests pass |

### 3d. Hashing (`hash.c`)

| Function | Status | Notes |
|----------|--------|-------|
| MD5 / SHA-1 / SHA-256 / SHA-512 implementations | ✅ | All implemented in `src/windows/hash.c` in pure C — portable, just need to compile for Linux |
| `DetectSHA1Acceleration()` / `DetectSHA256Acceleration()` | ✅ | x86 CPUID check is platform-neutral; works on Linux |
| `HashFile()` / `HashBuffer()` | ✅ | Implemented in `src/linux/hash.c` with POSIX `open`/`read` |
| `HashThread()` / `IndividualHashThread()` | ✅ | Implemented with pthread via compat layer; 107 tests passing (3 new hash dialog tests) |
| `PE256Buffer()` / `efi_image_parse()` | ✅ | Extracted to `src/common/hash_pe.c` (shared by both platforms); helper structs and `efi_image_region_add`/`cmp_pe_section` included from same file; 9 tests pass |
| `IsFileInDB()` / `IsBufferInDB()` | ✅ | Extracted to `src/common/hash_db.c` along with `StringToHash`/`FileMatchesHash`/`BufferMatchesHash`; shared by both platforms |
| `IsSignedBySecureBootAuthority()` / `IsBootloaderRevoked()` | ✅ | Full OpenSSL-based implementation in `src/linux/hash.c`: DBX hash check (local file + EFI var at `/sys/firmware/efi/efivars/`), SBAT section check, cert revocation check, Secure Boot authority check; `IsRevokedBySvn()` fully implemented (item 126); 135 hash tests pass |
| `UpdateMD5Sum()` | ✅ | Reads md5sum.txt, recomputes MD5 for each `modified_files` entry, patches hex in-place, writes back; bootloader rename (`GetResource`/IDR_MD5_BOOT) is Windows-only and intentionally omitted; 4 tests pass |
| `ValidateMD5Sum` flag | ✅ | Respected by `UpdateMD5Sum`; `validate_md5sum` global wired |

### 3e. Networking (`net.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `DownloadToFileOrBufferEx()` | ✅ | libcurl implementation; file + buffer modes, HTTP status tracking, silent/noisy error, User-Agent; 45 tests pass |
| `IsDownloadable()` | ✅ | URL validation: http:// and https:// only; 45 tests pass |
| TLS / certificate verification | ✅ | `libcurl` + system CA bundle; CURLOPT_SSL_VERIFYPEER enabled by default |
| `DownloadSignedFile()` | ✅ | RSA-SHA256 signature verification implemented in `linux/net.c` via `ValidateOpensslSignature()` in `linux/pki.c`; 6 tests pass |
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
| `GetExecutableVersion()` | ✅ | `"RUFUS:VER:MAJOR.MINOR.PATCH\n"` marker embedded in .rodata; scanner in `linux/stdfn.c` reads `/proc/self/exe` (NULL) or any path; 20 tests pass |
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
| `FileDialog()` | ✅ | Test-injectable; GTK `GtkFileChooserNative` (GTK 3.20+) impl via `#ifdef USE_GTK` in `stdlg.c`; transparent Wayland XDG portal + X11 fallback; file filter support with ext list; test-mode extension matching; 56 tests pass |
| `NotificationEx()` / notification popups | ✅ | Test-injectable; GTK `GtkMessageDialog` impl via `#ifdef USE_GTK` in `stdlg.c`; maps MB_* flags to GTK message/button types; 36 tests pass |
| `CustomSelectionDialog()` | ✅ | GTK implementation: checkbox/radio-button grid GtkDialog; username_index creates inline GtkEntry; test-injectable; fallback returns mask; 40 tests pass |
| `ListDialog()` | ✅ | GTK implementation: scrollable GtkListBox dialog; non-GTK dumps to stderr; 40 tests pass |
| `CreateTooltip()` / `DestroyTooltip()` | ✅ | Uses `gtk_widget_set_tooltip_text` / `gtk_widget_set_has_tooltip`; `#ifdef USE_GTK` guard; 6 tests pass; wired into `on_app_activate` for device, boot, filesystem, cluster, label, select, start controls |
| `SetTaskbarProgressValue()` | 🚫 | Windows taskbar progress bar — not implemented; window title shows `(NN%)` instead (Feature 215) |
| `CreateAboutBox()` / `AboutCallback()` | ✅ | GTK About dialog implemented in `ui_gtk.c`; Windows `AboutCallback` stub unused (GTK handles this directly) |
| `LicenseCallback()` | ✅ | GTK scrollable GtkTextView dialog; `find_license_file()` searches app_dir; 3 tests pass (item 37) |
| `UpdateCallback()` / `NewVersionCallback()` | ✅ | `UM_NEW_VERSION` + GTK GtkMessageDialog with version string and release notes; 4 tests pass (item 38) |
| `SetFidoCheck()` / `SetUpdateCheck()` | ✅ | Both implemented: `SetFidoCheck` checks for pwsh, spawns `CheckForFidoThread` (downloads Fido.ver, validates URL, posts `UM_ENABLE_DOWNLOAD_ISO` to reveal Download ISO button); wired into `on_app_activate`; 57 net tests pass |
| `FlashTaskbar()` | ✅ | `gtk_window_set_urgency_hint` — flashes taskbar on operation complete (Feature 218) |
| `MyCreateDialog()` / `MyDialogBox()` | ✅ | `IDD_HASH` replaced with `UM_HASH_COMPLETED` → GTK dialog; other dialogs use native GTK equivalents; Windows dialog resource system is not used on Linux |
| `GetDialogTemplate()` | 🚫 | Windows `.rc` resource — not applicable on Linux |
| `SetAlertPromptHook()` / `SetAlertPromptMessages()` | 🚫 | Windows-only WinEvent hooks for system format dialogs — N/A on Linux |
| `CenterDialog()` / `ResizeMoveCtrl()` | 🚫 | GTK handles layout automatically |
| `CreateStaticFont()` / `SetHyperLinkFont()` | ✅ | CSM help ⓘ indicator with blue Pango markup; `SetHyperLinkFont` uses CSS label; 19 CSM tests pass (item 41) |
| `DownloadNewVersion()` | ✅ | Calls `xdg-open DOWNLOAD_URL` to open browser to Rufus downloads page |

### 3k. UI Logic (`ui.c` / `ui_gtk.c`)

| Function / Feature | Status | Notes |
|--------------------|--------|-------|
| GTK window and all widgets | ✅ | Window, all dropdowns, buttons, progress, log dialog |
| `EnableControls()` | ✅ | Disables/re-enables all input widgets |
| `EnableBootOptions` parity (`update_advanced_controls`) | ✅ | `src/linux/ui_enable_opts.c`: 5 pure-C predicates (`should_enable_old_bios`, `should_enable_uefi_validation`, `should_enable_extended_label`, `should_enable_quick_format`, `should_force_quick_format`); `update_advanced_controls()` wired into `on_boot_changed`, `on_fs_changed`, `on_target_changed`, `UM_IMAGE_SCANNED`; conditionally grays out UEFI-validation / old-BIOS-fixes / quick-format checkboxes based on image type, boot type, partition scheme and FS; 38 tests in `test_ui_enable_opts_linux.c` pass |
| `UpdateProgress()` / `_UpdateProgressWithInfo()` | ✅ | Thread-safe via `g_idle_add` |
| `InitProgress()` | ✅ | Resets progress bar |
| `TogglePersistenceControls()` | ✅ | Show/hide persistence row |
| `SetPersistencePos()` / `SetPersistenceSize()` | ✅ | Slider + label |
| `ToggleAdvancedDeviceOptions()` / `ToggleAdvancedFormatOptions()` | ✅ | GtkExpander expand/collapse |
| `ToggleImageOptions()` | ✅ | Show/hide image option row |
| Device combo population | ✅ | `combo_bridge.c`: full CB_* message dispatch for all combo boxes; `GetDevices()` populates device list via combo_bridge; 105 tests pass |
| Boot type combo population | ✅ | `populate_boot_combo()` adds Non-bootable/ISO Image/FreeDOS; wired in `combo_register_all()` |
| Partition scheme / target system / FS / cluster combos | ✅ | `ui_combo_logic.c`: `populate_fs_combo()`, `populate_cluster_combo()`, `SetFSFromISO()`, `SetPartitionSchemeAndTargetSystem()` — smart selection based on `img_report` + `boot_type`; no GTK dependency; wired into `on_device_changed()`, `on_boot_changed()`, `UM_IMAGE_SCANNED`; `SetComboEntry()` fixed to search by data value; 43 tests in `test_combo_logic_linux` pass; `on_start_clicked()` reads `hClusterSize` combo → `selected_cluster_size` so GTK UI cluster size selection is honoured by `FormatThread` |
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
| `SetDOSLocale()` | ✅ | Detects system XKB keyboard layout from /etc/default/keyboard (Debian/Ubuntu) and /etc/vconsole.conf XKBLAYOUT/KEYMAP (Fedora/RHEL/Arch); reads XKBVARIANT= alongside XKBLAYOUT= and returns combined "layout:variant" format (e.g. "ch:fr"); variant table overrides: Swiss French (ch+fr→sf), Serbian Latin (rs+latin→yu); KEYMAP= entries still strip variant suffixes (de-latin1→de); fixed rs/sr default → yc (Yugoslav Cyrillic) not ru/yu; fixed la=Laos→us (not Latin American), latam→la (correct Latin American Spanish); added at/au/ie/kg/kz/md/me/nz/za country mappings; maps to FreeDOS 2-letter code + OEM codepage; selects correct driver file (keyboard.sys/keybrd2.sys/keybrd3.sys); upgrades CP850→CP858 (Euro symbol); selects correct EGA/CPX font file; writes full AUTOEXEC.BAT with GOTO/codepage/keyb parity; human-readable keyboard/codepage names in FDCONFIG.SYS menu; US locale: AUTOEXEC.BAT only (no FDCONFIG.SYS); 127 total dos tests |
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
| `CreateUnattendXml()` | ✅ | POSIX + timezone from `IanaToWindowsTimezone()`; OOBE international locale via `GetOobeLocale()` (cross-platform: Linux reads `$LANG`+keyboard, Windows reads registry/LCIDs); `#ifdef _WIN32` removed from OOBE block in `common/wue.c`; `OobeLocale` struct and `GetOobeLocale()` in `src/common/oobe_locale.h`; 136 WUE + 16 oobe_locale_common + 85 locale_oobe tests pass |
| `SetupWinPE()` | ✅ | POSIX file copy + binary patching (CRC/path/rdisk patches) |
| `PopulateWindowsVersion()` | ✅ | wimlib + ezxml (cross-platform) |
| `CopySKUSiPolicy()` | 🚫 | Windows-only WDAC policy; stub returns FALSE |
| `SetWinToGoIndex()` / `SetupWinToGo()` | ✅ | `SetWinToGoIndex()`: wimlib + ezxml + `CustomSelectionDialog`; `SetupWinToGo()`: `WimApplyImage` + static BCD template (generated by `gen_bcd_template.py`) + EFI bootloader copy; fully wired into `format.c` FormatThread: WTG detection, XP_ESP\|XP_MSR partition creation (260 MB ESP + 128 MB MSR + main, GPT only), AltMountVolume → SetupWinToGo → AltUnmountVolume; 9 partition_ops tests + 3 format_thread integration tests |
| `ApplyWindowsCustomization()` | ✅ | POSIX file copy to Panther/OEM paths; boot.wim patching via wimlib_update_image + wimlib_overwrite; appraiserres.dll rename + empty placeholder |

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
| `SetAutorun()` | ✅ | Creates `autorun.inf` (`[autorun]\nicon=autorun.ico\nlabel=<label>`) for FAT/NTFS/exFAT drives (not ext2+); reads label from `hLabel` via `GetWindowTextA`; skipped for DD image writes; guarded by `use_extended_label` global; 12 unit tests in `test_icon_linux.c` (null path, creates file, content header/icon/comment, existing-file preservation, label from hLabel, empty label, success/fail cases) |
| IDC_EXTENDED_LABEL checkbox | ✅ | GTK checkbox in advanced format expander; toggles `use_extended_label` global; enable/disable logic driven by `should_enable_extended_label()`; 3 FormatThread integration tests in `test_format_thread_linux.c` |

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
| `stdfn.c` (htab, StrArray) tests | ✅ | 365 tests; htab_create/hash/destroy, StrArray, NULL guards, CompareGUID, IsCurrentProcessElevated, rufus_log_write, FileIO, GetWindowsVersion, isSMode, SetLGP/SetPrivilege/TakeOwnership stubs |
| `parser.c` / `localization.c` tests | ✅ | 111 tests covering replace_char, filter_chars, remove_substr, sanitize_label, ASN.1, GetSbatEntries, GetThumbprintEntries, open_loc_file, token CRUD, insert_section_data, replace_in_token_data |
| PE parsing functions tests | ✅ | 59 tests pass in `test_pe_parser_linux` |
| `msg_dispatch` (PostMessage/SendMessage bridge) tests | ✅ | 61 tests: handler registry, sync/async dispatch, cross-thread SendMessage, concurrent posts, macro aliases, UM_* constants |
| `common/device_monitor` (hotplug) tests | ✅ | 20 tests: lifecycle (start/stop/double/null), callback dispatch, debounce, thread safety, inject |
| `common/net` (IsDownloadable, DownloadToFileOrBufferEx) tests | ✅ | 45 tests; real libcurl downloads, file+buffer modes, HTTP status, User-Agent, 404 handling, binary data |
| `combo_bridge` (ComboBox message dispatch) tests | ✅ | 105 tests: lifecycle, all CB_* messages (ADDSTRING/RESETCONTENT/GETCURSEL/SETCURSEL/GETCOUNT/SETITEMDATA/GETITEMDATA/GETLBTEXT/GETLBTEXTLEN), capacity growth, GTK-free unit testing |
| `device_combo.c` (`device_open_in_fm_build_cmd`) tests | ✅ | 7 tests in `test_ui_linux.c`: basic, sdc, nvme, null path, empty path, buffer too small, null output buffer |
| `hyperlink.c` (`hyperlink_build_markup`) tests | ✅ | 7 tests in `test_ui_linux.c`: basic, null text falls back to url, XML escape, null url/buf/bufsz error cases, empty text |
| `proposed_label.c` (`get_iso_proposed_label`) tests | ✅ | 8 tests in `test_ui_linux.c`: all branches covered |
| `ntfsfix.c` (`RunNtfsFix`) tests | ✅ | 24 tests in `test_ntfsfix_linux.c`: null/empty path, command format + quoting, return values, hook replacement, overflow safety; `ntfsfix_set_system_hook()` added to `ntfsfix.c` |
| `dump_fat.c` (`DumpFatDir`) tests | ✅ | 15 tests in `test_dump_fat_linux.c` |
| `common/iso_report.c` (`log_iso_report`) parity | ✅ | Removed `#ifdef _WIN32` guards; 47 tests pass |
| `linux/locale_oobe.c` tests | ✅ | 85 tests in `test_locale_oobe_linux.c`; fixed `C.UTF-8` → `en-US` in `lang_to_bcp47()`; added `GetOobeLocale()` wrapper (2 tests) |
| `common/oobe_locale.h` cross-platform `GetOobeLocale()` | ✅ | Common struct + common interface; Linux impl wraps `GetLinuxOobeLocale()`; Windows impl reads registry + `LCIDToLocaleName`; 16 cross-platform tests in `test_oobe_locale_common.c` (Linux + Wine); `#ifdef _WIN32` removed from `common/wue.c` OOBE block |
| `common/timezone_name.h` cross-platform `GetLocalTimezone()` | ✅ | Common interface; Linux wraps `IanaToWindowsTimezone()`; Windows reads `GetTimeZoneInformation()`; 6 cross-platform tests in `test_timezone_common.c` (Linux + Wine); 3 new tests in `test_timezone_linux.c` (286 total); `#ifdef _WIN32` removed from `common/wue.c` timezone block; added `<TimeZone>` XML tests to WUE (140 total) |
| `common/stdfn.c` cross-platform tests | ✅ | 71 tests in `test_stdfn_common.c`; htab_create/hash/destroy, StrArrayAdd/AddUnique/Find/Destroy, CompareGUID — Linux + Wine |
| `common/xml.c` cross-platform tests | ✅ | 74 tests in `test_xml_common.c`; buffer-based ezxml parse/child/attr/sibling/idx/get_val/error/toxml/entity — Linux + Wine |
| `common/stdio.c` cross-platform tests | ✅ | 47 tests in `test_stdio_common.c`; GuidToString/StringToGuid/TimestampToHumanReadable — Linux + Wine |
| `common/wue.c` cross-platform tests | ✅ | 38 tests in `test_wue_common.c`; wue_compute_option_flags (all UNATTEND_* flag combinations, build gates, expert mode) — Linux + Wine; fixed `bypass_name[]` to have explicit size [3] for standalone compilation; added `unattend_username` extern declaration; added `#include "msapi_utf8.h"` to Win32 block |
| `common/iso_config.c` cross-platform tests | ✅ | 73 tests in `test_iso_config_common.c`; iso_patch_config_file — null guards, label replace (grub/syslinux/spaces), persistence (Ubuntu/Mint/Debian/size=0), RH8 stage2→repo, FreeNAS cd9660, Tails dual-BIOS copy, modified_files list, is_cfg=FALSE skip, BT_IMAGE guard, multi-occurrence replace — Linux + Wine; replace_char inlined to avoid common/parser.c PE-parsing header conflicts on MinGW |
| `common/iso_report.c` cross-platform tests | ✅ | 48 tests in `test_iso_report_common.c`; log_iso_report — label, size, Windows version, mismatch (truncated/larger), 4GB/long-filename/deep-dir flags, Syslinux/old-c32, KolibriOS/ReactOS/Grub4DOS/GRUB2, EFI (img/standard), Bootmgr (BIOS/UEFI/both), WinPE (i386/amd64/minint/minint-suffix), install.esd/wim, NTFS, symlinks, no-WinPE/no-wininst guards — Linux + Wine; all stubs inlined in test, no separate glue file needed |
| `parser.c` cross-platform tests | ✅ | 135 tests in `test_parser_common.c`; replace_char, filter_chars, remove_substr, sanitize_label, get_data_from_asn1, GetSbatEntries, GetThumbprintEntries, open_loc_file, get_supported_locales, get_loc_data_file (populates msg_table), get_token_data_file_indexed, set_token_data_file, get_token_data_buffer, insert_section_data, replace_in_token_data, parse_update_into — Linux + Wine; added parse_update_into() to windows/parser.c for parity |
| `ToLocaleName()` C.UTF-8 fix | ✅ | Fixed `linux/stdfn.c` `ToLocaleName()` to return `en-US` for `C.UTF-8` (was returning `"C"`); added `to_locale_name_c_utf8_locale` test (366 total) |
| TMPDIR override test | ✅ | Added `paths_temp_dir_respects_tmpdir_env` test to `test_settings_linux.c` (85 total) |
| Wine hash test expansion | ✅ | Expanded Wine `test_hash.exe` from 54 to 82 assertions: moved StringToHash (7 tests), FileMatchesHash (4 tests), PE256Buffer (5 tests), efi_image_parse (4 tests) outside `#ifdef __linux__`; made `make_ht_file()` cross-platform; replaced stub PE256Buffer in `hash_win_glue.c` with real `common/hash_pe.c` implementation |
| localization common tests | ✅ | New `test_localization_common.c` (68 assertions, Linux + Wine): `lmprintf` (4 tests: NULL table → UNTRANSLATED, format strings, out-of-range, rolling buffer), `get_locale_from_name` (5 tests), `get_locale_from_lcid` (4 tests), `toggle_default_locale` (2 tests), `get_name_from_id` (3 tests), `free_loc_cmd` null safety, `get_loc_dlg_count/entry` accessors, init/exit lifecycle |

---

## Pending Work

_(None — all features 188–224 are implemented and tested.)_
