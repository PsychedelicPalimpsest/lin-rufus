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

---

## 1. Build & Infrastructure

| Item | Status | Notes |
|------|--------|-------|
| Autotools configure (`--with-os=linux`) | ✅ | Produces a valid Linux build |
| MinGW cross-compile (`--with-os=windows`) | ✅ | Produces `rufus.exe` |
| Linux build script (`build-rufus-linux.sh`) | ✅ | |
| Windows cross-build script (`build-rufus-mingw.sh`) | ✅ | |
| Test system (`tests/`, `run_tests.sh`) | ✅ | Runs native + Wine |
| GCC 15 compound-literal regression fix in `cregex_compile.c` | ✅ | Static node lifetimes replaced with local vars |
| GTK3 UI backend (`-DUSE_GTK`) | ✅ | Window builds and launches |
| Non-GTK console fallback (`src/linux/rufus.c main()`) | 🔧 | Prints error and exits; no real CLI yet |

---

## 2. Compatibility Layer (`src/linux/compat/`)

These headers allow Windows source files to compile on Linux unchanged.

| Header | Status | Notes |
|--------|--------|-------|
| `windows.h` | 🔧 | ~1 200 lines; types, macros, most stubs present. `SendMessage`/`PostMessage` are no-ops — needs GTK dispatch integration |
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
| `DumpFatDir()` | 🟡 | Debug helper; stub returns FALSE; low priority |
| `OpticalDiscSaveImage()` / `IsoSaveImageThread()` / `SaveImage()` | 🟡 | Optical disc read; stub no-op; low priority |

### 3d. Hashing (`hash.c`)

| Function | Status | Notes |
|----------|--------|-------|
| MD5 / SHA-1 / SHA-256 / SHA-512 implementations | ✅ | All implemented in `src/windows/hash.c` in pure C — portable, just need to compile for Linux |
| `DetectSHA1Acceleration()` / `DetectSHA256Acceleration()` | ✅ | x86 CPUID check is platform-neutral; works on Linux |
| `HashFile()` / `HashBuffer()` | ✅ | Implemented in `src/linux/hash.c` with POSIX `open`/`read` |
| `HashThread()` / `IndividualHashThread()` | ✅ | Implemented with pthread via compat layer; 78 tests passing |
| `PE256Buffer()` / `efi_image_parse()` | ✅ | Pure C PE parsing ported from `src/windows/hash.c`; helper structs (`image_region`, `efi_image_regions`) and `efi_image_region_add`/`cmp_pe_section` added to `src/linux/hash.c`; 9 tests pass |
| `IsFileInDB()` / `IsBufferInDB()` | ✅ | Hash database lookup implemented in `src/linux/hash.c` |
| `IsSignedBySecureBootAuthority()` / `IsBootloaderRevoked()` | 🟡 | Needs cert DB + SBAT parsing; uses `pki.c` |
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
| `DownloadISO()` | 🟡 | Stub; Fido script launcher — needs `process.c` |
| `UseLocalDbx()` | 🟡 | Stub; use local DBX (revocation) database |
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
| `GetResource()` / `GetResourceSize()` | 🚫 | Windows PE resource API; resources are compiled into the binary — embed as C arrays or load from disk |
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
| `wuprintf()` | 🔧 | `wchar_t` print; works but GTK uses UTF-8 — may need conversion |
| `uprint_progress()` | ✅ | Calls `_UpdateProgressWithInfo(OP_FORMAT, ...)` when max > 0 |
| `read_file()` / `write_file()` | ✅ | Work correctly |
| `DumpBufferHex()` | 🟡 | Debug helper; low priority |
| `_printbits()` | 🟡 | Debug helper; low priority |
| `WindowsErrorString()` / `StrError()` | 🔧 | Maps to `strerror()`; works, but DWORD error codes from compat layer may not match `errno` values |
| `ExtractZip()` | ✅ | See stdfn above (bled-based implementation) |

### 3j. Standard Dialogs (`stdlg.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `FileDialog()` | ✅ | Test-injectable stub; returns preset path or NULL in tests; GTK impl in `stdlg_gtk.c` (pending) |
| `NotificationEx()` / notification popups | ✅ | Test-injectable; logs to stderr in non-GTK mode; GTK `GtkMessageDialog` impl pending |
| `CustomSelectionDialog()` | ✅ | Test-injectable; returns preset mask in tests; GTK impl pending |
| `ListDialog()` | ✅ | Dumps to stderr in non-GTK; test-mode no-op |
| `CreateTooltip()` / `DestroyTooltip()` | ✅ | Uses `gtk_widget_set_tooltip_text` / `gtk_widget_set_has_tooltip`; `#ifdef USE_GTK` guard; 6 tests pass |
| `SetTaskbarProgressValue()` | 🚫 | Windows taskbar — N/A; could map to GTK window urgency hint |
| `CreateAboutBox()` / `AboutCallback()` | 🔧 | GTK About dialog implemented in `ui_gtk.c`; callback stub unused |
| `LicenseCallback()` | 🟡 | Show license in a `GtkDialog` |
| `UpdateCallback()` / `NewVersionCallback()` | 🟡 | Update dialog; low priority |
| `SetFidoCheck()` / `SetUpdateCheck()` | ✅ | `SetUpdateCheck` implemented: settings commcheck roundtrip; first-run sets 86400s interval; disabled if interval<0; wired into `on_app_activate` GTK startup; 4 tests pass |
| `FlashTaskbar()` | 🚫 | N/A on Linux |
| `MyCreateDialog()` / `MyDialogBox()` | 🟡 | Windows dialog resource system; replace with GTK `GtkDialog` builders |
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
| On-START → `FormatThread` launch | ✅ | `on_start_clicked()` reads combo selections into globals (fs_type, partition_type, target_type, boot_type) then launches FormatThread with drive index |
| Cancel in-progress operation | ✅ | `on_close_clicked` sets `ErrorStatus = RUFUS_ERROR(ERROR_CANCELLED)` |
| Language menu (`ShowLanguageMenu`) | ✅ | Builds GTK menu from `locale_list`; activates via `PostMessage → main_dialog_handler` |
| `SetAccessibleName()` | 🔧 | Maps to tooltip; should use `atk_object_set_name` for true accessibility |
| Device-change notification (hot-plug) | 🟡 | Windows uses `WM_DEVICECHANGE`; Linux needs `udev` monitor in a thread |
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
| GRUB support | 🔧 | MBR boot code written via `write_grub2_mbr` (ms-sys); `InstallGrub2` calls `grub-install --target=i386-pc` for core.img install on BIOS-boot GRUB2 ISOs; wired into FormatThread after ExtractISO; 3 tests pass. GRUB4DOS: MBR-only (grldr copy not yet wired). UEFI GRUB: works via EFI files extracted by ISO extraction |

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

All functions are no-ops on Linux — correct.  GTK theming handles dark mode automatically via `GTK_THEME` / `prefer-dark-appearance` setting.

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
| Root-required operations (device open, raw write) | 🟡 | Either run entire app as root, or use `pkexec` / `polkit` for individual operations |
| `polkit` integration | ❌ | Preferred for desktop integration; not yet started |

---

## 7. Embedded Resources

| Item | Status | Notes |
|------|--------|-------|
| `GetResource()` — Windows PE resources | 🚫 | PE resource section not available on ELF Linux binary |
| Embedded locale data (`res/loc/embedded.loc`) | ✅ | `find_loc_file()` searches `app_dir/res/loc/embedded.loc`, `app_dir/embedded.loc`, `RUFUS_DATADIR/embedded.loc`; loaded in `on_app_activate()`; 7 new tests in `test_parser` (get_supported_locales + get_loc_data_file) pass |
| Embedded FreeDOS / MS-DOS boot files | 🟡 | Same — embed as binary arrays or install to `$datadir` |
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
11. ~~**Hashing** (`hash.c`)~~ ✅ **DONE** — all hash algorithms + HashThread/IndividualHashThread; 78 tests pass
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
