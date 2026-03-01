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

---

## 3. Core Business Logic

### 3a. Device Enumeration (`dev.c` / `drive.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `GetDevices()` | ✅ | sysfs scan: removable flag, size, vendor/model; sorted by size; 79 tests pass |
| `CycleDevice()` / `CyclePort()` | 🟡 | Stub; needed to refresh the device dropdown |
| `ClearDrives()` | ✅ | Frees rufus_drive[] strings and zeros the array |
| `GetPhysicalName()` | 🟡 | Should return `/dev/sdX` path |
| `GetPhysicalHandle()` | 🟡 | Should open `/dev/sdX` with `O_RDWR` |
| `GetLogicalName()` / `GetLogicalHandle()` | 🟡 | Should return/open `/dev/sdXN` |
| `GetDriveSize()` | 🟡 | `ioctl(BLKGETSIZE64)` |
| `GetDriveLabel()` | 🟡 | `blkid_get_tag_value()` |
| `IsMediaPresent()` | 🟡 | `stat()` or `ioctl` |
| `GetDriveTypeFromIndex()` | 🟡 | `udev` property `ID_USB` |
| `GetDriveLetters()` / `GetUnusedDriveLetter()` | 🚫 | Drive letters are Windows-only; adapt callers to use mount points |
| `MountVolume()` / `UnmountVolume()` | 🟡 | `udisks2` D-Bus API or `mount(2)` / `umount(2)` |
| `AltMountVolume()` / `AltUnmountVolume()` | 🟡 | Same as above |
| `RemoveDriveLetters()` | 🚫 | N/A on Linux |
| `CreatePartition()` | 🟡 | `ioctl(BLKPG_ADD_PARTITION)` or call `sfdisk` |
| `InitializeDisk()` | 🟡 | Write fresh MBR/GPT with `libfdisk` |
| `RefreshDriveLayout()` / `RefreshLayout()` | 🟡 | `ioctl(BLKRRPART)` |
| `AnalyzeMBR()` / `AnalyzePBR()` | 🟡 | Read first sector and inspect signature |
| `GetDrivePartitionData()` | 🟡 | Parse partition table via `libfdisk` or `/proc/partitions` |
| `GetMBRPartitionType()` / `GetGPTPartitionType()` | 🟡 | Look up type in local table (no Windows dep) |
| `DeletePartition()` | 🟡 | `ioctl(BLKPG_DEL_PARTITION)` |
| `SetAutoMount()` / `GetAutoMount()` | 🚫 | Windows auto-mount concept; Linux equivalent is `udisks2` policy |
| `GetOpticalMedia()` | 🟡 | Scan `/dev/sr*` |
| `ClearDrives()` | ✅ | Done (part of GetDevices implementation) |
| `IsMsDevDrive()` | 🚫 | Windows Dev Drive feature; always return FALSE |
| `IsFilteredDrive()` | 🟡 | May need per-device filtering for safety |
| `IsVdsAvailable()` / `ListVdsVolumes()` / `VdsRescan()` | 🚫 | VDS is Windows-only |
| `ToggleEsp()` / `GetEspOffset()` | 🟡 | Set ESP partition type flag via `libfdisk` |

### 3b. Formatting (`format.c`, `format_fat32.c`, `format_ext.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `FormatThread()` (main format worker) | 🟡 | 2 060-line Windows impl; needs pthread + Linux syscalls throughout |
| `FormatPartition()` | 🟡 | Call `mkfs.*` or format libs directly |
| `WritePBR()` (partition boot record) | 🟡 | Write boot sector bytes via `pwrite(2)` |
| `FormatLargeFAT32()` | 🟡 | Windows impl is self-contained; port format loop, remove Win32 I/O |
| `FormatExtFs()` | 🟡 | Uses bundled `ext2fs` lib (already compiles); just needs real block device handle |
| `error_message()` / `ext2fs_print_progress()` | 🟡 | Trivial wrappers once ext2fs is wired |
| `GetExtFsLabel()` | 🟡 | `ext2fs_get_label()` |
| Quick format vs. full zero-wipe | ❌ | Write-zero loop via `pwrite` for full format |
| Progress reporting from format thread | 🟡 | Route through `UpdateProgress()` → GTK idle |

### 3c. ISO / Image Handling (`iso.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `ExtractISO()` | 🟡 | Uses bundled `libcdio`; needs real file I/O and thread |
| `ExtractISOFile()` | 🟡 | Single-file extraction from ISO |
| `ReadISOFileToBuffer()` | 🟡 | Same |
| `iso9660_readfat()` | 🟡 | FAT-within-ISO reader; tied to `syslinux/libfat` |
| `HasEfiImgBootLoaders()` | 🟡 | Scan ISO for EFI images |
| `GetGrubVersion()` / `GetGrubFs()` / `GetEfiBootInfo()` | 🟡 | Parse version strings from ISO files |
| `DumpFatDir()` | 🟡 | Debug helper; low priority |
| `OpticalDiscSaveImage()` / `IsoSaveImageThread()` / `SaveImage()` | 🟡 | Optical disc read; use `libcdio` / `dd` |

### 3d. Hashing (`hash.c`)

| Function | Status | Notes |
|----------|--------|-------|
| MD5 / SHA-1 / SHA-256 / SHA-512 implementations | ✅ | All implemented in `src/windows/hash.c` in pure C — portable, just need to compile for Linux |
| `DetectSHA1Acceleration()` / `DetectSHA256Acceleration()` | 🔧 | x86 CPUID check is platform-neutral; already works on Linux once compiled properly |
| `HashFile()` / `HashBuffer()` | 🟡 | Need real Linux file I/O (`open`/`read`) instead of `CreateFile`/`ReadFile` |
| `HashThread()` / `IndividualHashThread()` | 🟡 | Need pthread wrapper instead of `CreateThread` |
| `PE256Buffer()` / `efi_image_parse()` | 🟡 | PE parsing is pure C; remove Windows I/O |
| `IsFileInDB()` / `IsBufferInDB()` | 🟡 | Hash database lookup — pure C once I/O is sorted |
| `IsSignedBySecureBootAuthority()` / `IsBootloaderRevoked()` | 🟡 | Needs cert DB + SBAT parsing; uses `pki.c` |
| `UpdateMD5Sum()` | 🟡 | Write `md5sum`-compatible file on the target drive |
| `ValidateMD5Sum` flag | 🟡 | Validate checksums after write |

### 3e. Networking (`net.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `DownloadToFileOrBufferEx()` | 🟡 | 1 042-line Windows impl uses `WinInet`; replace with `libcurl` |
| `DownloadSignedFile()` / `DownloadSignedFileThreaded()` | 🟡 | Wraps `DownloadToFileOrBufferEx` + signature check |
| `CheckForUpdates()` | 🟡 | Fetches update JSON; needs `libcurl` + `parser.c` |
| `DownloadISO()` | 🟡 | Fido script launcher; needs `process.c` + `libcurl` |
| `UseLocalDbx()` | 🟡 | Use local DBX (revocation) database |
| `IsDownloadable()` | 🟡 | URL validation; trivial once `libcurl` is available |
| TLS / certificate verification | 🟡 | WinInet handles this on Windows; `libcurl` + system CA bundle on Linux |

### 3f. PKI / Certificates (`pki.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `ValidateSignature()` | 🟡 | Uses `WinTrust` on Windows; replace with OpenSSL `PKCS7_verify` |
| `ValidateOpensslSignature()` | 🟡 | Already calls OpenSSL — just needs linking |
| `GetSignatureName()` / `GetSignatureTimeStamp()` | 🟡 | Parse Authenticode; use OpenSSL ASN.1 parser |
| `GetIssuerCertificateInfo()` | 🟡 | OpenSSL `X509_*` |
| `ParseSKUSiPolicy()` | 🟡 | Read Windows policy XML; pure `xml.c` |
| `WinPKIErrorString()` | 🟡 | Map OpenSSL errors |

### 3g. Process Management (`process.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `EnablePrivileges()` | 🔧 | Returns TRUE on Linux (root check is in `stdfn.c`); adequate for now |
| `GetPPID()` | 🟡 | Read `/proc/PID/status` |
| `StartProcessSearch()` / `SetProcessSearch()` | 🟡 | Used to detect open handles to the target drive; replace with `lsof` / `/proc` scan |
| `SearchProcessAlt()` | 🟡 | Same |
| `PhEnumHandlesEx()` / `PhOpenProcess()` | 🚫 | NT internal APIs; not applicable on Linux |
| `NtStatusError()` | 🚫 | NT status codes; not applicable |
| `RunCommandWithProgress()` (in `stdfn.c`) | 🟡 | Spawn subprocess and read stdout; use `posix_spawn` + pipes |

### 3h. Standard Functions / Utilities (`stdfn.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `htab_create()` / `htab_destroy()` / `htab_hash()` | ✅ | Full implementation ported from Windows stdfn.c; 299 tests pass |
| `StrArray*` functions | ✅ | Implemented and work |
| `FileIO()` | 🟡 | Read/write whole file; trivial with POSIX `fopen` |
| `GetResource()` / `GetResourceSize()` | 🚫 | Windows PE resource API; resources are compiled into the binary — embed as C arrays or load from disk |
| `SetLGP()` / `SetLGPThread()` | 🚫 | Windows Group Policy — no Linux equivalent |
| `MountRegistryHive()` / `UnmountRegistryHive()` | 🚫 | Windows Registry — no Linux equivalent |
| `TakeOwnership()` | 🚫 | Windows ACL — no Linux equivalent; use `chown` if ever needed |
| `SetPrivilege()` | 🚫 | Windows token privilege — no Linux equivalent |
| `SetThreadAffinity()` | 🟡 | Use `pthread_setaffinity_np()` |
| `GetWindowsVersion()` | 🚫 | N/A; return zeroed struct (done) |
| `GetExecutableVersion()` | 🟡 | Read `ELF` / PE version; low priority |
| `IsFontAvailable()` | 🟡 | Use `pango_font_description_from_string` or `fontconfig` |
| `ToLocaleName()` | 🟡 | Map locale code to BCP-47 string |
| `IsCurrentProcessElevated()` | ✅ | Returns `geteuid() == 0` |
| `isSMode()` | 🚫 | Windows S Mode — always FALSE |
| `ExtractZip()` | 🟡 | Use `libzip` or `libarchive` |
| `ListDirectoryContent()` | 🟡 | Use POSIX `opendir` / `readdir` |
| `WriteFileWithRetry()` | 🟡 | Use `pwrite` with retry loop |
| `ResolveDllAddress()` | 🚫 | DLL delay-load — N/A on Linux |
| `WaitForSingleObjectWithMessages()` | 🟡 | Needs pthread condvar or `poll()` loop |
| `CreateFileWithTimeoutThread()` | 🟡 | Use `open()` with `O_NONBLOCK` + `alarm` |

### 3i. Standard I/O (`stdio.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `uprintf()` / `uprintfs()` | 🔧 | Writes to `stderr`; should route to GTK log widget in GUI mode |
| `wuprintf()` | 🔧 | `wchar_t` print; works but GTK uses UTF-8 — may need conversion |
| `uprint_progress()` | 🟡 | Needs to update progress bar |
| `read_file()` / `write_file()` | ✅ | Work correctly |
| `DumpBufferHex()` | 🟡 | Debug helper; low priority |
| `_printbits()` | 🟡 | Debug helper; low priority |
| `WindowsErrorString()` / `StrError()` | 🔧 | Maps to `strerror()`; works, but DWORD error codes from compat layer may not match `errno` values |
| `ExtractZip()` | 🟡 | See stdfn above |

### 3j. Standard Dialogs (`stdlg.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `FileDialog()` | 🟡 | Needs GTK `GtkFileChooserDialog` (SELECT button partially wired in `ui_gtk.c`) |
| `NotificationEx()` / notification popups | 🟡 | Use `GtkMessageDialog` |
| `CustomSelectionDialog()` | 🟡 | Use `GtkDialog` with dynamic buttons |
| `ListDialog()` | 🟡 | Use `GtkDialog` + `GtkTreeView` |
| `CreateTooltip()` / `DestroyTooltip()` | 🟡 | Use `gtk_widget_set_tooltip_text` |
| `SetTaskbarProgressValue()` | 🚫 | Windows taskbar — N/A; could map to GTK window urgency hint |
| `CreateAboutBox()` / `AboutCallback()` | 🔧 | GTK About dialog implemented in `ui_gtk.c`; callback stub unused |
| `LicenseCallback()` | 🟡 | Show license in a `GtkDialog` |
| `UpdateCallback()` / `NewVersionCallback()` | 🟡 | Update dialog; low priority |
| `SetFidoCheck()` / `SetUpdateCheck()` | 🟡 | Fido / update check UI toggle |
| `FlashTaskbar()` | 🚫 | N/A on Linux |
| `MyCreateDialog()` / `MyDialogBox()` | 🟡 | Windows dialog resource system; replace with GTK `GtkDialog` builders |
| `GetDialogTemplate()` | 🚫 | Windows `.rc` resource — not applicable on Linux |
| `SetAlertPromptHook()` / `SetAlertPromptMessages()` | 🟡 | Alert interception; GTK equivalent needed |
| `CenterDialog()` / `ResizeMoveCtrl()` | 🚫 | GTK handles layout automatically |
| `CreateStaticFont()` / `SetHyperLinkFont()` | 🟡 | Use Pango / CSS for hyperlink styling |
| `DownloadNewVersion()` | 🟡 | Launch browser or download via `net.c` |

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
| Device combo population | 🟡 | Calls `GetDevices()` which is a stub |
| Boot type combo population | 🟡 | Needs to match Windows boot type enum |
| Partition scheme / target system / FS / cluster combos | 🟡 | Values hardcoded; need to be driven by device selection logic |
| On-START → `FormatThread` launch | 🟡 | Format thread not wired (`format_thread` unused) |
| Cancel in-progress operation | 🟡 | `TODO` in `on_close_clicked` |
| Language menu (`ShowLanguageMenu`) | 🟡 | `TODO` in `ui_gtk.c:718` — build GTK popover from `locale_list` |
| `SetAccessibleName()` | 🔧 | Maps to tooltip; should use `atk_object_set_name` for true accessibility |
| Device-change notification (hot-plug) | 🟡 | Windows uses `WM_DEVICECHANGE`; Linux needs `udev` monitor in a thread |
| `SetComboEntry()` | ✅ | |
| DPI scaling / `AdjustForLowDPI()` | ✅ | GTK handles natively |
| Window positioning / `CenterDialog()` | 🚫 | GTK manages automatically |
| `OnPaint()` | 🚫 | GTK/cairo handles all drawing |

### 3l. Localization (`localization.c`, `parser.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `get_supported_locales()` | 🟡 | Parse `.loc` file list; `parser.c` is stubbed |
| `get_loc_data_file()` | 🟡 | Load locale data from embedded or on-disk `.loc` file |
| `dispatch_loc_cmd()` | 🟡 | Apply locale string to GTK widget by ID |
| `lmprintf()` | 🟡 | Look up message in current locale table; trivial once tables are populated |
| `PrintStatusInfo()` | 🟡 | Route through `uprintf` + GTK status label |
| `apply_localization()` / `reset_localization()` | 🟡 | Set widget labels for a dialog |
| `get_locale_from_lcid()` / `get_locale_from_name()` | 🟡 | Look up in `locale_list` |
| `toggle_default_locale()` | 🟡 | Switch between user locale and English |
| `get_token_data_file_indexed()` / `set_token_data_file()` | 🟡 | INI-style token parser; mostly portable |
| `get_token_data_buffer()` | 🟡 | Same |
| `insert_section_data()` / `replace_in_token_data()` | 🟡 | String manipulation; portable |
| `replace_char()` / `filter_chars()` / `remove_substr()` | 🟡 | Portable string utils |
| `parse_update()` | 🟡 | Parse update JSON / INI |
| `get_data_from_asn1()` | 🟡 | ASN.1 parser for certificates; use OpenSSL |
| `sanitize_label()` | 🟡 | Sanitize volume label characters |
| `GetSbatEntries()` / `GetThumbprintEntries()` | 🟡 | Parse SBAT level / thumbprint text |
| `GetPeArch()` / `GetPeSection()` / `RvaToPhysical()` / `FindResourceRva()` / `GetPeSignatureData()` | 🟡 | PE binary parsing; pure C, no Windows deps |
| `GetPeSignatureData()` | 🟡 | Used for Secure Boot signature extraction |

### 3m. DOS / Syslinux / Bootloader (`dos.c`, `dos_locale.c`, `syslinux.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `ExtractFreeDOS()` / `ExtractDOS()` | 🟡 | Extract FreeDOS/MS-DOS boot files from embedded data |
| `SetDOSLocale()` | 🟡 | Write locale config to DOS boot drive |
| `InstallSyslinux()` | 🟡 | Write syslinux boot sector; `syslinux/libinstaller` is bundled |
| `GetSyslinuxVersion()` | 🟡 | Parse version from bundled ldlinux data |
| `libfat_readfile()` | 🟡 | FAT filesystem read callback for syslinux |
| GRUB support | ❌ | GRUB write not yet wired (ISO extraction only) |

### 3n. WIM / VHD / WUE (`vhd.c`, `wue.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `IsBootableImage()` | 🟡 | Check image header / magic bytes |
| `GetWimVersion()` | 🟡 | Read WIM XML metadata; use bundled `wimlib` |
| `WimExtractFile()` / `WimSplitFile()` / `WimApplyImage()` | 🟡 | All use bundled `wimlib`; need Linux file I/O |
| `VhdMountImageAndGetSize()` | 🟡 | Mount VHD via Linux `nbd` kernel module or `qemu-nbd` |
| `VhdUnmountImage()` | 🟡 | Unmount nbd device |
| `CreateUnattendXml()` | 🟡 | Generate `autounattend.xml`; pure string work |
| `SetupWinPE()` | 🟡 | Copy WinPE helpers to drive |
| `PopulateWindowsVersion()` | 🟡 | Parse Windows version from WIM XML |
| `CopySKUSiPolicy()` | 🟡 | Copy policy file to drive |
| `SetWinToGoIndex()` / `SetupWinToGo()` | 🟡 | Windows To Go setup |
| `ApplyWindowsCustomization()` | 🟡 | Apply unattend / registry tweaks post-write |

### 3o. S.M.A.R.T. (`smart.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `Identify()` | 🟡 | Issue ATA IDENTIFY via `ioctl(HDIO_GET_IDENTITY)` or `SG_IO` |
| `SmartGetVersion()` | 🟡 | Issue ATA SMART READ DATA via `SG_IO` |
| `IsHDD()` | 🟡 | Determine if device is an HDD from IDENTIFY data |
| `SptStrerr()` | 🟡 | Translate SCSI/ATA error to string |

### 3p. Bad Blocks (`badblocks.c`)

| Function | Status | Notes |
|----------|--------|-------|
| `BadBlocks()` | 🟡 | Write/read test patterns across the device; pure block I/O — relatively straightforward POSIX port |

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
| `WM_DEVICECHANGE` device-arrival events | 🟡 | Replace with `udev_monitor` thread that calls `GetDevices()` and posts a GTK refresh |
| Windows timer (`SetTimer` / `KillTimer`) | 🟡 | Replace with `g_timeout_add` |
| `CRITICAL_SECTION` / `Mutex` | ✅ | `CRITICAL_SECTION` (recursive pthread mutex) and `CreateMutex`/`ReleaseMutex` implemented in compat layer |
| `op_in_progress` flag | 🔧 | Defined in `globals.c`; needs atomic set/clear around thread lifetime |

---

## 5. Settings / Persistence

| Item | Status | Notes |
|------|--------|-------|
| Windows `rufus.ini` file read/write | 🟡 | `parser.c` stubs need implementing; use `get_token_data_file_indexed` once ported |
| Registry settings (`HKCU\Software\Rufus\`) | 🚫 | Replace with `~/.config/rufus/rufus.ini` or GLib `GKeyFile` |
| `app_dir` / `app_data_dir` / `user_dir` paths | 🟡 | Should be set to `XDG_CONFIG_HOME`, `XDG_DATA_HOME` etc. in `globals.c` |

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
| Embedded locale data (`res/loc/embedded.loc`) | 🟡 | Must be compiled in as a C array (`xxd -i`) or loaded from a data directory |
| Embedded FreeDOS / MS-DOS boot files | 🟡 | Same — embed as binary arrays or install to `$datadir` |
| Application icon (`.desktop` / `.png`) | ❌ | Need a `.desktop` file and icon for Linux desktop integration |

---

## 8. Testing Gaps

| Area | Status | Notes |
|------|--------|-------|
| `common/cregex` tests | ✅ | 37 tests, Linux + Wine |
| Threading compat layer tests | ✅ | 51 tests covering threads, events, mutexes, CRITICAL_SECTION |
| `common/xml` (ezxml) tests | ❌ | No tests yet; XML parsing used by localization and WIM |
| `stdfn.c` (htab, StrArray) tests | ✅ | 299 tests; htab_create/hash/destroy, StrArray, NULL guards |
| `parser.c` token functions tests | ❌ | |
| PE parsing functions tests | ❌ | `GetPeArch`, `GetPeSection` etc. are portable C |
| `msg_dispatch` (PostMessage/SendMessage bridge) tests | ✅ | 61 tests: handler registry, sync/async dispatch, cross-thread SendMessage, concurrent posts, macro aliases, UM_* constants |
| Format logic tests (unit) | ❌ | Requires mock block device abstraction |
| Device enumeration tests (`test_dev_linux`) | ✅ | 79 tests: fake sysfs, removable/HDD/size/sort/name/index/cleanup |

---

## 9. Priority Order (Suggested)

1. ~~**Threading bridge**~~ ✅ **DONE** — `CreateThread` → `pthread`, events, mutexes, `CRITICAL_SECTION` all implemented with 51 passing tests
2. ~~**`PostMessage`/`SendMessage` → GTK dispatch**~~ ✅ **DONE** — `msg_dispatch.c` bridge with 61 passing tests; GTK `g_idle_add` scheduler and main dialog handler registered in `ui_gtk.c`
3. ~~**`stdfn.c` htab**~~ ✅ **DONE** — full hash table + StrArray ported; 299 tests pass
4. ~~**Device enumeration** (`dev.c`)~~ ✅ **DONE** — sysfs scan with sort, filtering, combo population; 79 tests pass using fake sysfs
5. **Device combo hot-plug** — wire `WM_DEVICECHANGE` to udev monitor; call `GetDevices()` on hot-plug events
6. **Localization + parser** — get locale loading working so all strings are correct
6. **Format thread** (`format.c`) — the core write operation; start with FAT32 quick-format
7. **FAT32 formatter** (`format_fat32.c`) — self-contained; relatively mechanical port
8. **ext formatter** (`format_ext.c`) — `ext2fs` lib is already bundled and compiles
9. **ISO extraction** (`iso.c`) — `libcdio` is bundled; wire up real I/O
10. **Hashing** (`hash.c`) — algorithms are pure C; just need POSIX I/O wrappers
11. **Networking** (`net.c`) — replace `WinInet` with `libcurl`
12. **PKI / signatures** (`pki.c`) — replace `WinTrust` with OpenSSL
13. **Bad blocks** (`badblocks.c`) — straightforward block I/O loop
14. **S.M.A.R.T.** (`smart.c`) — `SG_IO` ioctl
15. **WIM / VHD** (`vhd.c`, `wue.c`) — `wimlib` is bundled; VHD needs `nbd`
16. **Settings persistence** — `~/.config/rufus/rufus.ini`
17. **Elevation / polkit** — for proper desktop integration
18. **Syslinux / DOS bootloaders** — finish installer wiring
19. **Language menu** (`ShowLanguageMenu` TODO in `ui_gtk.c`)
20. **Desktop integration** — `.desktop` file, icon, AppStream metadata
