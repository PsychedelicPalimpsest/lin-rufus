# Contributing to Rufus (Linux Port)

Thank you for your interest in contributing to the Linux port of Rufus!
This document covers the conventions used in the Linux port specifically.
For general contribution guidelines (code style, commit format, issue
reporting) please read the upstream README.

---

## Table of Contents

1. [Architecture overview](#architecture-overview)
2. [Porting conventions](#porting-conventions)
3. [Compat-layer rules](#compat-layer-rules)
4. [Test requirements](#test-requirements)
5. [Adding a new compat header](#adding-a-new-compat-header)
6. [Running the test suite](#running-the-test-suite)
7. [Wine cross-testing](#wine-cross-testing)
8. [Adding a new feature](#adding-a-new-feature)
9. [features.md](#featuresmd)
10. [Code review checklist](#code-review-checklist)

---

## Architecture overview

```
src/
├── common/         Portable logic — NO OS-specific code allowed here
│   ├── stdfn.c         htab, StrArray, GuidToString, …
│   ├── stdio.c         TimestampToHumanReadable, GuidToString, …
│   ├── drive.c         GetMBRPartitionType, GetGPTPartitionType
│   ├── format_fat32.c  fat32_default_cluster_size
│   ├── format_ext.c    error_message, GetExtFsLabel, ext2fs_print_progress
│   ├── bootloader_scan.c  GetBootladerInfo
│   ├── iso_scan.c      GetGrubVersion, GetGrubFs, GetEfiBootInfo
│   ├── iso_config.c    iso_patch_config_file
│   ├── iso_check.c     check_iso_props
│   ├── iso_report.c    log_iso_report
│   ├── hash_pe.c       PE256Buffer, efi_image_parse
│   ├── hash_db.c       IsFileInDB, IsBufferInDB, StringToHash
│   ├── localization.c  lmprintf, dispatch_loc_cmd, get_locale_from_*
│   └── parser.c        token CRUD, GetSbatEntries, PE parsing, …
│
├── linux/          Linux-specific implementations
│   ├── compat/         Windows API shim headers (no .c files)
│   │   ├── windows.h       Core types, macros, SendMessage/PostMessage,
│   │   │                   CreateThread/WaitForSingleObject, …
│   │   ├── shlwapi.h       PathFileExists, PathCombine, StrStrIA
│   │   ├── shellapi.h      ShellExecuteA (→ xdg-open)
│   │   ├── psapi.h         Stub (no callers on Linux)
│   │   └── …
│   ├── dev.c           Device enumeration via sysfs / libudev
│   ├── drive.c         MountVolume, CreatePartition, libfdisk wrappers
│   ├── format.c        FormatThread, FormatPartition (mkntfs, mkfs.exfat)
│   ├── format_fat32.c  FormatLargeFAT32 (POSIX)
│   ├── format_ext.c    FormatExtFs (bundled ext2fs)
│   ├── hash.c          HashFile, HashThread, OpenSSL Secure Boot checks
│   ├── iso.c           ExtractISO, DumpFatDir (libcdio)
│   ├── net.c           DownloadToFileOrBufferEx (libcurl), CheckForUpdates
│   ├── pki.c           ValidateOpensslSignature (OpenSSL EVP)
│   ├── stdfn.c         GetResource, GetExecutableVersion, SetThreadAffinity
│   ├── stdio.c         uprintf, WindowsErrorString, RunCommandWithProgress
│   ├── stdlg.c         FileDialog, NotificationEx, CustomSelectionDialog
│   ├── ui_gtk.c        GTK window, all signal handlers, g_idle_add bridges
│   ├── settings.h      ReadSetting*/WriteSetting* → ~/.config/rufus/rufus.ini
│   └── …
│
└── windows/        Windows-specific implementations (unchanged)
    ├── rufus.c         WinMain, Windows dialog resources, …
    └── …
```

The key invariant: **`src/common/` must compile and run on both platforms
without any `#ifdef _WIN32` that changes runtime behaviour.**  Platform
differences belong in `src/linux/` or `src/windows/`.

---

## Porting conventions

### No runtime no-ops without a comment

Every stub function in `src/linux/` must have a comment explaining *why*
it is a no-op and what the equivalent Linux mechanism is (or why none is
needed).

```c
/* Windows S Mode — always FALSE on Linux */
BOOL isSMode(void) { return FALSE; }
```

A stub that silently does nothing without explanation is a bug.

### Extract shared logic to `common/`

Whenever you find code that is identical (or nearly identical) in both
`src/windows/X.c` and `src/linux/X.c`, extract it to `src/common/X.c`.
Use the "include trick" when the common file needs platform-specific
constants:

```c
/* src/common/format_ext.c — shared ext2fs helpers */
#ifndef EXT_IO_MANAGER   /* defined differently by each platform */
#  error "include this file from linux/format_ext.c or windows/format_ext.c"
#endif
```

### Use the compat headers, not `#ifdef _WIN32`

Business logic should not `#ifdef _WIN32`.  Add a compat shim instead:

```c
/* Bad — mixes OS detection into business logic */
#ifdef _WIN32
    CreateFile(...);
#else
    open(...);
#endif

/* Good — compat header provides CreateFile as an inline that calls open() */
#include "compat/windows.h"
CreateFile(...);   /* works on both platforms */
```

### Globals and forward declarations

Shared globals (e.g. `fs_type`, `boot_type`, `img_report`) are declared
in `src/windows/rufus.h` and defined once — either in a platform
`.c` file or in `src/linux/globals.c`.  Never define a global in a header.

---

## Compat-layer rules

`src/linux/compat/` contains header-only Windows API shims.  Rules:

1. **No `.c` files in `compat/`.**  All implementations are `static inline`
   functions or macros in the `.h` file.
2. **Never include `<windows.h>`** from inside a compat header — it doesn't
   exist on Linux.  Include `"windows.h"` (the compat version) instead.
3. **Stub return values must be semantically correct.**  A function that
   returns `BOOL` should return `TRUE` (success) or `FALSE` (failure)
   matching what real callers expect, not a random value.
4. **Document every deviation** from the Windows API contract with a comment.
5. **Prefer real implementations over stubs.**  A stub is acceptable only
   when the Windows feature has no Linux equivalent _and_ the caller path
   is unreachable on Linux.

---

## Test requirements

Every new public function (or ported Windows function) **must have at
least 3 tests** in `tests/test_<name>_linux.c`.  Tests must:

- Use `framework.h` macros: `TEST()`, `CHECK()`, `CHECK_STR_EQ()`,
  `CHECK_INT_EQ()`, `RUN()`, `TEST_RESULTS()`.
- Be self-contained: no network, no real block devices (use loopback or
  fake data), no GUI.
- Use injectable paths (`RUFUS_TEST` build-time flag) to avoid touching
  the real filesystem outside `/tmp`.
- Pass cleanly under AddressSanitizer (`_asan` variant built by the test
  Makefile).

### Test file naming

| Type | File pattern | Example |
|------|-------------|---------|
| Linux-only | `test_<feature>_linux.c` | `test_dev_linux.c` |
| Common (both platforms) | `test_<feature>_common.c` | `test_fat32_common.c` |

Linux-only test files are excluded from the Wine/MinGW pass automatically.

### SKIP_NOT_ROOT

Tests that require block device access use:

```c
#include "framework.h"
TEST(my_root_test) {
    if (geteuid() != 0) return;   /* or SKIP_IF(geteuid() != 0) */
    …
}
```

Run root tests in the container environment (see below).

---

## Adding a new compat header

1. Create `src/linux/compat/<name>.h`.
2. Add a guard: `#pragma once` + `#ifndef _WIN32` check where relevant.
3. Include `"windows.h"` if Windows base types are needed.
4. Implement each function/macro as `static inline` or `#define`.
5. Add the header to `src/linux/compat/windows.h` with an
   `#include "<name>.h"` so it is pulled in automatically.
6. Write at least 3 tests in `tests/test_compat_linux.c` covering the
   new header's behaviour.

---

## Running the test suite

### Prerequisites

Install all dependencies via the canonical script (used by CI and the
Docker image):

```sh
sudo bash tests/install-deps.sh
```

### Quick start

```sh
./configure --with-os=linux
make -j$(nproc)
./run_tests.sh --linux-only   # fast; no Wine, no container
```

### Full suite (including Wine)

```sh
./run_tests.sh                # Linux native + Wine (if Wine is installed)
```

### Root-requiring tests (loopback block devices)

These tests need `/dev/loop*` and must run as root.  Use the container:

```sh
./run_tests.sh --container    # builds & runs in a privileged Docker/Podman container
```

The container image is `tests/Dockerfile` (Ubuntu 22.04 + all deps).
The first build takes a few minutes; subsequent runs use the cached image.

### Toolchain overrides

```sh
CC=clang ./run_tests.sh --linux-only
CC_WIN=i686-w64-mingw32-gcc ./run_tests.sh --wine-only
```

### Individual tests

```sh
make -C tests test_dev_linux_linux
./tests/test_dev_linux_linux
```

---

## Wine cross-testing

Tests whose names do **not** end in `_linux` are also built with MinGW
and run under Wine.  This checks that common code compiles and behaves
identically on Windows.

To run only the Wine tests:

```sh
./run_tests.sh --wine-only
```

Wine and `x86_64-w64-mingw32-gcc` must be installed.  The test runner
skips the Wine pass gracefully if either is missing.

---

## Adding a new feature

Follow this process:

1. **Update `features.md`** — add an entry in the relevant section with
   status `❌` (not started).
2. **Write tests first** — create `tests/test_<feature>_linux.c` with
   at least 3 tests that exercise the intended behaviour.  Run them to
   confirm they fail (TDD red phase).
3. **Implement** the feature in `src/linux/<feature>.c` (or in
   `src/common/` if portable).  Wire up to `src/Makefile.am`.
4. **Make the tests pass** (TDD green phase).
5. **Wire to the UI** — if the feature changes user-visible behaviour,
   connect it to `src/linux/ui_gtk.c` (GTK signal handler or
   `main_dialog_handler`).
6. **Update `features.md`** — change status to `✅` and add a brief note.
7. **Commit** when a complete feature milestone is reached (not on every
   green test).

---

## features.md

`features.md` is the master todo list for the Linux port.  Every item has
a status symbol:

| Symbol | Meaning |
|--------|---------|
| ✅ | Done / works on Linux |
| 🔧 | Partial / needs finishing |
| 🟡 | Stub exists, real implementation needed |
| ❌ | Not started |
| 🚫 | Windows-only / permanently N/A on Linux |

Keep this file updated as you work.  Strikethrough (`~~item~~`) plus ✅
marks completed items in the Priority Order section.

---

## Code review checklist

Before opening a pull request:

- [ ] `./run_tests.sh --linux-only` passes with zero failures
- [ ] New functions have ≥ 3 tests
- [ ] No `#ifdef _WIN32` in `src/common/`
- [ ] No runtime no-ops without explanatory comments
- [ ] `features.md` updated
- [ ] Copyright header present in new files (GPL-3.0)
- [ ] No hard-coded absolute paths (use `app_dir`, `app_data_dir`, `XDG_*`)
- [ ] No direct `printf` in library code (use `uprintf` for log output)
