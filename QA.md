# Rufus Linux Port — QA Notes

> **Last updated:** 2026-03-04 (session 8)
> **Reviewer:** Copilot QA session

---

## How to Read This File

General notes, gotchas, environment info, and anything the *next* QA reviewer
needs to know before starting.  Actual bug reports / feature gaps live in
`features.md` (Pending Work section).

---

## Environment

| Item | Value |
|------|-------|
| Test disk | `/dev/nvme0n2` (25 GiB NVMe) — safe to wipe |
| Available ISOs | `~/Win11_25H2_English_x64.iso`, `~/ubuntu-24.04.4-desktop-amd64.iso` |
| Wine | Installed, but **wine32 is missing** — only 64-bit EXEs work |
| AT-SPI2 | `python3-pyatspi` is installed; UI automation tests work |
| Xvfb | `xvfb-run` is present; virtual display `:97` is used by some tests |

### Build Gotcha — configure must be called with `--with-os=linux`

The `configure.ac` **defaults to `--with-os=windows`**.  Running bare
`./configure` selects Windows toolchain, breaks GTK detection, and leaves
`USE_GTK_TRUE="#"` (disabled).  Always use the helper script:

```
./build-rufus-linux.sh         # sets CC=gcc, passes --with-os=linux
```

Or manually:

```
CC=gcc ./configure --with-os=linux [--with-ui=gtk]
```

This tripped up the QA session (see session log).  The existing
`config.status` / `src/rufus` binary should be correct after
`./build-rufus-linux.sh` was last run, but always double-check with:

```
grep 'USE_GTK_TRUE' config.status   # must NOT be '#'
```

---

## Known Open Issues (to be tracked in features.md)

### ~~CRITICAL — GTK binary silently ignores CLI flags~~ **RESOLVED**

**Resolved in commit `3df14315`** (`fix(cli): make --version, --help work without --device in GTK binary`).

`ui_gtk.c` main() now scans `argv` manually before `g_application_run()` and
short-circuits into `cli_parse_args()` / `cli_run()` when `--device`, `-d`,
`--list-devices`, `-L`, `--version`, or `--help` is present.

```
$ ./src/rufus --device /dev/sdb   # works correctly ✅
$ ./src/rufus --help              # shows Rufus CLI help ✅
$ ./src/rufus --list-devices      # lists devices and exits ✅
```

Verified in session 8: `test_exe_cli_linux_linux` (31 passed), manual tests
all pass.

---

### ~~Minor — `device_combo.c` uses unquoted path~~ **RESOLVED**

Fixed in session 6 (Feature 192): path is now quoted as `xdg-open '%s'`.
Tests updated to match (`test_ui_linux.c`).

---

### ~~Minor — `ntfsfix.c` and Missing dedicated unit tests~~ **RESOLVED**

All four previously-untested files now have full test coverage:
- `ntfsfix.c` — 24 tests in `test_ntfsfix_linux.c`
- `device_combo.c` — 7 tests in `test_ui_linux.c`
- `dump_fat.c` — 15 tests in `test_dump_fat_linux.c`
- `proposed_label.c` — 8 tests in `test_ui_linux.c`

---

### Informational — Windows CLI vs Linux CLI are intentionally different

The Windows `rufus.exe` CLI flags (`-i/-g/-l/-f/-w`) only *pre-select* GUI
options; the Windows version has no headless write mode.  The Linux CLI is
a genuine non-interactive formatter.  This divergence is intentional and
documented in `DIFFERENCES.md`, but may surprise users expecting parity.

---

## What Was Tested — Session 2026-03-03 (initial session)

| Test | Result |
|------|--------|
| `./run_tests.sh --linux-only` | ✅ All tests passed |
| `test_ui_smoke_linux_linux` | ✅ 9 passed |
| `test_ui_automation_linux_linux` | ✅ 10 passed |
| `sudo RUFUS_TEST_DEVICE=/dev/nvme0n2 test_real_device_linux_linux` | ✅ 11 passed (FAT32, FreeDOS, NTFS, GPT formats) |
| `sudo RUFUS_TEST_DEVICE=/dev/nvme0n2 test_e2e_linux_linux` | ✅ 13 passed |
| `test_iso_hashes_linux` | ✅ 50 passed |
| Manual Ubuntu ISO DD write to `/dev/nvme0n2` | ✅ ISO 9660 magic verified |
| `rufus --device /dev/nvme0n2 --help` | ❌ "Unknown option --device" (GTK build) |

---

## What Was Tested — Session 2026-03-03 (this session)

### Bug Fixed This Session

**3 failing tests in `tests/test_ui_linux.c`** — `device_open_in_fm_build_cmd_basic`,
`device_open_in_fm_build_cmd_sdc`, and `device_open_in_fm_build_cmd_nvme` expected the
**old unquoted** command format (`xdg-open /dev/sdb`) but the implementation (Feature 192
fix) now produces the **quoted** format (`xdg-open '/dev/sdb'`).  The tests were stale.
Fixed by updating the three `CHECK_MSG` expected strings.

### Tests Run

| Test | Result |
|------|--------|
| `./run_tests.sh --linux-only` | ✅ All tests passed (after fix) |
| `./run_tests.sh --wine-only` | ✅ All tests passed |
| `test_ui_linux_linux` (force-rebuilt) | ✅ 56 passed (was 53/56 before fix) |
| `sudo RUFUS_TEST_DEVICE=/dev/nvme0n2 test_real_device_linux_linux` | ✅ 11 passed |
| `sudo RUFUS_TEST_DEVICE=/dev/nvme0n2 test_e2e_linux_linux` | ✅ 13 passed |
| `test_iso_hashes_linux` | ✅ 50 passed |
| `test_format_ntfs_exfat_linux_linux` | ✅ 121 passed |
| `test_smart_linux_linux` | ✅ 26 passed |
| `test_cppcheck_linux_linux` | ✅ 20 passed |
| `test_man_page_linux_linux` | ✅ 45 passed |
| Manual Ubuntu ISO DD write to `/dev/nvme0n2` | ✅ ISO 9660 magic `01 CD001` verified at offset 0x8000 |
| `rufus --device /dev/nvme0n2` | ❌ "Unknown option --device" — Feature 188/189 still open |

### Spot Checks Performed

| File | Finding |
|------|---------|
| `src/linux/device_combo.c` | Path is now correctly quoted (`'%s'`); fix was implemented but tests not updated — **fixed** |
| `src/linux/hyperlink.c` | Correct XML escaping; tested in `test_ui_linux.c` |
| `src/linux/dump_fat.c` | `wchar16_to_utf8` uses static buffer (documented as not thread-safe); single-threaded usage only — acceptable |
| `src/linux/ntfsfix.c` | No test coverage (Feature 191 pending) |
| `src/linux/darkmode.c` | No-op stubs only; no tests needed |
| `src/linux/icon.c` | `ExtractAppIcon` stub; `SetAutorun` correct |
| `src/linux/notify.c` | `shell_escape` helper looks correct |
| `src/linux/wue.c` | `ApplyWindowsCustomization` uses `s_mount_path` (not Windows drive letter) — correct Linux behaviour |
| `src/linux/smart.c` | `ScsiPassthroughDirect` returns `int` (not `BOOL` as on Windows); callers consistent; tests pass |
| `src/common/iso_check.c` | Potential null deref after `safe_strdup` at line 119 — inside `#ifdef _WIN32`, Linux unaffected |

### Feature 192 is now RESOLVED

`device_combo.c` was already fixed (uses `'%s'` quoting); `features.md` updated to mark it closed.

---

## What Was Tested — Session 2026-03-03 (third session)

### Bugs Fixed This Session

**Bug 1 — `--include-hdds` ignored with `--list-devices`** (two related sub-bugs):
1. `cli_options_t opts` declared uninitialized; `cli_parse_args()` now calls
   `cli_options_init(opts)` at the top so callers don't need to.
2. `cli_apply_options(&opts)` was missing in the `CLI_PARSE_LIST` branch of both
   `ui_gtk.c` and `rufus.c`; added before `cli_print_devices()`.

**Bug 2 — `--label` silently ignored**:
1. `cli_apply_options()` in `cli.c` now wires `opts->label` into `hLabel` via
   `window_text_register()` + `SetWindowTextA()` using a static sentinel HWND.
2. `WritePBR_fs()` in `format.c` changed all `write_fat_32_*_br(fp, 0)` →
   `write_fat_32_*_br(fp, 1)` (bKeepLabel) so the VBR write preserves the label
   set by `FormatLargeFAT32` in the boot sector BPB (offset 0x47).  On Windows
   `SetVolumeLabel()` handles re-applying the label after WritePBR; Linux had no
   such fallback.

**Known remaining gap (Feature 199):** The FAT32 root-directory volume label entry
(`ATTR_VOLUME_ID=0x08`) is not created by `FormatLargeFAT32`.  `fatlabel` returns empty;
`blkid` shows `LABEL_FATBOOT` correctly from the boot sector.

### Tests Run

| Test | Result |
|------|--------|
| `./run_tests.sh --linux-only` | ✅ All tests passed |
| `./run_tests.sh --wine-only` | ✅ All tests passed |
| `sudo RUFUS_TEST_DEVICE=/dev/nvme0n2 test_real_device_linux_linux` | ✅ 11 passed |
| `sudo RUFUS_TEST_DEVICE=/dev/nvme0n2 test_e2e_linux_linux` | ✅ 13 passed |
| Manual `--list-devices` (no flags) | ✅ exit 1, no output (NVMe not removable) |
| Manual `--include-hdds --list-devices` | ✅ nvme0n1 + nvme0n2 shown, exit 0 |
| Manual `--include-hdds --list-devices --json` | ✅ valid JSON |
| Manual `--fs fat32 --no-prompt` | ✅ format completed, FAT32 partition verified |
| Manual `--image ubuntu-24.04.4 --write-as-image --no-prompt` | ✅ ISO 9660 magic verified |
| Manual `--fs fat32 --label TESTVOL --no-prompt` | ✅ `blkid` shows `LABEL_FATBOOT="TESTVOL"` |

### Spot Checks Performed

| File | Finding |
|------|---------|
| `src/linux/pki.c` | OpenSSL RSA-2048 + PKCS7; correct cleanup with goto |
| `src/linux/stdio.c` | Log handler, uprintf, wuprintf; correct |
| `src/linux/device_monitor.c` | udev netlink monitor; correct |
| `src/linux/drag_drop.c` | File URI decoder; clean |
| `src/linux/format_ext_tools.c` | Tool-finder and command-builder; clean |
| `src/linux/ui_enable_opts.c` | Checkbox sensitivity predicates; correct |
| `tests/test_status_history_linux.c` | 15 tests for ring-buffer; good coverage |
| `tests/test_drag_drop_linux.c` | 11 tests for URI parsing; good coverage |

### Feature Parity Notes (Priority 6)

- `DIFFERENCES.md` documents intentional divergences accurately.
- Windows CLI (`-i/-g/-l/-f/-w`) only pre-selects GUI options; no headless mode.
  Linux CLI is a genuine non-interactive formatter.  This is expected and documented.
- All CLI flags exercised from man page match `cli_parse_args()` option table.
- `--label` was documented but broken; now fixed.

### New Feature Tracker Items

- Feature 199: FAT32 root-directory label entry missing from `FormatLargeFAT32`
- Feature 200: Integration test for `--include-hdds --list-devices` pipeline

---

## Tips for Next QA Session (updated)

1. **Read this file and check `features.md` Pending Work** before starting.
2. **Use `shuf`** to distribute spot-check effort evenly across the large codebase.
3. **Run `./run_tests.sh --linux-only` first** to establish baseline; always
   force-rebuild specific test binaries (`make -B -C tests test_<name>_linux_linux`).
4. **Test disk `/dev/nvme0n2`** — after third session it has FAT32 with label "TESTVOL".
5. **`--label` now works** (verified: `blkid` shows `LABEL_FATBOOT`); `fatlabel` also
   works since Feature 199 fixed the root-dir label entry.
6. **Wine32 missing** — `wine32 is missing` warnings are benign; only 64-bit tests work.
7. **No hardcoded `/dev/nvme0n2` in repo** — all device tests use `RUFUS_TEST_DEVICE` env var.

1. **Start by reading this file**, then check `features.md` Pending Work.
2. **Use `shuf` to select random spot-check targets** (as per task instructions).
3. **Run the full test suite first** to establish a passing baseline before
   making any code changes.  **Always force-rebuild the specific test binary**
   (`make -B test_<name>_linux`) before accepting "up to date" as a pass —
   stale binaries masked the 3 failing tests this session.
4. **All features 188–222 are RESOLVED** — the `features.md` Pending Work section
   is a clean summary table; no open items remain.
5. **Wine** only supports 64-bit on this machine; the Windows-binary tests
   via Wine may show `wine32 is missing` warnings — ignore them as long as
   Wine tests still pass for 64-bit code.
6. **The test disk `/dev/nvme0n2`** is safe to use destructively; re-image
   with any format you need.  After the 2026-03-04 session it has the Ubuntu
   24.04 ISO written to it (ISO 9660 magic verified).
7. **No TODO/FIXME/HACK/BUG comments** were found in `src/linux/*.c` — the
   codebase is clean in that regard.
8. **`test_ui_linux_linux` 65 tests** — 7 cover `device_combo`, 7 cover
   `hyperlink`, 8 cover `proposed_label`, 10 cover window title progress.
   Always force rebuild suspicious tests.

---

## What Was Tested — Session 2026-03-04 (this session)

### Bug Fixed This Session

**`--locale` missing from man page** (`doc/rufus.1`):
- Added `[--locale LOCALE]` to the SYNOPSIS section
- Added `.TP` entry with full description under OPTIONS
- 105 man page tests still pass after the fix

### Tests Run

| Test | Result |
|------|--------|
| `./run_tests.sh --linux-only` | ✅ All tests passed |
| `./run_tests.sh --wine-only` | ✅ All tests passed |
| `sudo RUFUS_TEST_DEVICE=/dev/nvme0n2 test_real_device_linux_linux` | ✅ 11 passed |
| `sudo RUFUS_TEST_DEVICE=/dev/nvme0n2 test_e2e_linux_linux` | ✅ 13 passed |
| `test_man_page_linux_linux` (rebuilt) | ✅ 105 passed |
| `test_multidev_linux_linux` (rebuilt) | ✅ 74 passed |
| `test_format_linux_linux` (rebuilt) | ✅ 167 passed |
| `test_cli_linux_linux` (rebuilt) | ✅ 320 passed |
| `test_progress_linux_linux` | ✅ 33 passed |
| `test_progress_text_linux_linux` | ✅ 18 passed |
| `test_dump_fat_linux_linux` | ✅ 139 passed |
| `test_ui_linux_linux` | ✅ 65 passed |
| Manual `--device /dev/nvme0n2 --fs fat32 --label QATEST --no-prompt` | ✅ FAT32 formatted; `fatlabel` shows `QATEST` |
| Manual `--device /dev/nvme0n2 --image ~/ubuntu-24.04.4-desktop-amd64.iso --write-as-image --no-prompt` | ✅ ISO 9660 magic `01 CD001` verified at offset 0x8000 |
| Manual `--include-hdds --list-devices --json` | ✅ valid JSON, nvme0n1 + nvme0n2 shown |
| Manual `--version` | ✅ `rufus 4.13.0` |
| Manual `--help` | ✅ full usage printed, all flags shown |

### Spot Checks Performed

| File | Finding |
|------|---------|
| `src/linux/ventoy_detect.c` | Clean; `make_part_path` handles nvme/mmcblk `p` suffix correctly |
| `src/linux/polkit.c` | Clean; `rufus_build_pkexec_argv` correctly handles empty argv |
| `src/linux/paths.c` | Clean; `rufus_effective_home_impl` correctly handles all edge cases |
| `src/linux/status_history.c` | Ring buffer correct; `status_history_tooltip` walks oldest→newest |
| `src/linux/globals.c` | All globals initialized; `lmprintf` weak stub present |
| `src/linux/usb_speed.c` | `usb_speed_string` range table correct (USB 1.0–4) |
| `src/linux/boot_validation.c` | All predicates clean; no dead code |
| `src/linux/ui_combo_logic.c` | `set_preselected_fs` / `set_user_selected_fs` correct |
| `src/linux/dump_fat.c` | 15 tests pass; `iso9660_readfat` cache window logic correct |
| `src/linux/hyperlink.c` | XML escaping correct; tested in `test_ui_linux.c` |
| `src/linux/sl_version.c` | Port of Windows `GetSyslinuxVersion`; unchanged from upstream |
| `src/linux/verify.c` | Chunk-by-chunk compare; `CHECK_FOR_USER_CANCEL` in loop |
| `src/linux/ntfsfix.c` | Double-quote protection; pluggable system hook for tests |
| `doc/rufus.1` | `--locale` was absent from SYNOPSIS and OPTIONS — **fixed** |

### features.md Cleanup

Removed all verbose QA session narratives and verbose RESOLVED feature descriptions
(lines 573–1149 of the old file).  Replaced with a compact summary table of all
188–222 features in the new "Pending Work" section.  File shrunk from 75 KB → 43 KB.


---

## What Was Tested — Session 2026-03-04 (session 5)

### Bugs Fixed This Session

**DIFFERENCES.md documentation error — `GetProcessSearch` listed as "Not Implemented":**
- `DIFFERENCES.md` had two places stating `GetProcessSearch` is not implemented on Linux.
- Reality: `process.c` contains a full `/proc`-scan-based implementation that matches
  Windows semantics exactly — it iterates `/proc/<pid>/fd/`, checks `st_rdev`, and
  adds process names to `BlockingProcessList`.
- Fixed by updating the "Behavioral Differences" section to document the real implementation,
  and removing the entry from the "Not Implemented" table.

**`features.md` — `FlashTaskbar()` listed as 🚫 N/A:**
- Feature 218 implemented `FlashTaskbar()` via `gtk_window_set_urgency_hint`, but
  the `features.md` UI stub table still showed it as 🚫.  Updated to ✅.

### Tests Run

| Test | Result |
|------|--------|
| `./run_tests.sh --linux-only` | ✅ All tests passed |
| `./run_tests.sh --wine-only` | ✅ All tests passed |
| `sudo RUFUS_TEST_DEVICE=/dev/nvme0n2 test_real_device_linux_linux` | ✅ 11 passed |
| `sudo RUFUS_TEST_DEVICE=/dev/nvme0n2 test_e2e_linux_linux` | ✅ 13 passed |
| `test_verify_linux_linux` (force-rebuilt) | ✅ 37 passed |
| `test_dev_usb_speed_linux_linux` (force-rebuilt) | ✅ 17 passed |
| `test_cluster_sizes_linux_linux` (force-rebuilt) | ✅ 29 passed |
| `test_kbd_shortcuts_linux_linux` (force-rebuilt) | ✅ 140 passed |
| Manual `--device /dev/nvme0n2 --fs fat32 --label QASESSION --no-prompt` | ✅ `blkid` shows `LABEL="QASESSION"` + `LABEL_FATBOOT="QASESSION"` |
| Manual `--device /dev/nvme0n2 --image ~/ubuntu-24.04.4-desktop-amd64.iso --write-as-image --no-prompt` | ✅ ISO 9660 magic `01 CD001` verified at offset 0x8000 |
| Manual `--include-hdds --list-devices --json` | ✅ valid JSON, nvme0n1 + nvme0n2 shown |
| Manual `--version` | ✅ `rufus 4.13.0` |
| Manual `--help` | ✅ all 42 flags shown |

### Spot Checks Performed

| File | Finding |
|------|---------|
| `src/linux/process.c` | Clean; full `/proc` scan implementation for `GetProcessSearch`; `SearchProcessAlt` scans `/proc/PID/comm` |
| `src/linux/boot_validation.c` | Clean; all predicates correct; no dead code |
| `src/linux/syslinux.c` | Clean; libfat/libinstaller integration correct |
| `src/linux/format.c` (WritePBR, sector_write) | Clean; sector-aligned write buffer correct |
| `tests/test_verify_linux.c` | Good coverage: null source, invalid fd, zero size, match, mismatch (small+large), second chunk, cancel, progress reporting, short source |
| `tests/test_dev_usb_speed_linux.c` | Good coverage: all USB speeds, null/empty, unknown, boundary conditions |
| `tests/test_cluster_sizes_linux.c` | Good coverage: FAT16/32/NTFS/exFAT/ext2/UDF across size ranges |
| `tests/test_kbd_shortcuts_linux.c` | Excellent: 140 tests covering all Alt+key shortcuts |
| `tests/cli_linux_glue.c` | Mock `/dev/sda` is a test string (not real device access) — acceptable |
| `DIFFERENCES.md` | `GetProcessSearch` incorrectly listed as N/A — **fixed** |
| `features.md` | `FlashTaskbar()` incorrectly listed as 🚫 — **fixed**; historic "Resolved Features Summary" table removed |
| `doc/rufus.1` | All 42 CLI flags present in both SYNOPSIS and OPTIONS; man page accurate |

### Feature Parity Notes

- All 87 `src/linux/*.c` files have test coverage (either direct test file or tested
  via a larger test that includes the file).
- `wintogo_bcd_template.c` (data-only file) is covered by `test_wue_linux.c`.
- No TODO/FIXME/HACK comments in `src/linux/*.c` or `src/common/*.c`.
- `DIFFERENCES.md` now accurately reflects implemented vs N/A features.

### features.md Cleanup (session 5)

- Removed `## Build / CI Fixes (session 2025-07)` section (all resolved).
- Removed `### Resolved Features Summary` table (features 188–224; all done).
- Updated `## Pending Work` to clearly state all 188–224 are complete.
- Corrected two stale entries in the main status tables.
- File shrunk from 581 → 513 lines.

---

## Tips for Next QA Session (session 5 update)

1. **Read this file**, then check `features.md` Pending Work (currently empty).
2. **Use `shuf`** to distribute spot-check effort evenly.
3. **Run `./run_tests.sh --linux-only` first** to establish a passing baseline.
4. **Force-rebuild suspicious tests** before accepting them as passing.
5. **Test disk `/dev/nvme0n2`** — after session 5 it has Ubuntu 24.04 ISO written (DD mode).
6. **No hardcoded `/dev/nvme0n2` in repo** — use `RUFUS_TEST_DEVICE` env var.
7. **`DIFFERENCES.md` is now accurate** — `GetProcessSearch` is implemented; `FlashTaskbar` is ✅.
8. **Wine32 missing** — benign warnings; 64-bit Wine tests work fine.

---

## What Was Tested — Session 2026-03-04 (session 6)

### Bugs Fixed This Session

**`FileMatchesHash()` null-pointer dereference when `str` is NULL:**
- Both `src/common/hash_db.c` and `tests/hash_win_glue.c` had identical bugs:
  `FileMatchesHash(path, NULL)` would call `StringToHash(NULL)` which hits
  `if_assert_fails(...)` (assertion abort) before returning NULL.
  `BufferMatchesHash` already had a `str == NULL` guard; `FileMatchesHash` did not.
- Fixed by adding early-return `if (str == NULL) return FALSE;` and caching the
  `StringToHash()` return to guard against NULL dereference in `memcmp()`.
- Added test `file_matches_hash_null_str` in `tests/test_hash.c`.
- This also caused **a Wine test failure** in `test_hash.exe` — now fixed.

**`calloc` transposed arguments (two files):**
- `src/common/parser.c:70`: `calloc(sizeof(loc_cmd), 1)` → `calloc(1, sizeof(loc_cmd))`
- `src/common/hash_pe.c:179`: `calloc(sizeof(IMAGE_SECTION_HEADER *), num_sections)` → `calloc(num_sections, sizeof(IMAGE_SECTION_HEADER *))`
- Both were functionally equivalent but triggered `-Wcalloc-transposed-args` warnings.

**`ExitThread` not marked `__attribute__((noreturn))`:**
- `src/linux/compat/windows.h`: `ExitThread()` wrapper around `pthread_exit()` was
  missing `__attribute__((noreturn))`.  This caused a `-Wreturn-type` warning in
  `src/linux/hash.c:725` where `HashThread` ends with `ExitThread(r)`.
- Fixed by adding `__attribute__((noreturn))` to the inline wrapper.

**`DIFFERENCES.md` incorrect build instructions:**
- Build Notes section said `./configure && make -C src rufus` (bare configure, which
  defaults to Windows target).  Fixed to document `./build-rufus-linux.sh` and the
  `CC=gcc ./configure --with-os=linux` form.

### Tests Run

| Test | Result |
|------|--------|
| `./run_tests.sh --linux-only` | ✅ All tests passed |
| `./run_tests.sh --wine-only` | ✅ All tests passed (was failing before fix) |
| `sudo RUFUS_TEST_DEVICE=/dev/nvme0n2 test_real_device_linux_linux` | ✅ 11 passed |
| `sudo RUFUS_TEST_DEVICE=/dev/nvme0n2 test_e2e_linux_linux` | ✅ 13 passed |
| `test_hash_linux` (force-rebuilt) | ✅ 148 passed (+1 new test) |
| `test_man_page_linux_linux` (force-rebuilt) | ✅ 105 passed |
| `test_cppcheck_linux_linux` (force-rebuilt) | ✅ 20 passed |
| `wine test_hash.exe` (force-rebuilt) | ✅ 83 passed (was crashing) |
| Manual `--device /dev/nvme0n2 --fs fat32 --label QASESSION6 --no-prompt` | ✅ `blkid` shows `LABEL="QASESSION6"` |
| Manual `--device /dev/nvme0n2 --image ~/ubuntu-24.04.4-desktop-amd64.iso --write-as-image --no-prompt` | ✅ ISO 9660 magic `01 CD001` at 0x8000 |
| Manual `--device /dev/nvme0n2 --fs ext3 --label QATEST6 --no-prompt` | ✅ `blkid` shows `TYPE="ext3" LABEL="QATEST6"` |
| Manual `--include-hdds --list-devices --json` | ✅ valid JSON |
| Manual `--version` | ✅ `rufus 4.13.0` |
| Manual `--help` | ✅ all 42 flags shown |

### Spot Checks Performed

| File | Finding |
|------|---------|
| `src/common/hash_db.c` | `FileMatchesHash` null-deref on invalid `str` — **fixed** |
| `src/common/parser.c` | `calloc` args transposed (line 70) — **fixed** |
| `src/common/hash_pe.c` | `calloc` args transposed (line 179) — **fixed** |
| `src/linux/compat/windows.h` | `ExitThread` missing `noreturn` attribute — **fixed** |
| `src/linux/darkmode.c` | All no-op stubs; clean |
| `src/linux/proposed_label.c` | Logic correct and well-tested |
| `src/linux/globals.c` | All globals initialized; correct |
| `src/linux/progress.c` | Ring-buffer speed/ETA logic correct |
| `src/linux/verify.c` | Chunk-by-chunk compare with cancel check; clean |
| `src/linux/format_ext.c` | Full ext2/3 formatter; clean |
| `src/linux/syslinux.c` | libfat/libinstaller integration; clean |
| `src/linux/crash_handler.c` | Signal-safe backtrace; async-signal-safe throughout |
| `src/linux/notify.c` | Three-tier dispatch (libnotify/notify-send/nop); clean |
| `src/linux/progress_title.c` | Simple `build_progress_title`; clean |
| `src/linux/vhd.c` | VHD footer parsing + NBD server; clean |
| `src/linux/image_scan.c` | `ImageScanThread` clean delegation |
| `src/linux/dos.c` | FreeDOS extraction correct |
| `src/linux/download_resume.c` | `.partial` file helpers; clean |
| `src/linux/system_info.c` | TPM/SecureBoot/SetupMode; test-injectable paths |
| `src/linux/status_timeout.c` | Timed status-bar restore; clean |
| `DIFFERENCES.md` | Build instructions incorrect — **fixed** |
| `features.md` | Pending Work section already clean (none); no changes needed |

### Feature Parity (Priority 6) Notes

- All 42 CLI flags present in both `--help` and man page.
- ext3, FAT32, ISO DD write — all verified working via CLI.
- No hardcoded `/dev/nvme0n2` or real device paths in test files.
- `/dev/sda`/`/dev/sdb` in tests are string literals, not device access.

---

## Tips for Next QA Session (session 6 update)

1. **Read this file**, then check `features.md` Pending Work (currently empty).
2. **Use `shuf`** to distribute spot-check effort evenly.
3. **Run `./run_tests.sh --linux-only` AND `--wine-only`** — Wine tests can fail
   independently. The session 6 bug only showed up in Wine.
4. **Force-rebuild suspicious tests** before accepting them as passing.
5. **Test disk `/dev/nvme0n2`** — after session 6 it has Ubuntu 24.04 ISO written (DD mode).
6. **No hardcoded `/dev/nvme0n2` in repo** — use `RUFUS_TEST_DEVICE` env var.
7. **`ExitThread` now has `noreturn`** — hash.c warning resolved.
8. **`FileMatchesHash` now NULL-safe** — both Linux and Wine/Windows glue fixed.
9. **Wine32 missing** — benign warnings; 64-bit Wine tests work fine.

---

## What Was Tested — Session 7 (fuzz + security fixes)

### Bugs Found and Fixed This Session

**Fuzz crash #1 — fuzz harness null-termination bug (harness bug, not production):**
- `tests/fuzz_pe.c` passed a single non-null `uint16_t` (not null-terminated) to
  `FindResourceRva`, which scans for a `0x0000` terminator.  ASAN reported
  heap-buffer-overflow via OOB stack read.
- Fixed: changed to `const uint16_t names[][4]` with explicit `0x0000` terminators.

**Fuzz crash #2 — infinite recursion in `FindResourceRva` (real security bug):**
- A crafted PE with circular resource directory references caused `FindResourceRva`
  to recurse indefinitely → stack overflow.  PE resource trees are max 3 levels deep;
  legitimate trees should never exceed 8.
- Fixed: split into static `FindResourceRva_r(... int depth)` with a
  `MAX_RESOURCE_DEPTH 8` guard; public `FindResourceRva()` calls the helper at depth 0.
- File: `src/common/parser.c`.

**Fuzz crash #3 — OOB heap read via unchecked `e_lfanew` (real security bug):**
- `GetPeArch`, `GetPeSection`, `GetPeSignatureData`, and `RvaToPhysical` all
  dereferenced `&buf[dos_header->e_lfanew]` without first checking that the offset
  plus NT header size fits within the buffer.  A 40-byte crafted PE with
  `e_lfanew=0xFF000000` caused a heap-buffer-overflow.
- Fixed: added `uint32_t buf_size` parameter to all four functions; added bounds
  check `if ((uint32_t)dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > buf_size)`
  in each.  All callers in `src/linux/hash.c` and `src/linux/pki.c` updated to
  pass the buffer length.  `src/windows/rufus.h` declarations split with
  `#ifdef _WIN32` / `#else` to keep Windows callers unchanged.
- Files: `src/common/parser.c`, `src/linux/hash.c`, `src/linux/pki.c`,
  `src/windows/rufus.h`.
- Added 5 regression tests to `tests/test_pe_parser_linux.c`:
  `get_pe_arch_elfanew_oob`, `get_pe_section_elfanew_oob`,
  `rva_to_physical_elfanew_oob`, `get_pe_sig_elfanew_oob`,
  `get_pe_arch_fuzz_crash3_input`.

### GitHub Actions Version Inconsistencies Fixed

- `.github/workflows/linux.yml`: `actions/checkout@v4` → `@v6`,
  `upload-artifact@v4` → `@v6`.
- `.github/workflows/setup.yml`: `upload-artifact/merge@v5` → `@v6`.
  All workflows now consistently use `@v6` for GitHub-provided actions.

### Test Totals This Session

- `./run_tests.sh --linux-only`: all passed (61102+ tests across all suites)
- `make -C tests check-asan`: all passed
- `make -C tests check-cppcheck`: no issues
- `fuzz_pe` 30-second campaign after fixes: 166572 runs, 0 crashes
- `tests/test_pe_parser_linux_linux`: 67 passed, 0 failed

---

## Tips for Next QA Session (session 7 update)

1. **Read this file**, then check `features.md` Pending Work.
2. **PE parsing functions now require `buf_size`** — any new caller of `GetPeArch`,
   `GetPeSection`, `GetPeSignatureData`, `RvaToPhysical` on Linux MUST pass the
   buffer size.  The `#ifdef _WIN32` block in `rufus.h` retains old Windows signatures.
3. **Run `./run_tests.sh --container`** — loopback/block-device root tests not yet
   run from this session (no container available in current env).
4. **Fuzz corpus** is in `tests/corpus/pe/` — run `fuzz_pe corpus/pe/` to resume
   where this session left off.
5. **`FindResourceRva` depth guard** is `MAX_RESOURCE_DEPTH 8` — legitimate PE
   resource trees are max 3 levels; 8 gives headroom without allowing abuse.
6. **No hardcoded `/dev/nvme0n2` in repo** — use `RUFUS_TEST_DEVICE` env var.

---

## What Was Tested — Session 8 (2026-03-04)

### Bugs / Stale Notes Found This Session

No bugs found. The following QA notes from earlier sessions were stale and have
been updated above:

- **Feature 188 / GTK CLI bypass** — was listed as "CRITICAL open"; actually
  resolved in commit `3df14315`.  The GTK binary correctly handles `--device`,
  `--help`, `--version`, `--list-devices` by scanning `argv` before calling
  `g_application_run()`.
- **Minor open issues** (unquoted xdg-open, missing tests) — all resolved in
  sessions 6–7.  QA notes updated.

### Tests Run

| Test | Result |
|------|--------|
| `./run_tests.sh --linux-only` | ✅ All tests passed |
| `./run_tests.sh --wine-only` | ✅ All tests passed |
| `test_ui_smoke_linux_linux` (from tests/) | ✅ 9 passed |
| `test_ui_automation_linux_linux` (from tests/) | ✅ 15 passed |
| `test_exe_cli_linux_linux` | ✅ 31 passed |
| `test_man_page_linux_linux` | ✅ 105 passed |
| `test_cppcheck_linux_linux` | ✅ 20 passed |
| `test_icon_linux_linux` | ✅ 22 passed |
| `test_dev_usb_speed_linux_linux` | ✅ 17 passed |
| Manual: `rufus --version` | ✅ `rufus 4.13.0` |
| Manual: `rufus --help` | ✅ Full CLI help shown |
| Manual: `rufus --list-devices --include-hdds` | ✅ Lists `/dev/nvme0n2` and `/dev/nvme0n1` |
| Manual: FAT32 format of `/dev/nvme0n2` | ✅ `Format completed successfully.` |
| Manual: Ubuntu ISO DD write to `/dev/nvme0n2` | ✅ ISO 9660 magic `01 CD001` verified at offset 0x8000 |
| Manual: `rufus --list-devices` (no HDDs) | ✅ Returns empty list + exit 1 (correct — no removable drives) |

### Spot Checks Performed

| File | Finding |
|------|---------|
| `src/linux/multidev.c` | Clean; all NULL guards present |
| `src/linux/globals.c` | `dialog_handle` defined but only meaningfully used on Windows (OK, no Linux code references it for flashing) |
| `src/common/cregex_parse.c` | Shunting-yard parser; clean |
| `src/linux/icon.c` | `SetAutorun()` correctly queries `hLabel` via `GetWindowTextA`; good test coverage |
| `src/linux/sl_version.c` | Port of Windows `GetSyslinuxVersion()`; clean |
| `src/linux/usb_speed.c` | Speed-to-string lookup; clean; 17 tests pass |
| `src/linux/csm_help.c` | Simple predicate; clean |
| `src/common/hash_db.c` | `StringToHash` / `FileMatchesHash` / etc.; clean; cast to `unsigned char` before `tolower()` is correct |
| `src/linux/pki.c` | OpenSSL-based PKI; `buf_size` bounds checks present (post session 7 fix) |
| `src/linux/rufus.c` | Non-GTK `main()` (dead in GTK build but correct conditional compilation) |
| `src/common/format_ext.c` | Included by platform ext files; clean |
| `src/linux/window_text_bridge.c` | Mutex-protected registry; clean |
| `src/linux/proposed_label.c` | Trivial; clean |

### Coverage Check

All `src/linux/*.c` and `src/common/*.c` files are covered by tests — either
directly via a matching `test_*_linux.c`, via common tests, or via the
integration/e2e suite.  No untested production code identified.

---

---

## What Was Tested — Session 9 (2026-03-05)

### Bugs Found and Fixed This Session

#### CRITICAL: CLI ISO extraction silently skipped (fixed)

**File:** `src/linux/cli.c` — `cli_run()`

**Root cause:** `cli_run()` launched `FormatThread` directly without first calling
`ImageScanThread`. The extraction code path in `format.c` (~line 1202) is gated on
`img_report.is_iso == TRUE`, but since `ImageScanThread` (which calls
`ExtractISO(path, "", TRUE)` in scan-only mode) was never invoked, `img_report`
was all-zero and extraction was silently skipped. Only a trivial `autorun.inf`
was written (32 KB used on a 25 GB disk).

The DD write path (`--write-as-image`) was unaffected — it uses a separate code
path that doesn't check `img_report.is_iso`.

The GTK UI path was also unaffected — `ui_gtk.c` correctly calls
`ImageScanThread` via `g_idle_add` before triggering `FormatThread`.

**Fix:** In `cli_run()`, added a block that creates `ImageScanThread` as a
synchronous thread (via `CreateThread` + `WaitForSingleObject`) when
`opts->image[0] != '\0' && !opts->write_as_image`.

**Regression test:** `cli_image_scan_populates_img_report` added to
`tests/test_e2e_linux.c`. The test creates a tiny ISO with genisoimage, calls
`cli_run()` with that ISO in extraction mode, and asserts `img_report.is_iso ==
TRUE` after the call. `ImageScanThread` stub added to `e2e_linux_glue.c`.

**Verified manually:** Ubuntu 24.04 ISO extracted to FAT32 — 6.3 GB written,
files present, GRUB2 installed.

### Tests Run

| Test | Result |
|------|--------|
| `./run_tests.sh --linux-only` (post-fix) | ✅ 94 passed, 0 failed |
| `./run_tests.sh --wine-only` | ✅ All passed (baseline) |
| `sudo ./tests/test_e2e_linux_linux` | ✅ 14 passed (incl. new regression test) |
| Manual: `rufus --help` | ✅ 42 flags shown |
| Manual: `rufus --version` | ✅ `rufus 4.13.0` |
| Manual: `rufus --list-devices --include-hdds` | ✅ Lists nvme0n1 + nvme0n2 |
| Manual: `rufus --list-devices --json` | ✅ Valid JSON |
| Manual: FAT32 format `/dev/nvme0n2` label QASESS9 | ✅ blkid confirms |
| Manual: NTFS format `/dev/nvme0n2` label QANTFS9 | ✅ blkid confirms |
| Manual: Ubuntu 24.04 ISO DD write | ✅ ISO 9660 magic at 0x8000 |
| Manual: Ubuntu 24.04 ISO extraction (post-fix) | ✅ 6.3 GB written, GRUB2 installed |

### Spot Checks Performed (session 9)

| File | Finding |
|------|---------|
| `src/linux/locale_oobe.c` | Clean |
| `src/linux/iso_config.c` | Clean |
| `src/linux/download_resume.c` | Clean |
| `src/linux/vhd.c` | Clean |
| `src/linux/smart.c` | Clean |
| `src/linux/format_fat32.c` | Clean |
| `src/linux/stdfn.c` | Clean |
| `src/linux/wue.c` | Clean |

### Coverage Check (session 9)

All `src/linux/*.c` and `src/common/*.c` files covered. New `ImageScanThread`
code path now has regression coverage via `cli_image_scan_populates_img_report`.

---

## Tips for Next QA Session (session 9 update)

1. **Read this file**, then check `features.md` Pending Work (currently empty).
2. **GTK binary handles CLI flags** — `--device`, `--help`, `--version`,
   `--list-devices` all bypass GTK and run headless.
3. **PE parsing functions now require `buf_size`** — see session 7 notes.
4. **`FindResourceRva` depth guard** is `MAX_RESOURCE_DEPTH 8`.
5. **Run `./run_tests.sh --container`** if a container runtime is available —
   loopback/root tests provide additional coverage.
6. **UI tests must run from `tests/` directory** (not repo root) — binary path
   resolution uses `../src/rufus` relative to the test binary location.
7. **No hardcoded `/dev/nvme0n2` in repo** — use `RUFUS_TEST_DEVICE` env var.
8. **Fuzz corpus** is in `tests/corpus/pe/` — run periodically.
9. **CLI ISO extraction fix (session 9):** `cli_run()` now calls
   `ImageScanThread` synchronously before `FormatThread` when `--image` is used
   without `--write-as-image`. Regression test in `test_e2e_linux.c`.
   `ImageScanThread` stub in `e2e_linux_glue.c` for the E2E test build.

---

## Session 10 ($(date +%Y-%m-%d))

### Summary

Fuzz testing found a **CRITICAL heap-buffer-overflow** in `GetSbatEntries` (parser.c).
Fixed, regression-tested, and added to corpus. Also fixed the broken `fuzz_iso` build.

### Bug Found and Fixed

**`GetSbatEntries` heap-buffer-overflow** (`src/common/parser.c:841-846`)

- **Type**: heap-buffer-overflow (WRITE of size 8, 0 bytes past end of `calloc` allocation)
- **Trigger**: SBAT data using CR-only (`\r`) or CRLF (`\r\n`) line endings
- **Root cause**: First counting pass only counted original `\n` characters, but
  also converted `\r`→`\n` in-place. Second (allocation) pass then encountered more
  `\n` characters than were allocated for, writing past the end of the array.
- **Fix**: Swap the order — perform `\r`→`\n` conversion *before* the newline count
  increment, so the first pass sees the same newlines as the second pass.
- **Discovered by**: `fuzz_parser` (30-second run, new crash `crash-598321...`)
- **Regression tests**: `GetSbatEntries_cr_line_endings`, `GetSbatEntries_crlf_line_endings`,
  `GetSbatEntries_fuzz_crash_cr_only` added to `tests/test_parser_common.c`
- **Corpus**: crash added to `tests/corpus/parser/`

### Infrastructure Fix: fuzz_iso

`fuzz_iso` was unbuildable (Makefile pointed at non-existent source files).

Fixed:
- `tests/fuzz_iso_glue.c` created — provides stubs for globals and functions not
  available in the subset of sources compiled for fuzzing (bled, WIM, progress, VHD, etc.)
- `tests/Makefile` `fuzz_iso` target rewritten with `FUZZ_ISO_SRC` / `FUZZ_ISO_FLAGS` /
  `FUZZ_ISO_LIBS` variables; uses system libcdio (`-liso9660 -ludf -lcdio`) so no
  need to rebuild the bundled libcdio with clang sanitizers
- `fuzz_iso.c` build comment updated to say `make -C tests fuzz-iso`
- 25-second initial fuzz run: no crashes found (39 code coverage points reached)
- `corpus/iso/` directory created

### GitHub Actions (`act`)

Started `act -W .github/workflows/linux.yml -j Linux-Build-and-Test` — still running
(12+ min) at time of writing; result pending.

### Test Results (session 10)

| Test | Result |
|------|--------|
| `./run_tests.sh --linux-only` | ✅ 94 passed, 0 failed |
| `fuzz_parser` (30 s) | ✅ Found & fixed crash-598321; follow-up 20 s: no new crashes |
| `fuzz_pe` (60 s baseline) | ✅ No crashes |
| `fuzz_iso` (25 s — first ever run) | ✅ No crashes |
| All old crash files in corpus | ✅ No longer reproduce |

### Tips for Next QA Session

1. **Read this file first**, especially the parser.c fix notes.
2. **All three fuzz targets now build**: `fuzz_parser`, `fuzz_pe`, `fuzz_iso`.
   Run them with `make -C tests fuzz-parser / fuzz-pe / fuzz-iso`.
3. **CRLF inputs for SBAT** now handled correctly — regression tests in
   `test_parser_common.c`.
4. **fuzz_iso corpus** at `tests/corpus/iso/` — run longer campaigns; coverage
   is currently low (only 39 points in 25 s) because random bytes rarely form
   a valid ISO9660 sector layout. Seed the corpus with a real minimal ISO.
5. **`act` run** was in progress — verify GitHub Actions pass on CI before merge.
6. **`--container`** loopback tests still not run this session; requires sudo/loop
   devices.
