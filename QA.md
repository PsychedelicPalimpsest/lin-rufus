# Rufus Linux Port — QA Notes

> **Last updated:** 2026-03-04 (session 5)
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

### CRITICAL — GTK binary silently ignores CLI flags (Feature 188)

The shipped binary (`src/rufus`) is compiled with `USE_GTK`.
When GTK processes `argc/argv` via `g_application_run()`, it intercepts
`--help` (shows GTK help, not Rufus CLI help) and rejects all Rufus-specific
flags (`--device`, `--image`, `--fs`, etc.) as "Unknown option".

```
$ ./src/rufus --device /dev/sdb   # fails with "Unknown option --device"
$ ./src/rufus --help              # shows GTK options, NOT cli_print_usage()
```

Root cause: `ui_gtk.c main()` calls `g_application_run()` directly with
`G_APPLICATION_FLAGS_NONE`; there is no `handle-local-options` signal
registered to intercept Rufus flags before GTK sees them.

The non-GTK CLI path (`#ifndef USE_GTK` in `rufus.c`) works correctly when
the binary is built without GTK, but:
1. Building without GTK on Linux currently fails (Windows-specific
   `darkmode.c` includes `dwmapi.h` when `USE_GTK` is not set).
2. There is no documented `--with-ui=cli` or `--without-gtk` build path.

The man page (`doc/rufus.1`) documents all CLI flags as if they work in the
GTK binary — this is inaccurate.

**Tracked as:** Feature 188 ("Test the cli directly by calling the rufus
executable (both via wine and linux)") — not yet resolved.

**Fix direction:** Register CLI options with `g_application_add_main_option_entries()`
and handle them in a `handle-local-options` signal to bypass the GTK
activate path when `--device` is given.

---

### Minor — `device_combo.c` uses unquoted path in xdg-open command

`device_open_in_fm_build_cmd()` builds `"xdg-open /dev/sdX"` without quoting
the path:

```c
snprintf(out, sz, "xdg-open %s", dev_path);   // unquoted!
```

In practice device paths come from sysfs (`/dev/sda`, `/dev/nvme0n1p1`) and
never contain spaces or shell metacharacters, so there is no real exploit
path.  However, it is a code quality issue — the function should quote the
path for correctness:

```c
snprintf(out, sz, "xdg-open '%s'", dev_path);
```

No dedicated unit test covers `device_open_in_fm_build_cmd()`.

---

### Minor — `ntfsfix.c` uses `system()` with only outer-quote protection

`RunNtfsFix()` builds `ntfsfix "<path>"` and calls `system()`.  A partition
path with embedded double-quote characters would break out of the quoting.
Again, partition paths from sysfs are safe, but consider switching to
`execv()` (no shell expansion) or quoting more robustly.

---

### Minor — Missing dedicated unit tests

The following source files have no directly corresponding test file:

| File | Notes |
|------|-------|
| `ntfsfix.c` | Single function `RunNtfsFix()`; easy to add a mock-system test |
| `device_combo.c` | `device_open_in_fm_build_cmd()`; should have string tests |
| `dump_fat.c` | Diagnostic helper; low priority |
| `proposed_label.c` | Very small; logic is correct but untested |

`proposed_label.c` is exercised indirectly through the GTK UI, and the
function is simple enough that the risk is low.

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
