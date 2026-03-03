# Rufus Linux Port — QA Notes

> **Last updated:** 2026-03-03  
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

## Tips for Next QA Session

1. **Start by reading this file**, then check `features.md` Pending Work.
2. **Use `shuf` to select random spot-check targets** (as per task instructions).
3. **Run the full test suite first** to establish a passing baseline before
   making any code changes.  **Always force-rebuild the specific test binary**
   (`make -B test_<name>_linux`) before accepting "up to date" as a pass —
   stale binaries masked the 3 failing tests this session.
4. **Feature 188/189** (CLI binary integration) remains the highest-priority
   open item; any developer working on GTK CLI integration should verify
   with `sudo rufus --device /dev/nvme0n2 --fs fat32 --no-prompt` returning 0.
5. **Wine** only supports 64-bit on this machine; the Windows-binary tests
   via Wine may show `wine32 is missing` warnings — ignore them as long as
   Wine tests still pass for 64-bit code.
6. **The test disk `/dev/nvme0n2`** is safe to use destructively; re-image
   with any format you need.  After this session it has the Ubuntu 24.04 ISO
   written to it (ISO 9660 magic verified).
7. **No TODO/FIXME/HACK/BUG comments** were found in `src/linux/*.c` — the
   codebase is clean in that regard.
8. **`test_ui_linux_linux` 56 tests** — 7 cover `device_combo`, 7 cover
   `hyperlink`, 8 cover `proposed_label`.  These tests previously passed
   stale because the binary was not rebuilt.  Always force rebuild suspicious
   tests.
