# Rufus Linux Build & Test Dependencies

All dependencies are installed by [`tests/install-deps.sh`](tests/install-deps.sh), which is
the single source of truth used by both the [Dockerfile](tests/Dockerfile) and the
[GitHub Actions workflow](.github/workflows/linux.yml).

The target platform is **Ubuntu 22.04** (the same image used in CI).  Package names
and versions may differ on other distributions.

---

## Build dependencies

These are required to configure and compile Rufus for Linux.

| Package | Ubuntu 22.04 name | Purpose |
|---|---|---|
| C build toolchain | `build-essential` | `gcc`, `ld`, `ar`, `make` |
| GCC 12 | `gcc-12` | `configure.ac` requires `-Wbidi-chars=none` (added in GCC 12) |
| Autotools | `autoconf automake libtool` | `./configure` / `make` build system |
| pkg-config | `pkg-config` | Locates library compile/link flags |
| GTK 3 (≥ 3.20) | `libgtk-3-dev` | GTK UI |
| libcurl (≥ 7.50) | `libcurl4-openssl-dev` | HTTP downloads |
| OpenSSL | `libssl-dev` | TLS / certificate handling |
| libudev | `libudev-dev` | Kernel device events (udev) |
| libblkid | `libblkid-dev` | Block device probing |
| fontconfig | `libfontconfig1-dev` | Font lookup |
| libnotify (≥ 0.7) | `libnotify-dev` | Desktop notifications |
| libxml2 | `libxml2-dev` | XML config / update manifests |
| zlib | `zlib1g-dev` | Compression |
| libcdio | `libcdio-dev` | CD/optical-disc I/O (headers for bundled copy) |
| libiso9660 | `libiso9660-dev` | ISO 9660 filesystem headers |
| libudf | `libudf-dev` | UDF filesystem headers |

> **Note on bundled libcdio:** `src/libcdio/` contains a vendored copy of
> libcdio whose `udf_setpos()` and related symbols differ from the system
> library.  The test `Makefile` links against the bundled static archives
> (`src/libcdio/udf/libudf.a`, etc.) via the `CDIO_LIBS` variable rather than
> the system `-ludf`/`-lcdio` flags.  The `*-dev` packages above are still
> needed for the header files.

---

## Test build dependencies

These are required to compile and run the test suite (`make -C tests linux`).

| Package | Ubuntu 22.04 name | Purpose |
|---|---|---|
| wimtools | `wimtools` | WIM image creation/inspection used by image-scan tests |
| libcdio utilities | `libcdio-utils` | `cd-info`, `iso-info` command-line tools |

---

## Test runtime dependencies

These tools are invoked at runtime by the tests.  Tests that need a missing
tool print `[SKIP]` and continue rather than failing hard.

| Tool | Ubuntu 22.04 package | Used by |
|---|---|---|
| `mkfs.fat` | `dosfstools` | FAT12/16/32 format tests |
| `mkntfs` | `ntfs-3g` | NTFS format tests |
| `mkfs.exfat` | `exfatprogs` | exFAT format tests |
| `mkudffs` | `udftools` | UDF format tests (skipped if absent) |
| `losetup` | `util-linux` | Loopback device tests (root-only) |

---

## ASAN / UBSan dependencies

Required for `make -C tests check-asan`.

| Package | Ubuntu 22.04 name | Purpose |
|---|---|---|
| AddressSanitizer | `libasan6` | Memory error detection (GCC 12 runtime) |
| UndefinedBehaviorSanitizer | `libubsan1` | Undefined behaviour detection |

---

## Static analysis dependency

Required for `make -C tests check-cppcheck`.

| Package | Ubuntu 22.04 name | Purpose |
|---|---|---|
| cppcheck | `cppcheck` | C static analysis |

---

## Cross-compilation dependency (Windows tests)

Required for `make -C tests windows` and Wine-based tests.

| Package | Ubuntu 22.04 name | Purpose |
|---|---|---|
| MinGW-w64 | `mingw-w64` | Cross-compiler targeting Windows (`x86_64-w64-mingw32-gcc`) |

---

## Running all tests locally

```bash
# Install all dependencies (requires sudo)
sudo bash tests/install-deps.sh

# Configure and build
./configure --with-os=linux
make -j$(nproc)

# Run Linux tests
./run_tests.sh --linux-only

# Run ASAN + UBSan tests
make -C tests check-asan

# Run cppcheck
make -C tests check-cppcheck

# Run root-requiring loopback tests (requires root + loop device support)
sudo ./run_tests.sh --root-only

# Run everything in Docker (recommended for root tests)
docker build -t rufus-test-env tests/
./run_tests.sh --full-container    # linux + ASAN + cppcheck + root
# or:
./run_tests.sh --container         # root tests only
```
