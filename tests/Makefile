# tests/Makefile
#
# Build and run tests natively (Linux) and via Wine (Windows/MinGW).
#
# Targets:
#   all          - build all Linux and Windows test binaries
#   linux        - build Linux test binaries only
#   windows      - build Windows test binaries only (requires MinGW)
#   run-linux    - build and run Linux tests
#   run-wine     - build and run Windows tests via Wine
#   clean        - remove all generated binaries
#
# Toolchain overrides (environment variables):
#   CC       - Linux C compiler   (default: gcc)
#   CC_WIN   - Windows C compiler (default: x86_64-w64-mingw32-gcc)

SRC_DIR  := ../src
COMMON   := $(SRC_DIR)/common
COMPAT   := $(SRC_DIR)/linux/compat

CFLAGS_COMMON := -I. -I$(COMMON) -Wall -Wextra -g

# Linux toolchain
CC       ?= gcc
CFLAGS_LINUX := $(CFLAGS_COMMON)

# Windows toolchain (MinGW cross-compiler)
CC_WIN   ?= x86_64-w64-mingw32-gcc
CFLAGS_WIN := $(CFLAGS_COMMON)

# Source files shared by all tests
CREGEX_SRC := $(COMMON)/cregex_compile.c \
              $(COMMON)/cregex_parse.c   \
              $(COMMON)/cregex_vm.c

# Discover all test_*.c files automatically
TEST_SRCS  := $(wildcard test_*.c)
LINUX_BINS := $(TEST_SRCS:.c=_linux)
WIN_BINS   := $(TEST_SRCS:.c=.exe)

# ---------------------------------------------------------------------------
# Per-test extra flags
# Add entries here when a test needs additional include paths or libraries.
# ---------------------------------------------------------------------------

# Threading tests need the compat headers and pthreads
CFLAGS_LINUX_test_threading  := -I$(COMPAT)
LDFLAGS_LINUX_test_threading := -lpthread

# msg_dispatch tests: need compat headers, the dispatch .c, and pthreads
MSG_DISPATCH_SRC := $(COMPAT)/msg_dispatch.c
CFLAGS_LINUX_test_msg_dispatch  := -I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux
LDFLAGS_LINUX_test_msg_dispatch := -lpthread
EXTRA_SRC_LINUX_test_msg_dispatch := $(MSG_DISPATCH_SRC)

# stdfn tests: htab + StrArray — Linux compat + windows headers + linux stdfn.c
STDFN_SRC := $(SRC_DIR)/linux/stdfn.c
CFLAGS_LINUX_test_stdfn  := -I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux -Wno-implicit-function-declaration
EXTRA_SRC_LINUX_test_stdfn := $(STDFN_SRC)

# dev_linux tests: device enumeration via fake sysfs
DEV_LINUX_SRC := $(SRC_DIR)/linux/dev.c $(SRC_DIR)/linux/stdfn.c
CFLAGS_LINUX_test_dev_linux  := -I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
                                 -Wno-implicit-function-declaration -Wno-unused-function
EXTRA_SRC_LINUX_test_dev_linux := $(DEV_LINUX_SRC)

.PHONY: all linux windows run-linux run-wine clean

all: linux windows

linux: $(LINUX_BINS)

windows: $(WIN_BINS)

# Pattern rules for Linux binaries
# We look up per-test extra flags by deriving the test name from the target.
_test_name = $(patsubst %_linux,%,$(notdir $@))

%_linux: %.c $(CREGEX_SRC)
	$(CC) $(CFLAGS_LINUX) $(CFLAGS_LINUX_$(_test_name)) -o $@ $< $(CREGEX_SRC) \
	    $(EXTRA_SRC_LINUX_$(_test_name)) $(LDFLAGS_LINUX_$(_test_name))

# Pattern rules for Windows binaries
%.exe: %.c $(CREGEX_SRC)
	$(CC_WIN) $(CFLAGS_WIN) -o $@ $^

run-linux: linux
	@failed=0; \
	for bin in $(LINUX_BINS); do \
	  printf '\n=== %s ===\n' "$$bin"; \
	  ./$$bin || failed=$$((failed + 1)); \
	done; \
	[ $$failed -eq 0 ] || { echo "$$failed test binary/binaries FAILED"; exit 1; }

run-wine: windows
	@command -v wine >/dev/null 2>&1 || { echo "wine not found; skipping Windows tests"; exit 0; }; \
	failed=0; \
	for bin in $(WIN_BINS); do \
	  printf '\n=== %s (wine) ===\n' "$$bin"; \
	  wine ./$$bin || failed=$$((failed + 1)); \
	done; \
	[ $$failed -eq 0 ] || { echo "$$failed test binary/binaries FAILED under Wine"; exit 1; }

clean:
	rm -f $(LINUX_BINS) $(WIN_BINS)
