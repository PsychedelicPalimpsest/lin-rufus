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
# Tests whose names end in _linux or whose sources are Linux-only are excluded
# from the Windows build (no Windows implementation exists for them).
WIN_EXCLUDE_SRCS := $(wildcard test_*_linux.c) test_device_monitor.c
WIN_BINS   := $(filter-out $(WIN_EXCLUDE_SRCS:.c=.exe), $(TEST_SRCS:.c=.exe))

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

# Shared flags for anything that links stdfn.c (fontconfig, freedos_data weak sym)
FONTCONFIG_CFLAGS := $(shell pkg-config --cflags fontconfig 2>/dev/null)
FONTCONFIG_LIBS   := $(shell pkg-config --libs   fontconfig 2>/dev/null)

# stdfn tests: htab + StrArray — Linux compat + windows headers + linux stdfn.c
STDFN_SRC := $(SRC_DIR)/linux/stdfn.c
CFLAGS_LINUX_test_stdfn  := -I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux -Wno-implicit-function-declaration $(FONTCONFIG_CFLAGS)
EXTRA_SRC_LINUX_test_stdfn := $(STDFN_SRC)
LDFLAGS_LINUX_test_stdfn := $(FONTCONFIG_LIBS)

# dev_linux tests: device enumeration via fake sysfs
DEV_LINUX_SRC := $(SRC_DIR)/linux/dev.c $(SRC_DIR)/linux/stdfn.c
CFLAGS_LINUX_test_dev_linux  := -I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
                                 -Wno-implicit-function-declaration -Wno-unused-function \
                                 $(FONTCONFIG_CFLAGS)
EXTRA_SRC_LINUX_test_dev_linux := $(DEV_LINUX_SRC)
LDFLAGS_LINUX_test_dev_linux := $(FONTCONFIG_LIBS)

# device_monitor tests: lifecycle, callback dispatch, debounce
DEVICE_MONITOR_SRC := $(SRC_DIR)/linux/device_monitor.c
CFLAGS_LINUX_test_device_monitor  := -I$(SRC_DIR)/common
LDFLAGS_LINUX_test_device_monitor := -lpthread -ludev
EXTRA_SRC_LINUX_test_device_monitor := $(DEVICE_MONITOR_SRC)

# parser tests: common parser + linux-specific file I/O parser
PARSER_SRC := $(COMMON)/parser.c $(SRC_DIR)/linux/parser.c \
              $(COMMON)/localization.c $(SRC_DIR)/linux/stdfn.c
CFLAGS_LINUX_test_parser  := -I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
                              -Wno-unused-function -Wno-sign-compare \
                              -Wno-implicit-function-declaration \
                              $(shell pkg-config --cflags fontconfig 2>/dev/null)
LDFLAGS_LINUX_test_parser := $(shell pkg-config --libs fontconfig 2>/dev/null)
EXTRA_SRC_LINUX_test_parser := $(PARSER_SRC)

# drive_linux tests: Linux drive access (GetPhysicalName, partition parsing, etc.)
# (full entry below overrides this — kept here for clarity on variable names)

# format_linux tests: FAT32 and ext2/ext3 formatting via POSIX image files
FORMAT_LINUX_SRC := $(SRC_DIR)/linux/format.c \
                    $(SRC_DIR)/linux/format_fat32.c \
                    $(SRC_DIR)/linux/format_ext.c \
                    $(SRC_DIR)/linux/format_ext_tools.c \
                    $(SRC_DIR)/linux/drive.c \
                    $(SRC_DIR)/linux/window_text_bridge.c \
                    $(SRC_DIR)/ext2fs/posix_io.c
EXT2FS_LIB := $(SRC_DIR)/ext2fs/libext2fs.a
BLED_LIB   := $(SRC_DIR)/bled/libbled.a
FORMAT_MS_SRC := $(SRC_DIR)/ms-sys/file.c \
                 $(SRC_DIR)/ms-sys/br.c \
                 $(SRC_DIR)/ms-sys/fat16.c \
                 $(SRC_DIR)/ms-sys/fat32.c \
                 $(SRC_DIR)/ms-sys/partition_info.c
CFLAGS_LINUX_test_format_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR) -I$(SRC_DIR)/ext2fs -I$(SRC_DIR)/ms-sys/inc -I$(SRC_DIR)/bled \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers
LDFLAGS_LINUX_test_format_linux := -lblkid
EXTRA_SRC_LINUX_test_format_linux := $(FORMAT_LINUX_SRC) $(FORMAT_MS_SRC) $(EXT2FS_LIB) $(BLED_LIB) format_linux_glue.c

# format_ntfs_exfat_linux tests: NTFS and exFAT formatting via mkntfs/mkfs.exfat
FORMAT_NTFS_EXFAT_LINUX_SRC := $(SRC_DIR)/linux/format.c \
                                $(SRC_DIR)/linux/format_fat32.c \
                                $(SRC_DIR)/linux/format_ext.c \
                                $(SRC_DIR)/linux/format_ext_tools.c \
                                $(SRC_DIR)/linux/drive.c \
                                $(SRC_DIR)/linux/window_text_bridge.c \
                                $(SRC_DIR)/ext2fs/posix_io.c
CFLAGS_LINUX_test_format_ntfs_exfat_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR) -I$(SRC_DIR)/ext2fs -I$(SRC_DIR)/ms-sys/inc -I$(SRC_DIR)/bled \
	-I$(COMMON) \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers
LDFLAGS_LINUX_test_format_ntfs_exfat_linux := -lblkid
EXTRA_SRC_LINUX_test_format_ntfs_exfat_linux := \
	$(FORMAT_NTFS_EXFAT_LINUX_SRC) $(FORMAT_MS_SRC) $(EXT2FS_LIB) $(BLED_LIB) \
	format_ntfs_exfat_glue.c

# format_thread_linux tests: FormatThread end-to-end, ClearMBRGPT, WriteMBR, WriteDrive
FORMAT_THREAD_LINUX_SRC := \
	$(SRC_DIR)/linux/format.c \
	$(SRC_DIR)/linux/format_fat32.c \
	$(SRC_DIR)/linux/format_ext.c \
	$(SRC_DIR)/linux/format_ext_tools.c \
	$(SRC_DIR)/linux/drive.c \
	$(SRC_DIR)/linux/window_text_bridge.c \
	$(SRC_DIR)/linux/verify.c \
	$(SRC_DIR)/ext2fs/posix_io.c \
	$(FORMAT_MS_SRC)
CFLAGS_LINUX_test_format_thread_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR) -I$(SRC_DIR)/ext2fs -I$(SRC_DIR)/ms-sys/inc -I$(SRC_DIR)/bled \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers
LDFLAGS_LINUX_test_format_thread_linux := -lpthread -lblkid
EXTRA_SRC_LINUX_test_format_thread_linux := $(FORMAT_THREAD_LINUX_SRC) $(EXT2FS_LIB) $(BLED_LIB) format_thread_linux_glue.c

# pe_parser_linux tests: PE binary parsing (GetPeArch, GetPeSection, RvaToPhysical, etc.)
PE_PARSER_SRC := $(COMMON)/parser.c $(SRC_DIR)/linux/parser.c \
                 $(COMMON)/localization.c $(SRC_DIR)/linux/stdfn.c
CFLAGS_LINUX_test_pe_parser_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter
EXTRA_SRC_LINUX_test_pe_parser_linux := $(PE_PARSER_SRC)

# drive_linux tests: block device ops, partition parsing, GPT/MBR creation
DRIVE_LINUX_SRC := $(SRC_DIR)/linux/drive.c $(SRC_DIR)/linux/stdfn.c \
                   $(SRC_DIR)/linux/stdio.c $(SRC_DIR)/linux/globals.c \
                   $(SRC_DIR)/linux/ui.c \
                   $(SRC_DIR)/linux/parser.c \
                   $(FORMAT_MS_SRC)
CFLAGS_LINUX_test_drive_linux  := -I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
                                   -I$(SRC_DIR)/ms-sys/inc -I$(SRC_DIR) -I$(SRC_DIR)/bled \
                                   -Wno-implicit-function-declaration -Wno-unused-function \
                                   -Wno-sign-compare -Wno-unused-parameter
LDFLAGS_LINUX_test_drive_linux := -lblkid
EXTRA_SRC_LINUX_test_drive_linux := $(DRIVE_LINUX_SRC) $(BLED_LIB)

# drive2_linux tests: GUID, partition types, AnalyzeMBR/PBR, RefreshLayout,
#                     GetDriveTypeFromIndex, GetDriveLabel
DRIVE2_LINUX_SRC := $(SRC_DIR)/linux/drive.c $(SRC_DIR)/linux/stdfn.c \
                    $(SRC_DIR)/linux/stdio.c $(SRC_DIR)/linux/globals.c \
                    $(SRC_DIR)/linux/ui.c \
                    $(FORMAT_MS_SRC)
CFLAGS_LINUX_test_drive2_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR)/ms-sys/inc -I$(SRC_DIR) -I$(SRC_DIR)/bled \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter
LDFLAGS_LINUX_test_drive2_linux := -lblkid
EXTRA_SRC_LINUX_test_drive2_linux := $(DRIVE2_LINUX_SRC) $(BLED_LIB)

# partition_ops_linux tests: DeletePartition, GetEspOffset, ToggleEsp
PARTITION_OPS_LINUX_SRC := $(SRC_DIR)/linux/drive.c $(SRC_DIR)/linux/stdfn.c \
                            $(SRC_DIR)/linux/stdio.c $(SRC_DIR)/linux/globals.c \
                            $(SRC_DIR)/linux/ui.c \
                            $(FORMAT_MS_SRC)
CFLAGS_LINUX_test_partition_ops_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR)/ms-sys/inc -I$(SRC_DIR) -I$(SRC_DIR)/bled \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter
LDFLAGS_LINUX_test_partition_ops_linux := -lblkid
EXTRA_SRC_LINUX_test_partition_ops_linux := $(PARTITION_OPS_LINUX_SRC) $(BLED_LIB)

# uefi_ntfs_linux tests: load_uefi_ntfs_data, write_uefi_ntfs_partition,
#                        uefi_ntfs_needs_extra_partition, CreatePartition+XP_UEFI_NTFS
CFLAGS_LINUX_test_uefi_ntfs_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR)/ms-sys/inc -I$(SRC_DIR) -I$(SRC_DIR)/bled \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter
LDFLAGS_LINUX_test_uefi_ntfs_linux := -lblkid
EXTRA_SRC_LINUX_test_uefi_ntfs_linux := $(PARTITION_OPS_LINUX_SRC) $(BLED_LIB)

# stdio_linux tests: RunCommandWithProgress, SizeToHumanReadable, WindowsErrorString,
#                    ListDirectoryContent, ExtractZip
STDIO_LINUX_SRC := $(SRC_DIR)/linux/stdio.c $(SRC_DIR)/linux/stdfn.c \
                   $(COMMON)/localization.c $(COMMON)/parser.c \
                   $(SRC_DIR)/linux/parser.c
CFLAGS_LINUX_test_stdio_linux  := -I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
                                   -I$(SRC_DIR)/bled -I$(SRC_DIR) -I$(COMMON) \
                                   -Wno-implicit-function-declaration -Wno-unused-function \
                                   -Wno-sign-compare -Wno-unused-parameter \
                                   $(FONTCONFIG_CFLAGS)
LDFLAGS_LINUX_test_stdio_linux := -lz $(FONTCONFIG_LIBS)
EXTRA_SRC_LINUX_test_stdio_linux := $(STDIO_LINUX_SRC) $(BLED_LIB)

# ui_linux tests: version initialization
CFLAGS_LINUX_test_ui_linux := -I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
                               -Wno-unused-function -Wno-sign-compare \
                               -Wno-implicit-function-declaration \
                               $(FONTCONFIG_CFLAGS)
LDFLAGS_LINUX_test_ui_linux := $(FONTCONFIG_LIBS)
EXTRA_SRC_LINUX_test_ui_linux := $(SRC_DIR)/linux/globals.c \
                                  $(SRC_DIR)/linux/device_combo.c

# notify_linux tests: desktop notification bridge (notify_build_cmd, rufus_notify, notify_format_message)
CFLAGS_LINUX_test_notify_linux := -I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
                                   -D_GNU_SOURCE -DRUFUS_TEST \
                                   -Wno-unused-function -Wno-sign-compare \
                                   -Wno-unused-parameter -Wno-implicit-function-declaration
EXTRA_SRC_LINUX_test_notify_linux := $(SRC_DIR)/linux/notify.c

# crash_handler_linux tests: signal handler, log file creation, backtrace
CFLAGS_LINUX_test_crash_handler_linux := -I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
                                          -D_GNU_SOURCE -DRUFUS_TEST \
                                          -Wno-unused-function -Wno-sign-compare \
                                          -Wno-unused-parameter
EXTRA_SRC_LINUX_test_crash_handler_linux := $(SRC_DIR)/linux/crash_handler.c

# compat_linux tests: shlwapi.h (PathFileExistsA, PathCombineA) and shellapi.h (ShellExecuteA)
# Pure header-only implementation — no extra .c sources needed
CFLAGS_LINUX_test_compat_linux := -I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
                                   -D_GNU_SOURCE \
                                   -Wno-unused-function -Wno-unused-parameter \
                                   -Wno-implicit-function-declaration

# stdlg_linux tests: NotificationEx, FileDialog, CustomSelectionDialog, ListDialog
# Links against stdlg.c (which provides test-mode injection) and stdfn.c only;
# stdio.c is NOT needed here (stdlg uses stdio.h directly, not rufus stdio.c)
STDLG_LINUX_SRC := $(SRC_DIR)/linux/stdlg.c $(SRC_DIR)/linux/stdfn.c
CFLAGS_LINUX_test_stdlg_linux  := -I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
                                   -Wno-implicit-function-declaration -Wno-unused-function \
                                   -Wno-sign-compare -Wno-unused-parameter \
                                   $(shell pkg-config --cflags fontconfig 2>/dev/null)
LDFLAGS_LINUX_test_stdlg_linux := -lpthread $(shell pkg-config --libs fontconfig 2>/dev/null)
EXTRA_SRC_LINUX_test_stdlg_linux := $(STDLG_LINUX_SRC)

# iso_linux tests: ISO image scanning and extraction via system libcdio
ISO_LINUX_SRC := $(SRC_DIR)/linux/iso.c \
                 $(SRC_DIR)/linux/stdfn.c \
                 $(SRC_DIR)/linux/stdio.c \
                 $(SRC_DIR)/linux/ui.c \
                 $(SRC_DIR)/linux/localization.c \
                 $(COMMON)/parser.c \
                 $(COMMON)/localization.c
CFLAGS_LINUX_test_iso_linux := \
	-DRUFUS_TEST \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR) -I$(SRC_DIR)/syslinux -I$(SRC_DIR)/syslinux/libfat \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers
LDFLAGS_LINUX_test_iso_linux := -lcdio -liso9660 -ludf $(SRC_DIR)/syslinux/libfat/libfat.a
EXTRA_SRC_LINUX_test_iso_linux := $(ISO_LINUX_SRC) $(BLED_LIB) iso_linux_glue.c

# test_iso_save_linux — OpticalDiscSaveImage / iso_save_run_sync tests
# Uses ISO_SAVE_LINUX_SRC (same as ISO_LINUX_SRC, minus ui.c) so the test
# file can provide its own tracking stubs for _UpdateProgressWithInfo and
# PostMessageA without conflicts.
ISO_SAVE_LINUX_SRC := $(SRC_DIR)/linux/iso.c \
                      $(SRC_DIR)/linux/stdfn.c \
                      $(SRC_DIR)/linux/stdio.c \
                      $(SRC_DIR)/linux/localization.c \
                      $(COMMON)/parser.c \
                      $(COMMON)/localization.c
CFLAGS_LINUX_test_iso_save_linux := \
	-DRUFUS_TEST \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR) -I$(SRC_DIR)/syslinux -I$(SRC_DIR)/syslinux/libfat \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers
LDFLAGS_LINUX_test_iso_save_linux := -lcdio -liso9660 -ludf $(SRC_DIR)/syslinux/libfat/libfat.a
EXTRA_SRC_LINUX_test_iso_save_linux := $(ISO_SAVE_LINUX_SRC) $(BLED_LIB) iso_save_linux_glue.c

# HashThread/IndividualHashThread tests additionally need:
#   - stdio.c (uprintf), stdfn.c (safe_* helpers), ui.c (UpdateProgress stubs),
#     stdlg.c (MyDialogBox stub), msg_dispatch.c (PostMessage compat bridge)
HASH_SRC := hash_linux_glue.c
HASH_LINUX_EXTRA := \
	$(SRC_DIR)/linux/stdio.c \
	$(SRC_DIR)/linux/stdfn.c \
	$(SRC_DIR)/linux/ui.c \
	$(SRC_DIR)/linux/stdlg.c \
	$(SRC_DIR)/linux/parser.c \
	$(SRC_DIR)/linux/pki.c \
	$(SRC_DIR)/linux/localization.c \
	$(SRC_DIR)/common/parser.c \
	$(SRC_DIR)/common/localization.c \
	$(COMPAT)/msg_dispatch.c
CFLAGS_LINUX_test_hash := -I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
                          -I$(SRC_DIR)/common -I$(SRC_DIR)/bled -I$(SRC_DIR) \
                          -D_GNU_SOURCE -DRUFUS_TEST \
                          -Wno-unused-function -Wno-sign-compare \
                          -Wno-implicit-function-declaration -Wno-unused-parameter \
                          -Wno-missing-field-initializers \
                          -march=native
LDFLAGS_LINUX_test_hash := -lpthread -lssl -lcrypto $(shell pkg-config --libs fontconfig 2>/dev/null)
EXTRA_SRC_LINUX_test_hash := $(HASH_SRC) $(HASH_LINUX_EXTRA)

# iso_hashes: fixture-based ISO hash regression tests (item 86)
CFLAGS_LINUX_test_iso_hashes := $(CFLAGS_LINUX_test_hash)
LDFLAGS_LINUX_test_iso_hashes := $(LDFLAGS_LINUX_test_hash)
EXTRA_SRC_LINUX_test_iso_hashes := $(HASH_SRC) $(HASH_LINUX_EXTRA)

CFLAGS_WIN_test_hash := -I$(SRC_DIR)/windows -I$(SRC_DIR)/common \
                        -Wno-unused-function -Wno-sign-compare \
                        -Wno-implicit-function-declaration -Wno-unused-parameter \
                        -march=native
EXTRA_SRC_WIN_test_hash := hash_win_glue.c

# net_linux tests: HTTP download via libcurl
# The test file includes src/linux/net.c directly (no glue file needed).
# net.c itself needs stdfn.c for safe_strlen/safe_free, and stdio.c for uprintf.
NET_LINUX_SRC := $(SRC_DIR)/linux/net.c \
                 $(SRC_DIR)/linux/download_resume.c \
                 $(SRC_DIR)/linux/stdfn.c \
                 $(SRC_DIR)/linux/stdio.c \
                 net_linux_glue.c
CFLAGS_LINUX_test_net_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR) -I$(COMMON) -I$(SRC_DIR)/bled -I$(SRC_DIR)/../res \
	-D_GNU_SOURCE -DRUFUS_TEST \
	-Wno-unused-function -Wno-sign-compare \
	-Wno-implicit-function-declaration -Wno-unused-parameter \
	-Wno-missing-field-initializers
LDFLAGS_LINUX_test_net_linux := -lcurl -lpthread -lssl -lcrypto $(shell pkg-config --libs fontconfig 2>/dev/null)
EXTRA_SRC_LINUX_test_net_linux := $(NET_LINUX_SRC)

# dbx_linux tests: DBX caching, timestamp URL building, UseLocalDbx().
# Uses real common/parser.c for settings (ReadSetting64/WriteSetting64) instead
# of the stubs in net_linux_glue.c, allowing INI-file-backed settings tests.
DBX_LINUX_SRC := $(SRC_DIR)/linux/net.c \
                 $(SRC_DIR)/linux/download_resume.c \
                 $(SRC_DIR)/linux/stdfn.c \
                 $(SRC_DIR)/linux/stdio.c \
                 $(SRC_DIR)/linux/parser.c \
                 $(COMMON)/parser.c \
                 $(COMMON)/localization.c \
                 dbx_linux_glue.c
CFLAGS_LINUX_test_dbx_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR) -I$(COMMON) -I$(SRC_DIR)/bled -I$(SRC_DIR)/../res \
	-Wno-unused-function -Wno-sign-compare \
	-Wno-implicit-function-declaration -Wno-unused-parameter \
	-Wno-missing-field-initializers
LDFLAGS_LINUX_test_dbx_linux := -lcurl -lpthread -lssl -lcrypto $(shell pkg-config --libs fontconfig 2>/dev/null)
EXTRA_SRC_LINUX_test_dbx_linux := $(DBX_LINUX_SRC)

# fido_linux tests: Fido script version-check (fido_check_url_updated).
# Uses real common/parser.c for settings (ReadSettingStr/WriteSettingStr).
FIDO_LINUX_SRC := $(SRC_DIR)/linux/net.c \
                  $(SRC_DIR)/linux/download_resume.c \
                  $(SRC_DIR)/linux/stdfn.c \
                  $(SRC_DIR)/linux/stdio.c \
                  $(SRC_DIR)/linux/parser.c \
                  $(COMMON)/parser.c \
                  $(COMMON)/localization.c \
                  fido_linux_glue.c
CFLAGS_LINUX_test_fido_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR) -I$(COMMON) -I$(SRC_DIR)/bled -I$(SRC_DIR)/../res \
	-Wno-unused-function -Wno-sign-compare \
	-Wno-implicit-function-declaration -Wno-unused-parameter \
	-Wno-missing-field-initializers
LDFLAGS_LINUX_test_fido_linux := -lcurl -lpthread -lssl -lcrypto $(shell pkg-config --libs fontconfig 2>/dev/null)
EXTRA_SRC_LINUX_test_fido_linux := $(FIDO_LINUX_SRC)

# settings_linux tests: FileIO, ReadSetting*/WriteSetting*, XDG path init.
SETTINGS_LINUX_SRC := \
	$(SRC_DIR)/linux/stdfn.c \
	$(SRC_DIR)/linux/parser.c \
	$(COMMON)/parser.c \
	$(COMMON)/localization.c \
	$(SRC_DIR)/linux/stdio.c \
	$(SRC_DIR)/linux/ui.c \
	$(SRC_DIR)/linux/stdlg.c \
	settings_linux_glue.c
CFLAGS_LINUX_test_settings_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR) -I$(COMMON) \
	-Wno-unused-function -Wno-sign-compare \
	-Wno-implicit-function-declaration -Wno-unused-parameter \
	-Wno-missing-field-initializers
EXTRA_SRC_LINUX_test_settings_linux := $(SETTINGS_LINUX_SRC)

# update_check_linux tests: first-run consent dialog for SetUpdateCheck()
# Uses the same sources as settings_linux (stdfn + parser + stdlg) for the full pipeline
CFLAGS_LINUX_test_update_check_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR) -I$(COMMON) \
	-Wno-unused-function -Wno-sign-compare \
	-Wno-implicit-function-declaration -Wno-unused-parameter \
	-Wno-missing-field-initializers
LDFLAGS_LINUX_test_update_check_linux := -lpthread $(shell pkg-config --libs fontconfig 2>/dev/null)
EXTRA_SRC_LINUX_test_update_check_linux := $(SETTINGS_LINUX_SRC)

# badblocks_linux tests: bad block detection via pread/pwrite on temp files
BADBLOCKS_LINUX_SRC := $(SRC_DIR)/linux/badblocks.c
CFLAGS_LINUX_test_badblocks_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR) -I$(SRC_DIR)/ext2fs \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers
LDFLAGS_LINUX_test_badblocks_linux := -lrt
EXTRA_SRC_LINUX_test_badblocks_linux := $(BADBLOCKS_LINUX_SRC)

# badblocks_integration_linux tests: FormatThread bad-blocks pre-scan wiring
# Uses the same source set as format_thread_linux but with a stub BadBlocks
# (in the test file itself) rather than the real badblocks.c.
CFLAGS_LINUX_test_badblocks_integration_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR) -I$(SRC_DIR)/ext2fs -I$(SRC_DIR)/ms-sys/inc -I$(SRC_DIR)/bled \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers
LDFLAGS_LINUX_test_badblocks_integration_linux := -lpthread -lblkid
EXTRA_SRC_LINUX_test_badblocks_integration_linux := \
	$(FORMAT_THREAD_LINUX_SRC) $(EXT2FS_LIB) $(BLED_LIB) \
	badblocks_integration_glue.c

# persistence_linux tests: casper/persistence partition support
# Uses the same source set as format_thread_linux.
CFLAGS_LINUX_test_persistence_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR) -I$(SRC_DIR)/ext2fs -I$(SRC_DIR)/ms-sys/inc -I$(SRC_DIR)/bled \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers
LDFLAGS_LINUX_test_persistence_linux := -lpthread -lblkid
EXTRA_SRC_LINUX_test_persistence_linux := \
	$(FORMAT_THREAD_LINUX_SRC) $(EXT2FS_LIB) $(BLED_LIB)

# process_linux tests: GetPPID, StartProcessSearch, SetProcessSearch,
#                      GetProcessSearch, SearchProcessAlt (Linux /proc-based)
CFLAGS_LINUX_test_process_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter
LDFLAGS_LINUX_test_process_linux :=
EXTRA_SRC_LINUX_test_process_linux := $(SRC_DIR)/linux/process.c

# mount_linux tests: AltMountVolume, AltUnmountVolume, MountVolume, RemountVolume
MOUNT_LINUX_SRC := $(SRC_DIR)/linux/drive.c \
                   $(SRC_DIR)/linux/stdfn.c \
                   $(SRC_DIR)/linux/stdio.c \
                   $(SRC_DIR)/linux/globals.c \
                   $(SRC_DIR)/linux/ui.c \
                   $(FORMAT_MS_SRC)
CFLAGS_LINUX_test_mount_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR)/ms-sys/inc -I$(SRC_DIR) -I$(SRC_DIR)/bled \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter
LDFLAGS_LINUX_test_mount_linux := -lblkid
EXTRA_SRC_LINUX_test_mount_linux := $(MOUNT_LINUX_SRC) $(BLED_LIB)

# localization_linux tests: apply_localization, reset_localization,
#                           dispatch_loc_cmd (GTK widget refs all NULL — no display needed)
LOC_LINUX_SRC := $(SRC_DIR)/linux/localization.c \
                 $(SRC_DIR)/linux/stdfn.c \
                 $(COMMON)/localization.c \
                 $(COMMON)/parser.c
LDFLAGS_LINUX_test_localization_linux := $(shell pkg-config --libs fontconfig 2>/dev/null)
CFLAGS_LINUX_test_localization_linux := \
	-DRUFUS_TEST \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(COMMON) -I$(SRC_DIR) \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers \
	$(shell pkg-config --cflags fontconfig 2>/dev/null)
EXTRA_SRC_LINUX_test_localization_linux := $(LOC_LINUX_SRC)

# smart_linux tests: SMART HDD/UFD detection via SG_IO
CFLAGS_LINUX_test_smart_linux := \
	-DRUFUS_TEST \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers
LDFLAGS_LINUX_test_smart_linux :=
EXTRA_SRC_LINUX_test_smart_linux := $(SRC_DIR)/linux/smart.c

# pki_linux tests: PKI/certificate functions via OpenSSL
CFLAGS_LINUX_test_pki_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers
LDFLAGS_LINUX_test_pki_linux := -lssl -lcrypto
EXTRA_SRC_LINUX_test_pki_linux := $(SRC_DIR)/linux/pki.c

# vhd_linux tests: IsBootableImage, GetWimVersion, VhdMountImageAndGetSize
# Links against vhd.c (Linux impl), libbled.a (compression), libwim.a (WIM)
WIM_LIB  := $(SRC_DIR)/wimlib/libwim.a
XML_SRC  := $(COMMON)/xml.c
CFLAGS_LINUX_test_vhd_linux := \
	-D_RUFUS \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR) -I$(SRC_DIR)/bled -I$(SRC_DIR)/wimlib -I$(COMMON) \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers \
	-Wno-strict-aliasing
LDFLAGS_LINUX_test_vhd_linux := -lz -lpthread -lxml2 -lm -lcdio -liso9660 -ludf
EXTRA_SRC_LINUX_test_vhd_linux := \
	$(SRC_DIR)/linux/vhd.c \
	$(BLED_LIB) \
	$(WIM_LIB) \
	$(XML_SRC)

# xml_linux tests: ezxml parse, navigate, build, round-trip
CFLAGS_LINUX_test_xml_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux -I$(COMMON) \
	-I$(SRC_DIR) \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers
LDFLAGS_LINUX_test_xml_linux :=
EXTRA_SRC_LINUX_test_xml_linux := $(XML_SRC)

# combo_linux tests: ComboBox message-dispatch bridge (no GTK required)
COMBO_LINUX_SRC := $(SRC_DIR)/linux/combo_bridge.c \
                   $(COMPAT)/msg_dispatch.c
CFLAGS_LINUX_test_combo_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter
LDFLAGS_LINUX_test_combo_linux := -lpthread
EXTRA_SRC_LINUX_test_combo_linux := $(COMBO_LINUX_SRC)

# window_text_linux tests: GetWindowTextA / SetWindowTextA bridge (no GTK required)
WINDOW_TEXT_SRC := $(SRC_DIR)/linux/window_text_bridge.c
CFLAGS_LINUX_test_window_text_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter
LDFLAGS_LINUX_test_window_text_linux := -lpthread
EXTRA_SRC_LINUX_test_window_text_linux := $(WINDOW_TEXT_SRC)

# status_history_linux tests: status label history ring buffer
STATUS_HISTORY_SRC := $(SRC_DIR)/linux/status_history.c
CFLAGS_LINUX_test_status_history_linux := \
	-I$(SRC_DIR)/linux \
	-Wno-unused-parameter
EXTRA_SRC_LINUX_test_status_history_linux := $(STATUS_HISTORY_SRC)

# wue_linux tests: CreateUnattendXml, PopulateWindowsVersion
# Links against wue.c (Linux impl), libwim.a (WIM), xml.c (ezxml)
CFLAGS_LINUX_test_wue_linux := \
	-D_RUFUS \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR) -I$(SRC_DIR)/wimlib -I$(COMMON) \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers \
	-Wno-strict-aliasing
LDFLAGS_LINUX_test_wue_linux := -lz -lpthread -lxml2 -lm -lcdio -liso9660 -ludf
EXTRA_SRC_LINUX_test_wue_linux := \
	$(SRC_DIR)/linux/wue.c \
	$(SRC_DIR)/linux/timezone.c \
	$(WIM_LIB) \
	$(XML_SRC)

# timezone_linux tests: IanaToWindowsTimezone, system TZ detection
CFLAGS_LINUX_test_timezone_linux := \
	-DRUFUS_TEST \
	-I$(SRC_DIR)/linux \
	-Wno-unused-function -Wno-unused-parameter
EXTRA_SRC_LINUX_test_timezone_linux := $(SRC_DIR)/linux/timezone.c

# xdg_dirs_linux tests: GetXdgUserDir — XDG user-dirs.dirs parsing
CFLAGS_LINUX_test_xdg_dirs_linux := \
	-DRUFUS_TEST \
	-I$(SRC_DIR)/linux \
	-Wno-unused-function -Wno-unused-parameter
EXTRA_SRC_LINUX_test_xdg_dirs_linux := $(SRC_DIR)/linux/xdg.c

# polkit_linux tests: privilege elevation helper
CFLAGS_LINUX_test_polkit_linux := \
	-I$(SRC_DIR)/linux \
	-Wno-unused-function -Wno-unused-parameter
EXTRA_SRC_LINUX_test_polkit_linux := $(SRC_DIR)/linux/polkit.c

# cli_linux tests: non-GTK CLI argument parser
CFLAGS_LINUX_test_cli_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter
EXTRA_SRC_LINUX_test_cli_linux := \
	$(SRC_DIR)/linux/cli.c \
	cli_linux_glue.c

# compat_layer_linux tests: ABI / type-size / macro-value checks for linux/compat/
# Pure header inclusion + value assertions — no extra .c sources needed.
CFLAGS_LINUX_test_compat_layer := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-Wno-unused-function -Wno-unused-parameter \
	-Wno-implicit-function-declaration

# loopback_linux tests: integration tests using real /dev/loop* block devices
# Requires root (tests skip gracefully when not root via SKIP_NOT_ROOT()).
# Uses the same source set as format_thread_linux.
CFLAGS_LINUX_test_loopback := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR) -I$(SRC_DIR)/ext2fs -I$(SRC_DIR)/ms-sys/inc -I$(SRC_DIR)/bled \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers
LDFLAGS_LINUX_test_loopback := -lpthread -lblkid
EXTRA_SRC_LINUX_test_loopback := \
	$(FORMAT_THREAD_LINUX_SRC) $(EXT2FS_LIB) $(BLED_LIB) loopback_linux_glue.c

# download_resume_linux tests: .partial file helpers for resumable downloads
CFLAGS_LINUX_test_download_resume_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter
EXTRA_SRC_LINUX_test_download_resume_linux := \
	$(SRC_DIR)/linux/download_resume.c \
	download_resume_linux_glue.c

# verify_linux tests: write-and-verify pass
CFLAGS_LINUX_test_verify_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter
EXTRA_SRC_LINUX_test_verify_linux := $(SRC_DIR)/linux/verify.c verify_linux_glue.c

# system_info_linux tests: GetTPMVersion, IsSecureBootEnabled, IsSetupModeEnabled
CFLAGS_LINUX_test_system_info_linux := \
	-DRUFUS_TEST \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter
EXTRA_SRC_LINUX_test_system_info_linux := $(SRC_DIR)/linux/system_info.c

# image_scan_linux tests: ImageScanThread — ISO scanning + img_report population
# Links iso.c (ExtractISO + img_report), vhd.c (IsBootableImage), image_scan.c (thread),
# plus stdfn.c, stdio.c, ui.c, localization chain, BLED (vhd decompression), WIM, XML.
# NOTE: WIM_LIB and XML_SRC must be defined before this block (above).
IMAGE_SCAN_LINUX_SRC := \
	$(SRC_DIR)/linux/image_scan.c \
	$(SRC_DIR)/linux/iso.c \
	$(SRC_DIR)/linux/vhd.c \
	$(SRC_DIR)/linux/stdfn.c \
	$(SRC_DIR)/linux/stdio.c \
	$(SRC_DIR)/linux/ui.c \
	$(SRC_DIR)/linux/localization.c \
	$(COMMON)/parser.c \
	$(COMMON)/localization.c \
	$(BLED_LIB) \
	$(WIM_LIB) \
	$(XML_SRC)
CFLAGS_LINUX_test_image_scan_linux := \
	-D_RUFUS -DRUFUS_TEST \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR) -I$(SRC_DIR)/syslinux -I$(SRC_DIR)/syslinux/libfat \
	-I$(SRC_DIR)/bled -I$(SRC_DIR)/wimlib -I$(COMMON) \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers \
	-Wno-strict-aliasing
LDFLAGS_LINUX_test_image_scan_linux := \
	-lpthread -lz -lxml2 -lm -lcdio -liso9660 -ludf \
	$(SRC_DIR)/syslinux/libfat/libfat.a
EXTRA_SRC_LINUX_test_image_scan_linux := $(IMAGE_SCAN_LINUX_SRC) iso_linux_glue.c

# bootloader_scan_linux tests: GetBootladerInfo() — EFI bootloader revocation check
# Uses image_scan.c (GetBootladerInfo), stubs for ReadISOFileToBuffer/IsSignedBy/IsRevoked.
CFLAGS_LINUX_test_bootloader_scan_linux := \
	-D_RUFUS -DRUFUS_TEST \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR) -I$(COMMON) \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers
LDFLAGS_LINUX_test_bootloader_scan_linux := -lpthread
EXTRA_SRC_LINUX_test_bootloader_scan_linux := \
	$(SRC_DIR)/linux/image_scan.c \
	$(SRC_DIR)/linux/stdfn.c \
	$(SRC_DIR)/linux/stdio.c \
	$(COMMON)/parser.c \
	$(COMMON)/localization.c \
	$(SRC_DIR)/linux/localization.c \
	bootloader_scan_linux_glue.c
DOS_LINUX_SRC := $(SRC_DIR)/linux/dos.c \
                 $(SRC_DIR)/linux/dos_locale.c \
                 $(SRC_DIR)/linux/stdio.c \
                 $(SRC_DIR)/linux/stdfn.c \
                 $(SRC_DIR)/linux/globals.c
CFLAGS_LINUX_test_dos_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR) -I$(COMMON) \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers
LDFLAGS_LINUX_test_dos_linux := $(shell pkg-config --libs fontconfig 2>/dev/null)
EXTRA_SRC_LINUX_test_dos_linux := $(DOS_LINUX_SRC) $(SRC_DIR)/linux/freedos_data.c dos_linux_glue.c

# syslinux_linux tests: GetSyslinuxVersion, libfat_readfile, InstallSyslinux
LIBFAT_LIB       := $(SRC_DIR)/syslinux/libfat/libfat.a
LIBINSTALLER_LIB := $(SRC_DIR)/syslinux/libinstaller/libinstaller.a
SYSLINUX_LINUX_SRC := \
	$(SRC_DIR)/linux/syslinux.c \
	$(SRC_DIR)/linux/stdfn.c \
	$(SRC_DIR)/linux/drive.c \
	$(FORMAT_MS_SRC)
CFLAGS_LINUX_test_syslinux_linux := \
	-I$(COMPAT) -I$(SRC_DIR)/windows -I$(SRC_DIR)/linux \
	-I$(SRC_DIR) -I$(SRC_DIR)/syslinux -I$(SRC_DIR)/syslinux/libfat \
	-I$(SRC_DIR)/syslinux/libinstaller -I$(SRC_DIR)/ms-sys/inc \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers
LDFLAGS_LINUX_test_syslinux_linux := -lblkid
EXTRA_SRC_LINUX_test_syslinux_linux := \
	$(SYSLINUX_LINUX_SRC) $(LIBFAT_LIB) $(LIBINSTALLER_LIB) $(BLED_LIB) syslinux_linux_glue.c

# Tests that require root / a privileged container (e.g. /dev/loop* access).
# Run via:  make run-root          (must already be root)
#           ./run_tests.sh --root-only   (same)
#           ./run_tests.sh --container   (auto-launches privileged Docker/Podman)
ROOT_BINS := test_loopback_linux

.PHONY: all linux windows run-linux run-wine run-root clean

all: linux windows

linux: $(LINUX_BINS)

windows: $(WIN_BINS)

# Pattern rules for Linux binaries
# We look up per-test extra flags by deriving the test name from the target.
_test_name = $(patsubst %_linux,%,$(notdir $@))

%_linux: %.c $(CREGEX_SRC)
	$(CC) $(CFLAGS_LINUX) $(CFLAGS_LINUX_$(_test_name)) -o $@ $< $(CREGEX_SRC) \
	    $(EXTRA_SRC_LINUX_$(_test_name)) $(LDFLAGS_LINUX_$(_test_name)) $(FONTCONFIG_LIBS)

# Pattern rules for Windows binaries
_win_test_name = $(patsubst %.exe,%,$(notdir $@))

%.exe: %.c $(CREGEX_SRC)
	$(CC_WIN) $(CFLAGS_WIN) $(CFLAGS_WIN_$(_win_test_name)) -o $@ $< $(CREGEX_SRC) \
	    $(EXTRA_SRC_WIN_$(_win_test_name))

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

# Root-requiring tests (loopback device access, etc.)
# Must run as root or inside a privileged container.
# See: ./run_tests.sh --container
run-root: $(ROOT_BINS)
	@failed=0; \
	for bin in $(ROOT_BINS); do \
	  printf '\n=== %s (root) ===\n' "$$bin"; \
	  ./$$bin || failed=$$((failed + 1)); \
	done; \
	[ $$failed -eq 0 ] || { echo "$$failed root test binary/binaries FAILED"; exit 1; }

# ---- AddressSanitizer + UBSan target (item 91) ----
# Rebuilds all Linux test binaries with -fsanitize=address,undefined,leak
# and runs the full Linux test suite under ASAN.  Requires GCC ≥ 4.8 / Clang ≥ 3.1
# with libasan + libubsan installed.  On Debian/Ubuntu: apt install gcc libasan6.
#
#   make check-asan
#
ASAN_FLAGS   := -fsanitize=address,undefined,leak -fno-omit-frame-pointer
ASAN_BINS    := $(LINUX_BINS:%=%_asan)

# _asan_test_name strips the _linux_asan suffix to look up per-test CFLAGS/LDFLAGS.
_asan_test_name = $(patsubst %_linux_asan,%,$(notdir $@))

%_linux_asan: %.c $(CREGEX_SRC)
	$(CC) $(CFLAGS_LINUX) $(CFLAGS_LINUX_$(_asan_test_name)) $(ASAN_FLAGS) \
	    -o $@ $< $(CREGEX_SRC) \
	    $(EXTRA_SRC_LINUX_$(_asan_test_name)) $(LDFLAGS_LINUX_$(_asan_test_name)) \
	    $(FONTCONFIG_LIBS)

check-asan: $(ASAN_BINS)
	@echo "=== Running tests under AddressSanitizer + UBSan ==="
	@failed=0; \
	for bin in $(ASAN_BINS); do \
	  printf '\n=== %s (ASAN) ===\n' "$$bin"; \
	  ASAN_OPTIONS=halt_on_error=1:detect_leaks=1 \
	  UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
	    ./$$bin || failed=$$((failed + 1)); \
	done; \
	[ $$failed -eq 0 ] && echo "All ASAN tests passed." \
	  || { echo "$$failed ASAN test binary/binaries FAILED"; exit 1; }

# ---- cppcheck static analysis target (item 95) ----
# Requires:  sudo apt install cppcheck
# Runs cppcheck over the Linux-specific sources with all checks enabled.
# Suppressions kept minimal — add entries when cppcheck reports false positives.
#
#   make check-cppcheck
#
CPPCHECK_SRCS := \
	$(SRC_DIR)/linux \
	$(SRC_DIR)/common

CPPCHECK_FLAGS := \
	--enable=all \
	--error-exitcode=1 \
	--suppress=missingIncludeSystem \
	--suppress=unmatchedSuppression \
	--inline-suppr \
	-I$(SRC_DIR)/linux \
	-I$(SRC_DIR)/linux/compat \
	-I$(SRC_DIR)/windows \
	-I$(SRC_DIR)/common \
	-I$(SRC_DIR) \
	-D__linux__ \
	-DRUFUS_TEST

check-cppcheck:
	@command -v cppcheck >/dev/null 2>&1 || { echo "cppcheck not found; install with: sudo apt install cppcheck"; exit 1; }
	cppcheck $(CPPCHECK_FLAGS) $(CPPCHECK_SRCS)
	@echo "cppcheck: no issues found."

clean:
	rm -f $(LINUX_BINS) $(WIN_BINS) $(ASAN_BINS)

