if TARGET_WINDOWS
SUBDIRS = ../.mingw bled ext2fs ms-sys syslinux/libfat syslinux/libinstaller syslinux/win libcdio/iso9660 libcdio/udf libcdio/driver wimlib ../res/loc
else
SUBDIRS = bled ext2fs ms-sys syslinux/libfat syslinux/libinstaller syslinux/win libcdio/iso9660 libcdio/udf libcdio/driver wimlib ../res/loc
endif

# As far as I can tell, the following libraries are *not* vulnerable to side-loading, so we link using their regular version:
if TARGET_WINDOWS
NONVULNERABLE_LIBS = -lole32 -lgdi32 -lshlwapi -lcomctl32 -luuid -lntdll
# The following libraries are vulnerable (or have an unknown vulnerability status), so we link using our delay-loaded replacement:
# See https://github.com/pbatard/rufus/issues/2272
VULNERABLE_LIBS = -lcrypt32-delaylib -ldwmapi-delaylib -lsetupapi-delaylib -luxtheme-delaylib -lversion-delaylib -lvirtdisk-delaylib -lwininet-delaylib -lwintrust-delaylib
else
NONVULNERABLE_LIBS =
VULNERABLE_LIBS =
endif

noinst_PROGRAMS = rufus

if TARGET_WINDOWS
AM_V_WINDRES_0 = @echo "  RC     $@";$(WINDRES)
AM_V_WINDRES_1 = $(WINDRES)
AM_V_WINDRES_  = $(AM_V_WINDRES_$(AM_DEFAULT_VERBOSITY))
AM_V_WINDRES   = $(AM_V_WINDRES_$(V))

windows/%_rc.o: windows/%.rc ../res/loc/embedded.loc
	$(AM_V_WINDRES) $(AM_RCFLAGS) -i $< -o $@
endif

COMMON_SOURCES = common/cregex_compile.c common/cregex_parse.c common/cregex_vm.c common/xml.c \
	common/localization.c common/parser.c

if TARGET_WINDOWS
OS_SOURCES = windows/badblocks.c windows/darkmode.c windows/dev.c windows/dos.c windows/dos_locale.c \
	windows/drive.c windows/format.c windows/format_ext.c windows/format_fat32.c windows/hash.c \
	windows/icon.c windows/iso.c windows/localization.c windows/net.c windows/parser.c \
	windows/pki.c windows/process.c windows/rufus.c windows/smart.c windows/stdfn.c \
	windows/stdio.c windows/stdlg.c windows/syslinux.c windows/ui.c windows/vhd.c windows/wue.c
else
# Select the UI backend source for Linux builds
if USE_GTK
LINUX_UI_SRC = linux/ui_gtk.c
else
LINUX_UI_SRC = linux/ui.c
endif
OS_SOURCES = linux/compat/msg_dispatch.c \
	linux/badblocks.c linux/combo_bridge.c linux/darkmode.c linux/dev.c linux/device_monitor.c \
	linux/dos.c linux/dos_locale.c linux/freedos_data.c \
	linux/drive.c linux/format.c linux/format_ext.c linux/format_ext_tools.c linux/format_fat32.c linux/globals.c \
	linux/hash.c linux/icon.c linux/image_scan.c linux/iso.c linux/localization.c linux/net.c linux/parser.c \
	linux/pki.c linux/process.c linux/rufus.c linux/smart.c linux/stdfn.c \
	linux/stdio.c linux/stdlg.c linux/syslinux.c $(LINUX_UI_SRC) linux/vhd.c linux/window_text_bridge.c linux/status_history.c linux/device_combo.c linux/wue.c linux/notify.c linux/system_info.c linux/timezone.c linux/xdg.c linux/polkit.c
endif

rufus_SOURCES = $(COMMON_SOURCES) $(OS_SOURCES)

if !TARGET_WINDOWS
polkitactionsdir = $(datadir)/polkit-1/actions
dist_polkitactions_DATA = $(top_srcdir)/res/ie.akeo.rufus.policy
endif

if TARGET_WINDOWS
rufus_CFLAGS = -I$(srcdir)/windows -I$(srcdir)/common \
	-I$(srcdir)/ms-sys/inc -I$(srcdir)/syslinux/libfat -I$(srcdir)/syslinux/libinstaller \
	-I$(srcdir)/syslinux/win -I$(srcdir)/libcdio -I$(srcdir)/wimlib -I$(srcdir)/../res \
	$(AM_CFLAGS) -DEXT2_FLAT_INCLUDES=0 -D_RUFUS -DSOLUTION=rufus -DCOMMON_PARSER_PE_FUNCTIONS
else
rufus_CFLAGS = -I$(srcdir)/linux/compat -I$(srcdir)/linux -I$(srcdir)/windows -I$(srcdir)/common \
	-I$(srcdir)/ms-sys/inc -I$(srcdir)/syslinux/libfat -I$(srcdir)/syslinux/libinstaller \
	-I$(srcdir)/syslinux/win -I$(srcdir)/libcdio -I$(srcdir)/wimlib -I$(srcdir)/../res \
	$(AM_CFLAGS) -DEXT2_FLAT_INCLUDES=0 -D_RUFUS -DSOLUTION=rufus $(FONTCONFIG_CFLAGS)
endif

if TARGET_WINDOWS
rufus_LDFLAGS = $(AM_LDFLAGS) -mwindows -L../.mingw
rufus_LDADD = windows/rufus_rc.o bled/libbled.a ext2fs/libext2fs.a ms-sys/libmssys.a syslinux/libfat/libfat.a syslinux/libinstaller/libinstaller.a syslinux/win/libwin.a \
	libcdio/iso9660/libiso9660.a libcdio/udf/libudf.a libcdio/driver/libdriver.a wimlib/libwim.a $(NONVULNERABLE_LIBS) $(VULNERABLE_LIBS)
else
rufus_LDFLAGS = $(AM_LDFLAGS)
if USE_GTK
rufus_LDADD = bled/libbled.a ext2fs/libext2fs.a ms-sys/libmssys.a syslinux/libfat/libfat.a syslinux/libinstaller/libinstaller.a syslinux/win/libwin.a \
	libcdio/iso9660/libiso9660.a libcdio/udf/libudf.a libcdio/driver/libdriver.a wimlib/libwim.a $(GTK_LIBS) -ludev -lssl -lcrypto $(FONTCONFIG_LIBS)
else
rufus_LDADD = bled/libbled.a ext2fs/libext2fs.a ms-sys/libmssys.a syslinux/libfat/libfat.a syslinux/libinstaller/libinstaller.a syslinux/win/libwin.a \
	libcdio/iso9660/libiso9660.a libcdio/udf/libudf.a libcdio/driver/libdriver.a wimlib/libwim.a -ludev -lssl -lcrypto $(FONTCONFIG_LIBS)
endif
endif
