AC_INIT([rufus], [4.13], [https://github.com/pbatard/rufus/issues], [rufus], [https://rufus.ie])
AM_INIT_AUTOMAKE([-Wno-portability foreign no-dist no-dependencies subdir-objects])
AC_CONFIG_SRCDIR([src/windows/rufus.c])
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])

AC_PREREQ([2.50])

# OS target selection -- must be processed before AC_PROG_CC so we can set CC
AC_ARG_WITH([os],
	[AS_HELP_STRING([--with-os=OS],
		[target OS: linux or windows (default=windows)])],
	[target_os=$withval],
	[target_os='windows'])

if test "x$target_os" = "xwindows"; then
  # Default to MinGW cross-compiler when targeting Windows and CC is not set
  if test "x${CC+set}" != "xset"; then
    CC="x86_64-w64-mingw32-gcc"
  fi
  # Derive the MinGW tool prefix from CC and pre-set WINDRES so AC_CHECK_TOOL picks it up
  if test "x${WINDRES+set}" != "xset"; then
    _mingw_prefix=$(echo "$CC" | sed 's/-gcc$//')
    if test "x$_mingw_prefix" != "x$CC"; then
      WINDRES="${_mingw_prefix}-windres"
    fi
  fi
  AC_MSG_NOTICE([Targeting Windows; CC=${CC}])
else
  AC_MSG_NOTICE([Targeting Linux])
fi

AC_PROG_CC
# autoconf 2.61 doesn't have AC_PROG_AR, but 2.63 has it
AC_DEFUN([AC_PROG_AR], [AC_CHECK_TOOL(AR, ar, :)])
AC_PROG_AR
AC_PROG_RANLIB
AC_PROG_SED
AC_PATH_PROG(RM, rm, rm)
AC_CHECK_TOOL(DLLTOOL, dlltool, :)
AC_CHECK_TOOL(STRIP, strip, :)
AC_CHECK_TOOL(WINDRES, windres, :)
AC_C_INLINE
AC_DEFINE([_GNU_SOURCE], [], [Use GNU extensions])
PKG_PROG_PKG_CONFIG

if test "x$target_os" = "xwindows"; then
  AM_CFLAGS="${AM_CFLAGS} -DWINVER=0x0A00 -D_WIN32_WINNT=0x0A00 -D_WIN32_IE=0x0A00"
  # "-Wl,--nxcompat" to enable DEP (Data Execution Prevention)
  # "-Wl,--dynamicbase" to enable ASLR (Address Space Layout Randomization)
  AM_LDFLAGS="${AM_LDFLAGS} -Wl,-no-undefined -Wl,--nxcompat -Wl,--no-insert-timestamp -Wl,--dynamicbase"
fi

# Debug symbols
AC_ARG_ENABLE([debug],
	[AS_HELP_STRING([--enable-debug],
		[keep debug symbols for gdb (default=yes)])],
	[debug_enabled=$enableval],
	[debug_enabled='yes'])
if test "x$debug_enabled" != "xno" ; then
  CFLAGS="-g -O0"
else
  CFLAGS="-Os"
  LDFLAGS="-s"
fi

# Alpha/Beta/Test
AC_ARG_ENABLE([alpha],[AS_HELP_STRING([--enable-alpha], [build an ALPHA release (default=no)])], [alpha_enabled=$enableval], [alpha_enabled='no'])
if test "x$alpha_enabled" != "xno" ; then
  CFLAGS+=" -DALPHA"
  SUFFIX=_ALPHA
fi
AC_ARG_ENABLE([beta],[AS_HELP_STRING([--enable-beta], [build a BETA release (default=no)])], [beta_enabled=$enableval], [beta_enabled='no'])
if test "x$beta_enabled" != "xno" ; then
  CFLAGS+=" -DBETA"
  SUFFIX=_BETA
fi
AC_ARG_ENABLE([test],[AS_HELP_STRING([--enable-test=#], [build a TEST release (default=no)])], [test_enabled=$enableval], [test_enabled='no'])
if test "x$test_enabled" != "xno" ; then
  if test "x$test_enabled" == "xyes" ; then $enableval="" ; fi
  CFLAGS+=" -DTEST=$enableval"
  SUFFIX=_TEST$enableval
fi

AC_MSG_RESULT([enabling Large File Support (ISO support)])
AM_CFLAGS="$AM_CFLAGS -D_FILE_OFFSET_BITS=64 -D_OFF_T_ -D_off_t=off64_t -Doff_t=off64_t -Doff32_t=long"

# Check for -Wno-pointer-sign compiler support (GCC >= 4)
saved_CFLAGS="${CFLAGS}"
CFLAGS="$CFLAGS -Wno-pointer-sign"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
	[nopointersign_cflags="-Wno-pointer-sign"], [nopointersign_cflags=""])
CFLAGS="${saved_CFLAGS}"

# NB: The DECLSPEC_IMPORT redefinition below is a temporary(?) workaround for MinGW32 delay-loading
# See https://github.com/pbatard/rufus/pull/2513 as well as https://sourceware.org/bugzilla/show_bug.cgi?id=14339
if test "x$target_os" = "xwindows"; then
  AM_CFLAGS="$AM_CFLAGS -DUNICODE -D_UNICODE -UNDEBUG -DCOBJMACROS -D__USE_MINGW_ANSI_STDIO=0 -UDECLSPEC_IMPORT -DDECLSPEC_IMPORT=__attribute__\(\(visibility\(\\\"hidden\\\"\)\)\) -std=gnu11 -Wshadow -Wall -Wformat-security -Wundef -Wunused -Wstrict-prototypes -Wno-restrict -Wno-array-bounds -Werror-implicit-function-declaration -Wbidi-chars=none $nopointersign_cflags"
else
  AM_CFLAGS="$AM_CFLAGS -I\$(top_srcdir)/src/linux/compat -I\$(top_srcdir)/src/windows -UNDEBUG -std=gnu11 -Wshadow -Wall -Wformat-security -Wundef -Wunused -Wstrict-prototypes -Wno-restrict -Wno-array-bounds -Werror-implicit-function-declaration -Wbidi-chars=none $nopointersign_cflags"
fi

AM_CONDITIONAL([TARGET_WINDOWS], [test "x$target_os" = "xwindows"])
AM_CONDITIONAL([TARGET_LINUX],   [test "x$target_os" = "xlinux"])

# UI backend selection
# --with-ui=gtk  : use GTK3 UI (default on Linux; optional on Windows)
# --with-ui=win  : use native Windows UI (default on Windows; N/A on Linux)
AC_ARG_WITH([ui],
	[AS_HELP_STRING([--with-ui=BACKEND],
		[UI backend: gtk or win (default: gtk on Linux, win on Windows)])],
	[ui_backend=$withval],
	[if test "x$target_os" = "xwindows"; then ui_backend='win'; else ui_backend='gtk'; fi])

if test "x$ui_backend" = "xgtk"; then
  if test "x$target_os" = "xwindows"; then
    # For MinGW cross-compilation, override pkg-config to only search MinGW paths.
    # Derive the sysroot prefix from CC (e.g. x86_64-w64-mingw32-gcc -> x86_64-w64-mingw32).
    _cc_base=$(basename "${CC:-gcc}")
    _host_prefix=$(echo "$_cc_base" | sed 's/-gcc$//')
    if test "x$_host_prefix" != "x$_cc_base"; then
      _mingw_sysroot="/usr/${_host_prefix}"
    else
      _mingw_sysroot="/usr/x86_64-w64-mingw32"
    fi
    _mingw_pkgconfig="${_mingw_sysroot}/lib/pkgconfig"
    AC_MSG_CHECKING([for MinGW pkg-config path])
    if test -d "$_mingw_pkgconfig"; then
      AC_MSG_RESULT([$_mingw_pkgconfig])
      PKG_CONFIG_LIBDIR="$_mingw_pkgconfig"
      PKG_CONFIG_PATH=""
      export PKG_CONFIG_LIBDIR PKG_CONFIG_PATH
    else
      AC_MSG_RESULT([not found])
      # Point to a non-existent path so Linux GTK is NOT accidentally found
      PKG_CONFIG_LIBDIR="${_mingw_pkgconfig}"
      PKG_CONFIG_PATH=""
      export PKG_CONFIG_LIBDIR PKG_CONFIG_PATH
    fi
    PKG_CHECK_MODULES([GTK], [gtk+-3.0 >= 3.18],
      [AC_MSG_NOTICE([MinGW GTK3 found: building GTK UI for Windows])],
      [AC_MSG_ERROR([MinGW-targeted GTK3 >= 3.18 not found.
  Install mingw-w64-gtk3 (AUR) or set PKG_CONFIG_LIBDIR to a MinGW GTK pkg-config directory.
  On Arch Linux: yay -S mingw-w64-gtk3
  On MSYS2/mingw64: pacman -S mingw-w64-x86_64-gtk3])])
  else
    PKG_CHECK_MODULES([GTK], [gtk+-3.0 >= 3.18],
      [AC_MSG_NOTICE([GTK3 found: building GTK UI])],
      [AC_MSG_ERROR([GTK3 >= 3.18 required for --with-ui=gtk])])
  fi
  AM_CFLAGS="$AM_CFLAGS $GTK_CFLAGS -DUSE_GTK"
  AM_LDFLAGS="$AM_LDFLAGS $GTK_LIBS"
fi

AM_CONDITIONAL([USE_GTK], [test "x$ui_backend" = "xgtk"])

# libcurl — required for Linux networking (net.c)
if test "x$target_os" = "xlinux"; then
  PKG_CHECK_MODULES([CURL], [libcurl >= 7.50],
    [AC_MSG_NOTICE([libcurl found])],
    [AC_MSG_ERROR([libcurl >= 7.50 required for Linux build.
Install it with: apt install libcurl4-openssl-dev  OR  dnf install libcurl-devel])])
  AM_CFLAGS="$AM_CFLAGS $CURL_CFLAGS"
  AM_LDFLAGS="$AM_LDFLAGS $CURL_LIBS"
fi

# libblkid — required for Linux drive label detection (drive.c)
if test "x$target_os" = "xlinux"; then
  PKG_CHECK_MODULES([BLKID], [blkid],
    [AC_MSG_NOTICE([libblkid found])],
    [AC_MSG_ERROR([libblkid required for Linux build.
Install it with: apt install libblkid-dev  OR  dnf install util-linux-devel])])
  AM_CFLAGS="$AM_CFLAGS $BLKID_CFLAGS"
  AM_LDFLAGS="$AM_LDFLAGS $BLKID_LIBS"
fi

# fontconfig — required for IsFontAvailable() on Linux
if test "x$target_os" = "xlinux"; then
  PKG_CHECK_MODULES([FONTCONFIG], [fontconfig],
    [AC_MSG_NOTICE([fontconfig found])],
    [AC_MSG_ERROR([fontconfig required for Linux build.
Install it with: apt install libfontconfig1-dev  OR  dnf install fontconfig-devel])])
fi

AC_SUBST([VISIBILITY_CFLAGS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_LDFLAGS])
AC_SUBST([SUFFIX])

AC_CONFIG_FILES([Makefile])
if test "x$target_os" = "xwindows"; then
  AC_CONFIG_FILES([.mingw/Makefile])
fi
AC_CONFIG_FILES([src/Makefile])
AC_CONFIG_FILES([src/bled/Makefile])
AC_CONFIG_FILES([src/ext2fs/Makefile])
AC_CONFIG_FILES([src/libcdio/iso9660/Makefile])
AC_CONFIG_FILES([src/libcdio/udf/Makefile])
AC_CONFIG_FILES([src/libcdio/driver/Makefile])
AC_CONFIG_FILES([res/loc/Makefile])
AC_CONFIG_FILES([src/ms-sys/Makefile])
AC_CONFIG_FILES([src/syslinux/libfat/Makefile])
AC_CONFIG_FILES([src/syslinux/libinstaller/Makefile])
AC_CONFIG_FILES([src/syslinux/win/Makefile])
AC_CONFIG_FILES([src/wimlib/Makefile])
AC_OUTPUT
