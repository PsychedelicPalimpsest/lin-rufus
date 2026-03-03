SUBDIRS = src
TARGET  = rufus
TAGVER  = $(shell git log --oneline | wc -l)
SEDCMD  = s/^\([ \t]*\)Version="\([0-9]*\)\.\([0-9]*\)\.[0-9]*\.\([0-9]*\)"\(.*\)/\1Version="\2.\3.@@TAGVER@@.\4"\5/

# --------------------------------------------------------------------------
# Linux desktop integration (install targets)
# --------------------------------------------------------------------------
if TARGET_LINUX

desktopdir      = $(datadir)/applications
dist_desktop_DATA = res/ie.akeo.rufus.desktop

man_MANS = doc/rufus.1


metainfodir     = $(datadir)/metainfo
dist_metainfo_DATA = res/ie.akeo.rufus.appdata.xml

# Install application icons into the hicolor icon theme tree
install-data-hook:
	$(MKDIR_P) "$(DESTDIR)$(datadir)/icons/hicolor/32x32/apps"
	$(INSTALL_DATA) "$(srcdir)/res/icons/rufus-32.png" \
		"$(DESTDIR)$(datadir)/icons/hicolor/32x32/apps/ie.akeo.rufus.png"
	$(MKDIR_P) "$(DESTDIR)$(datadir)/icons/hicolor/48x48/apps"
	$(INSTALL_DATA) "$(srcdir)/res/icons/rufus-48.png" \
		"$(DESTDIR)$(datadir)/icons/hicolor/48x48/apps/ie.akeo.rufus.png"
	$(MKDIR_P) "$(DESTDIR)$(datadir)/icons/hicolor/256x256/apps"
	$(INSTALL_DATA) "$(srcdir)/res/icons/rufus-256.png" \
		"$(DESTDIR)$(datadir)/icons/hicolor/256x256/apps/ie.akeo.rufus.png"
	@gtk-update-icon-cache -f -t "$(DESTDIR)$(datadir)/icons/hicolor" 2>/dev/null ||:
	@update-desktop-database "$(DESTDIR)$(datadir)/applications" 2>/dev/null ||:

endif # TARGET_LINUX

# Static analysis target — runs cppcheck over Linux and common source
check-cppcheck:
	@command -v cppcheck >/dev/null 2>&1 || { echo "cppcheck not found; skipping"; exit 0; }
	cppcheck --enable=warning,performance \
	         --suppress=missingIncludeSystem \
	         --suppress=normalCheckLevelMaxBranches \
	         --suppressions-list=$(srcdir)/cppcheck.suppress \
	         --error-exitcode=1 \
	         -I $(srcdir)/src/linux \
	         -I $(srcdir)/src/linux/compat \
	         -I $(srcdir)/src/windows \
	         -I $(srcdir)/src/common \
	         -D__linux__ \
	         $(srcdir)/src/linux/*.c \
	         $(srcdir)/src/common/*.c

.PHONY: check-cppcheck

upx: all
	@upx --lzma --best src/$(TARGET)$(EXEEXT)

# This step produces the UPX compressed and signed releases that are made available for public download
# NB: UPX v3.09 or later is needed for LZMA compression (http://upx.sourceforge.net/)
release: all
	@mv src/$(TARGET)$(EXEEXT) .
	@sleep 1
	@$(STRIP) $(TARGET)$(EXEEXT)
	@upx --lzma --best $(TARGET)$(EXEEXT)
	@mv $(TARGET)$(EXEEXT) $(TARGET)-$(VERSION)$(SUFFIX)$(EXEEXT)
	@cmd.exe //c _sign.cmd $(TARGET)-$(VERSION)$(SUFFIX)$(EXEEXT)

# AppImage packaging — requires a built Rufus binary.
# Downloads linuxdeploy + linuxdeploy-plugin-gtk on first run (cached in
# packaging/appimage/.tools/).  Output: Rufus-<VERSION>-x86_64.AppImage
appimage: all
	@bash $(srcdir)/packaging/appimage/build-appimage.sh

.PHONY: appimage

# Snap packaging — requires snapcraft.
# Output: rufus_<VERSION>_amd64.snap
snap:
	@command -v snapcraft >/dev/null 2>&1 || { \
	    echo "snapcraft not found; install with: sudo snap install snapcraft --classic"; \
	    exit 1; }
	cd $(srcdir)/packaging/snap && snapcraft --destructive-mode

.PHONY: snap
