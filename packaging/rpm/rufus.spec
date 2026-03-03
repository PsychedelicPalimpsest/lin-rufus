Name:           rufus
Version:        4.13.0
Release:        1%{?dist}
Summary:        The Reliable USB Formatting Utility

License:        GPL-3.0-or-later
URL:            https://github.com/pbatard/rufus
Source0:        https://github.com/pbatard/rufus/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  libtool
BuildRequires:  make
BuildRequires:  gcc
BuildRequires:  pkg-config
BuildRequires:  nasm
BuildRequires:  gtk3-devel
BuildRequires:  libcurl-devel
BuildRequires:  systemd-devel
BuildRequires:  libblkid-devel
BuildRequires:  util-linux-devel
BuildRequires:  openssl-devel
BuildRequires:  fontconfig-devel
BuildRequires:  libnotify-devel

Requires:       polkit
Requires:       ntfs-3g
Requires:       mtools
Requires:       dosfstools
Requires:       e2fsprogs
Recommends:     exfatprogs
Recommends:     udftools
Recommends:     grub2-tools
Recommends:     qemu-img

%description
Rufus is a utility that helps format and create bootable USB flash drives.

It is useful for cases where you need to create USB installation media from
bootable ISOs (Windows, Linux, UEFI, etc.), or where you need to work with
a device that has no OS installed, or where you need to flash a BIOS or
other firmware from DOS.

Rufus is fast: it is roughly twice as fast as UNetbootin, Universal USB
Installer or Windows 7 USB download tool, on the creation of a Windows 7
USB installation drive from an ISO. It is also marginally faster on the
creation of Linux bootable USB from ISOs. 

On Linux, Rufus uses GTK3 for its graphical interface and supports a
headless CLI mode for scripting and automation.

%prep
%autosetup -n %{name}
autoreconf -fi

%build
%configure \
    --with-os=linux \
    --disable-silent-rules
%make_build

%check
./run_tests.sh --linux-only

%install
%make_install

# Install man page
install -Dm644 doc/rufus.1 %{buildroot}%{_mandir}/man1/rufus.1

# Install polkit policy
install -Dm644 res/ie.akeo.rufus.policy \
    %{buildroot}%{_datadir}/polkit-1/actions/ie.akeo.rufus.policy

# Install resource data
install -d %{buildroot}%{_datadir}/rufus
cp -r res/* %{buildroot}%{_datadir}/rufus/

%files
%license LICENSE.txt
%doc README.md CONTRIBUTING.md doc/linux-architecture.md
%{_bindir}/rufus
%{_mandir}/man1/rufus.1*
%{_datadir}/applications/ie.akeo.rufus.desktop
%{_datadir}/metainfo/ie.akeo.rufus.appdata.xml
%{_datadir}/polkit-1/actions/ie.akeo.rufus.policy
%{_datadir}/icons/hicolor/32x32/apps/ie.akeo.rufus.png
%{_datadir}/icons/hicolor/48x48/apps/ie.akeo.rufus.png
%{_datadir}/icons/hicolor/256x256/apps/ie.akeo.rufus.png
%{_datadir}/rufus/

%changelog
* Wed Jan 01 2025 PsychedelicPalimpsest - 4.13.0-1
- Initial RPM packaging for the Linux port
- GTK3 graphical interface with polkit privilege escalation
- CLI mode for headless/scripting use
- Supports FAT16/FAT32/NTFS/exFAT/ext2/ext3/ext4/UDF filesystems
- Supports MBR/GPT partition schemes for BIOS and UEFI targets
- Full bootable ISO extraction (ISO9660/UDF via libcdio)
- SHA256/SHA512/MD5 hashing with Secure Boot validation
- WIM image support via bundled wimlib
- Resumable downloads via libcurl
- Desktop notifications via libnotify
