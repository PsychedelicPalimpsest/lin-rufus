/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: img_info.c — image report formatting
 * Copyright © 2025 Rufus contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include "rufus.h"
#include "../bled/bled.h"

static const char *img_arch_name(unsigned int arch_bit)
{
	switch (arch_bit) {
	case ARCH_X86_32:       return "x86 (32-bit)";
	case ARCH_X86_64:       return "x86-64";
	case ARCH_ARM_32:       return "ARM (32-bit)";
	case ARCH_ARM_64:       return "ARM64";
	case ARCH_IA_64:        return "IA-64";
	case ARCH_RISCV_64:     return "RISC-V 64";
	case ARCH_LOONGARCH_64: return "LoongArch 64";
	default:                return "Unknown";
	}
}

static const char *img_compression_name(uint8_t c)
{
	switch (c) {
	case BLED_COMPRESSION_NONE:  return NULL;   /* do not display "none" */
	case BLED_COMPRESSION_ZIP:   return "ZIP";
	case BLED_COMPRESSION_LZW:   return "LZW (.Z)";
	case BLED_COMPRESSION_GZIP:  return "gzip";
	case BLED_COMPRESSION_LZMA:  return "LZMA";
	case BLED_COMPRESSION_BZIP2: return "bzip2";
	case BLED_COMPRESSION_XZ:    return "XZ";
	case BLED_COMPRESSION_7ZIP:  return "7-Zip";
	case BLED_COMPRESSION_ZSTD:  return "Zstandard";
	default:                     return "Compressed";
	}
}

/**
 * format_img_info - build a human-readable summary from an img_report.
 *
 * Writes a short multi-line description of the scanned image into buf.
 * This function is pure C (no GTK), and is fully unit-tested.
 *
 * Returns the number of bytes written (excluding the NUL terminator),
 * or 0 on error.
 */
size_t format_img_info(const RUFUS_IMG_REPORT *r, char *buf, size_t sz)
{
	if (!r || !buf || sz == 0)
		return 0;

	/* Work with a local value so the HAS_* / IS_* macros (which use dot
	 * notation) receive a struct, not a pointer. */
	const RUFUS_IMG_REPORT img = *r;

	size_t n = 0;
#define APPEND(...) do { \
	int _rc = snprintf(buf + n, sz - n, __VA_ARGS__); \
	if (_rc > 0) n += (size_t)_rc; \
	if (n >= sz) { buf[sz-1] = '\0'; return n; } \
} while (0)

	/* ---- Image type ---- */
	if (img.is_vhd)
		APPEND("Type: VHD/VHDX");
	else if (img.is_iso)
		APPEND("Type: ISO 9660");
	else if (img.is_bootable_img)
		APPEND("Type: Bootable image");
	else
		APPEND("Type: Raw image");

	/* ---- Label ---- */
	if (img.label[0])
		APPEND("\nLabel: %s", img.label);

	/* ---- Size ---- */
	if (img.image_size > 0) {
		if (img.image_size >= (uint64_t)1 << 30)
			APPEND("\nSize: %.1f GiB", (double)img.image_size / (1 << 30));
		else if (img.image_size >= (uint64_t)1 << 20)
			APPEND("\nSize: %.1f MiB", (double)img.image_size / (1 << 20));
		else
			APPEND("\nSize: %" PRIu64 " KiB", img.image_size >> 10);
	}

	/* ---- Windows version ---- */
	if (img.is_windows_img && img.win_version.major) {
		APPEND("\nWindows: %u.%u (build %u)",
		       img.win_version.major, img.win_version.minor, img.win_version.build);
	}

	/* ---- WinPE ---- */
	if (HAS_WINPE(img))
		APPEND("\nWinPE: yes");

	/* ---- EFI / architecture ---- */
	if (IS_EFI_BOOTABLE(img)) {
		/* Collect architecture names; has_efi is a bitmask of (1 << ARCH_*) */
		char archs[128] = "";
		size_t an = 0;
		for (int i = ARCH_X86_32; i < ARCH_MAX; i++) {
			if (img.has_efi & (1u << i)) {
				int _rc = snprintf(archs + an, sizeof(archs) - an,
				                   "%s%s", an ? ", " : "", img_arch_name(i));
				if (_rc > 0) an += (size_t)_rc;
			}
		}
		if (archs[0])
			APPEND("\nArchitecture: %s", archs);
		else
			APPEND("\nEFI bootable");
	}

	/* ---- Secure Boot ---- */
	if (img.has_secureboot_bootloader & 0xfe)
		APPEND("\nSecure Boot: REVOKED (mask 0x%02x)", img.has_secureboot_bootloader & 0xfe);
	else if (img.has_secureboot_bootloader & 1)
		APPEND("\nSecure Boot: signed");

	/* ---- GRUB2 ---- */
	if (img.has_grub2 && img.grub2_version[0])
		APPEND("\nGRUB: %s", img.grub2_version);

	/* ---- Compression ---- */
	const char *comp = img_compression_name(img.compression_type);
	if (comp)
		APPEND("\nCompression: %s", comp);

#undef APPEND
	buf[n < sz ? n : sz - 1] = '\0';
	return n;
}
