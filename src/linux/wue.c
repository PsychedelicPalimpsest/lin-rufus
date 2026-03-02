/*
 * Rufus: The Reliable USB Formatting Utility
 * Windows User Experience — Linux port
 * Copyright © 2022-2025 Pete Batard <pete@akeo.ie>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <strings.h>  /* strcasecmp */
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>

#include "rufus.h"
#include "localization.h"
#include "missing.h"
#include "resource.h"
#include "vhd.h"
#include "xml.h"
#include "wue.h"
#include "wimlib.h"
#include "timezone.h"
#include "wintogo_bcd.h"

/* bypass registry key names (same as Windows) */
const char* bypass_name[] = { "BypassTPMCheck", "BypassSecureBootCheck", "BypassRAMCheck" };

/* Forward declarations */
static BOOL mkdir_all(const char *path);

int  unattend_xml_flags = 0, wintogo_index = -1, wininst_index = 0;
int  unattend_xml_mask  = UNATTEND_DEFAULT_SELECTION_MASK;
char *unattend_xml_path = NULL, unattend_username[MAX_USERNAME_LENGTH];
BOOL is_bootloader_revoked = FALSE;

/* -----------------------------------------------------------------------
 * CreateUnattendXml
 *   Generate an autounattend.xml answer file.
 * ----------------------------------------------------------------------- */
char* CreateUnattendXml(int arch, int flags)
{
	const static char* xml_arch_names[5] = { "x86", "amd64", "arm", "arm64" };
	const static char* unallowed_account_names[] = {
		"Administrator", "Guest", "KRBTGT", "Local", "NONE"
	};
	static char path[MAX_PATH];
	FILE* fd;
	int i, order;

	unattend_xml_flags = flags;
	if (arch < ARCH_X86_32 || arch > ARCH_ARM_64 || flags == 0) {
		uprintf("Note: No Windows User Experience options selected");
		return NULL;
	}
	arch--;  /* convert to 0-based index */

	if (temp_dir[0] == '\0')
		static_strcpy(temp_dir, "/tmp");

	if (GetTempFileName(temp_dir, APPLICATION_NAME, 0, path) == 0)
		return NULL;
	fd = fopen(path, "w");
	if (fd == NULL)
		return NULL;

	uprintf("Selected Windows User Experience options:");
	fprintf(fd, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
	fprintf(fd, "<unattend xmlns=\"urn:schemas-microsoft-com:unattend\">\n");

	if (flags & UNATTEND_WINPE_SETUP_MASK) {
		order = 1;
		fprintf(fd, "  <settings pass=\"windowsPE\">\n");
		fprintf(fd,
			"    <component name=\"Microsoft-Windows-Setup\" processorArchitecture=\"%s\""
			" language=\"neutral\""
			" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\""
			" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
			" publicKeyToken=\"31bf3856ad364e35\" versionScope=\"nonSxS\">\n",
			xml_arch_names[arch]);
		fprintf(fd, "      <UserData>\n");
		fprintf(fd, "        <ProductKey>\n");
		fprintf(fd, "          <Key />\n");
		fprintf(fd, "        </ProductKey>\n");
		fprintf(fd, "      </UserData>\n");
		if (flags & UNATTEND_SECUREBOOT_TPM_MINRAM) {
			uprintf("• Bypass SB/TPM/RAM");
			fprintf(fd, "      <RunSynchronous>\n");
			for (i = 0; i < ARRAYSIZE(bypass_name); i++) {
				fprintf(fd, "        <RunSynchronousCommand wcm:action=\"add\">\n");
				fprintf(fd, "          <Order>%d</Order>\n", order++);
				fprintf(fd,
					"          <Path>reg add HKLM\\SYSTEM\\Setup\\LabConfig"
					" /v %s /t REG_DWORD /d 1 /f</Path>\n",
					bypass_name[i]);
				fprintf(fd, "        </RunSynchronousCommand>\n");
			}
			fprintf(fd, "      </RunSynchronous>\n");
		}
		fprintf(fd, "    </component>\n");
		fprintf(fd, "  </settings>\n");
	}

	if (flags & UNATTEND_SPECIALIZE_DEPLOYMENT_MASK) {
		order = 1;
		fprintf(fd, "  <settings pass=\"specialize\">\n");
		fprintf(fd,
			"    <component name=\"Microsoft-Windows-Deployment\""
			" processorArchitecture=\"%s\" language=\"neutral\""
			" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\""
			" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
			" publicKeyToken=\"31bf3856ad364e35\" versionScope=\"nonSxS\">\n",
			xml_arch_names[arch]);
		fprintf(fd, "      <RunSynchronous>\n");
		if (flags & UNATTEND_NO_ONLINE_ACCOUNT) {
			uprintf("• Bypass online account requirement");
			fprintf(fd, "        <RunSynchronousCommand wcm:action=\"add\">\n");
			fprintf(fd, "          <Order>%d</Order>\n", order++);
			fprintf(fd,
				"          <Path>reg add"
				" HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OOBE"
				" /v BypassNRO /t REG_DWORD /d 1 /f</Path>\n");
			fprintf(fd, "        </RunSynchronousCommand>\n");
		}
		fprintf(fd, "      </RunSynchronous>\n");
		fprintf(fd, "    </component>\n");
		fprintf(fd, "  </settings>\n");
	}

	if (flags & UNATTEND_OOBE_MASK) {
		order = 1;
		fprintf(fd, "  <settings pass=\"oobeSystem\">\n");
		if (flags & UNATTEND_OOBE_SHELL_SETUP_MASK) {
			fprintf(fd,
				"    <component name=\"Microsoft-Windows-Shell-Setup\""
				" processorArchitecture=\"%s\" language=\"neutral\""
				" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\""
				" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
				" publicKeyToken=\"31bf3856ad364e35\" versionScope=\"nonSxS\">\n",
				xml_arch_names[arch]);
			if (flags & UNATTEND_NO_DATA_COLLECTION) {
				uprintf("• Disable data collection");
				fprintf(fd, "      <OOBE>\n");
				fprintf(fd, "        <ProtectYourPC>3</ProtectYourPC>\n");
				fprintf(fd, "      </OOBE>\n");
			}
			if (flags & UNATTEND_DUPLICATE_LOCALE) {
				const char* wintz = IanaToWindowsTimezone();
				uprintf("• Timezone: %s", wintz);
				fprintf(fd, "      <TimeZone>%s</TimeZone>\n", wintz);
			}
			if (flags & UNATTEND_SET_USER) {
				int allowed = 1;
				for (i = 0; i < ARRAYSIZE(unallowed_account_names); i++) {
					if (strcasecmp(unattend_username, unallowed_account_names[i]) == 0) {
						allowed = 0;
						break;
					}
				}
				if (!allowed) {
					uprintf("WARNING: '%s' is not allowed as local account name - Option ignored",
						unattend_username);
				} else if (unattend_username[0] != 0) {
					uprintf("• Use '%s' for local account name", unattend_username);
					fprintf(fd, "      <UserAccounts>\n");
					fprintf(fd, "        <LocalAccounts>\n");
					fprintf(fd, "          <LocalAccount wcm:action=\"add\">\n");
					fprintf(fd, "            <Name>%s</Name>\n", unattend_username);
					fprintf(fd, "            <DisplayName>%s</DisplayName>\n", unattend_username);
					fprintf(fd, "            <Group>Administrators;Power Users</Group>\n");
					fprintf(fd, "            <Password>\n");
					fprintf(fd, "              <Value>UABhAHMAcwB3AG8AcgBkAA==</Value>\n");
					fprintf(fd, "              <PlainText>false</PlainText>\n");
					fprintf(fd, "            </Password>\n");
					fprintf(fd, "          </LocalAccount>\n");
					fprintf(fd, "        </LocalAccounts>\n");
					fprintf(fd, "      </UserAccounts>\n");
					fprintf(fd, "      <FirstLogonCommands>\n");
					fprintf(fd, "        <SynchronousCommand wcm:action=\"add\">\n");
					fprintf(fd, "          <Order>%d</Order>\n", order++);
					fprintf(fd,
						"          <CommandLine>net user &quot;%s&quot;"
						" /logonpasswordchg:yes</CommandLine>\n",
						unattend_username);
					fprintf(fd, "        </SynchronousCommand>\n");
					fprintf(fd, "        <SynchronousCommand wcm:action=\"add\">\n");
					fprintf(fd, "          <Order>%d</Order>\n", order++);
					fprintf(fd,
						"          <CommandLine>net accounts"
						" /maxpwage:unlimited</CommandLine>\n");
					fprintf(fd, "        </SynchronousCommand>\n");
					fprintf(fd, "      </FirstLogonCommands>\n");
				}
			}
			fprintf(fd, "    </component>\n");
		}
		if (flags & UNATTEND_DISABLE_BITLOCKER) {
			uprintf("• Disable bitlocker");
			fprintf(fd,
				"    <component name=\"Microsoft-Windows-SecureStartup-FilterDriver\""
				" processorArchitecture=\"%s\" language=\"neutral\""
				" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\""
				" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
				" publicKeyToken=\"31bf3856ad364e35\" versionScope=\"nonSxS\">\n",
				xml_arch_names[arch]);
			fprintf(fd, "      <PreventDeviceEncryption>true</PreventDeviceEncryption>\n");
			fprintf(fd, "    </component>\n");
			fprintf(fd,
				"    <component name=\"Microsoft-Windows-EnhancedStorage-Adm\""
				" processorArchitecture=\"%s\" language=\"neutral\""
				" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\""
				" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
				" publicKeyToken=\"31bf3856ad364e35\" versionScope=\"nonSxS\">\n",
				xml_arch_names[arch]);
			fprintf(fd, "      <TCGSecurityActivationDisabled>1</TCGSecurityActivationDisabled>\n");
			fprintf(fd, "    </component>\n");
		}
		fprintf(fd, "  </settings>\n");
	}

	if (flags & UNATTEND_OFFLINE_SERVICING_MASK) {
		fprintf(fd, "  <settings pass=\"offlineServicing\">\n");
		if (flags & UNATTEND_OFFLINE_INTERNAL_DRIVES) {
			uprintf("• Set internal drives offline");
			fprintf(fd,
				"    <component name=\"Microsoft-Windows-PartitionManager\""
				" processorArchitecture=\"%s\" language=\"neutral\""
				" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\""
				" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
				" publicKeyToken=\"31bf3856ad364e35\" versionScope=\"nonSxS\">\n",
				xml_arch_names[arch]);
			fprintf(fd, "      <SanPolicy>4</SanPolicy>\n");
			fprintf(fd, "    </component>\n");
		}
		if (flags & UNATTEND_FORCE_S_MODE) {
			uprintf("• Enforce S Mode");
			fprintf(fd,
				"    <component name=\"Microsoft-Windows-CodeIntegrity\""
				" processorArchitecture=\"%s\" language=\"neutral\""
				" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\""
				" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
				" publicKeyToken=\"31bf3856ad364e35\" versionScope=\"nonSxS\">\n",
				xml_arch_names[arch]);
			fprintf(fd, "      <SkuPolicyRequired>1</SkuPolicyRequired>\n");
			fprintf(fd, "    </component>\n");
		}
		fprintf(fd, "  </settings>\n");
	}

	if (flags & UNATTEND_USE_MS2023_BOOTLOADERS)
		uprintf("• Use 'Windows CA 2023' signed bootloaders");

	fprintf(fd, "</unattend>\n");
	fclose(fd);
	return path;
}

/* -----------------------------------------------------------------------
 * wue_compute_option_flags
 *   Return a bitmask of UNATTEND_* flags that should be presented to the
 *   user in the WUE dialog, based on the Windows image version and whether
 *   expert mode is active.  Extracted here so it can be unit-tested without
 *   any UI dependency.
 * ----------------------------------------------------------------------- */
int wue_compute_option_flags(const RUFUS_IMG_REPORT *ir, BOOL exp_mode)
{
	const RUFUS_IMG_REPORT r = *ir;
	int flags = UNATTEND_SET_USER | UNATTEND_DUPLICATE_LOCALE |
	            UNATTEND_NO_DATA_COLLECTION | UNATTEND_DISABLE_BITLOCKER;
	if (IS_WINDOWS_11(r))
		flags |= UNATTEND_SECUREBOOT_TPM_MINRAM;
	if (r.win_version.build >= 22500)
		flags |= UNATTEND_NO_ONLINE_ACCOUNT;
	if (r.win_version.build >= 26200)
		flags |= UNATTEND_USE_MS2023_BOOTLOADERS;
	if (exp_mode)
		flags |= UNATTEND_FORCE_S_MODE;
	return flags;
}

/* -----------------------------------------------------------------------
 * PopulateWindowsVersionFromXml  (static helper)
 * ----------------------------------------------------------------------- */
static void PopulateWindowsVersionFromXml(const char* xml, size_t xml_len, int index)
{
	char* val;
	ezxml_t pxml = ezxml_parse_str((char*)xml, xml_len);
	if (pxml == NULL)
		return;

	val = ezxml_get_val(pxml, "IMAGE", index, "WINDOWS", 0, "VERSION", 0, "MAJOR", -1);
	img_report.win_version.major = (uint16_t)safe_atoi(val);
	val = ezxml_get_val(pxml, "IMAGE", index, "WINDOWS", 0, "VERSION", 0, "MINOR", -1);
	img_report.win_version.minor = (uint16_t)safe_atoi(val);
	val = ezxml_get_val(pxml, "IMAGE", index, "WINDOWS", 0, "VERSION", 0, "BUILD", -1);
	img_report.win_version.build = (uint16_t)safe_atoi(val);
	val = ezxml_get_val(pxml, "IMAGE", index, "WINDOWS", 0, "VERSION", 0, "SPBUILD", -1);
	img_report.win_version.revision = (uint16_t)safe_atoi(val);

	/* Normalise version numbers */
	if (img_report.win_version.major <= 5) {
		img_report.win_version.major = 0;
		img_report.win_version.minor = 0;
	} else if (img_report.win_version.major == 6) {
		if (img_report.win_version.minor == 0) {
			img_report.win_version.major = 0;
		} else if (img_report.win_version.minor == 1) {
			img_report.win_version.major = 7;
			img_report.win_version.minor = 0;
		} else if (img_report.win_version.minor == 2) {
			img_report.win_version.major = 8;
			img_report.win_version.minor = 0;
		} else if (img_report.win_version.minor == 3) {
			img_report.win_version.major = 8;
			img_report.win_version.minor = 1;
		} else if (img_report.win_version.minor == 4) {
			img_report.win_version.major = 10;
			img_report.win_version.minor = 0;
		}
	} else if (img_report.win_version.major == 10) {
		if (img_report.win_version.build > 20000)
			img_report.win_version.major = 11;
	}
	ezxml_free(pxml);
}

/* -----------------------------------------------------------------------
 * PopulateWindowsVersion
 * ----------------------------------------------------------------------- */
BOOL PopulateWindowsVersion(void)
{
	int r;
	char wim_path[4 * MAX_PATH] = "";
	char* xml = NULL;
	size_t xml_len;
	WIMStruct* wim = NULL;

	memset(&img_report.win_version, 0, sizeof(img_report.win_version));

	if (safe_strlen(image_path) == 0)
		goto out;

	assert(safe_strlen(image_path) + 1 < ARRAYSIZE(wim_path));
	static_strcpy(wim_path, image_path);
	if (!img_report.is_windows_img) {
		assert(safe_strlen(image_path) + safe_strlen(&img_report.wininst_path[0][1]) + 1
			< ARRAYSIZE(wim_path));
		static_strcat(wim_path, "|");
		static_strcat(wim_path, &img_report.wininst_path[0][1]);
	}

	r = wimlib_open_wimU(wim_path, 0, &wim);
	if (r != 0) {
		uprintf("Could not open WIM: Error %d", r);
		goto out;
	}

	r = wimlib_get_xml_data(wim, (void**)&xml, &xml_len);
	if (r != 0) {
		uprintf("Could not read WIM XML index: Error %d", r);
		goto out;
	}

	PopulateWindowsVersionFromXml(xml, xml_len, 0);

out:
	free(xml);
	if (wim)
		wimlib_free(wim);

	return ((img_report.win_version.major != 0) && (img_report.win_version.build != 0));
}

/* -----------------------------------------------------------------------
 * Stubs for Windows-only / unported functions
 * ----------------------------------------------------------------------- */
static BOOL copy_file(const char *src, const char *dst); /* defined later */

/* Module-level mount path set by the caller before using WUE functions */
static char *s_mount_path = NULL;

BOOL SetupWinPE(char drive_letter)
{
	(void)drive_letter; /* Linux uses s_mount_path instead */

	if (s_mount_path == NULL)
		return FALSE;

	const char* basedir[3] = { "i386", "amd64", "minint" };
	const char* patch_str_org[2] = { "\\minint\\txtsetup.sif", "\\minint\\system32\\" };
	const char* patch_str_rep[2][2] = {
		{ "\\i386\\txtsetup.sif",  "\\i386\\system32\\"  },
		{ "\\amd64\\txtsetup.sif", "\\amd64\\system32\\" }
	};
	const char* setupsrcdev = "SetupSourceDevice = \"\\device\\harddisk1\\partition1\"";
	const char* win_nt_bt_org = "$win_nt$.~bt";
	const char* rdisk_zero = "rdisk(0)";
	unsigned i, j;
	int index = 0;
	BOOL r = FALSE;
	char src[MAX_PATH], dst[MAX_PATH];
	char *buffer = NULL;
	FILE *fh = NULL;
	size_t size, read_size;

	if ((img_report.winpe & WINPE_AMD64) == WINPE_AMD64)
		index = 1;
	else if ((img_report.winpe & WINPE_MININT) == WINPE_MININT)
		index = 2;

	/* Copy ntdetect.com to root */
	static_sprintf(src, "%s/%s/ntdetect.com", s_mount_path, basedir[2 * (index / 2)]);
	static_sprintf(dst, "%s/ntdetect.com", s_mount_path);
	if (!copy_file(src, dst))
		uprintf("Did not copy %s as %s\n", src, dst);

	if (!img_report.uses_minint) {
		/* Copy txtsetup.sif to root (keep original unmodified) */
		static_sprintf(src, "%s/%s/txtsetup.sif", s_mount_path, basedir[index]);
		static_sprintf(dst, "%s/txtsetup.sif", s_mount_path);
		if (!copy_file(src, dst))
			uprintf("Did not copy %s as %s\n", src, dst);
		if (insert_section_data(dst, "[SetupData]", setupsrcdev, FALSE) == NULL) {
			uprintf("Failed to add SetupSourceDevice in %s\n", dst);
			goto out;
		}
		uprintf("Successfully added '%s' to %s\n", setupsrcdev, dst);
	}

	/* Copy setupldr.bin as BOOTMGR */
	static_sprintf(src, "%s/%s/setupldr.bin", s_mount_path, basedir[2 * (index / 2)]);
	static_sprintf(dst, "%s/BOOTMGR", s_mount_path);
	if (!copy_file(src, dst))
		uprintf("Did not copy %s as %s\n", src, dst);

	/* \minint + /minint option → no further patching needed */
	/* \minint without /minint and no i386/amd64 → unclear, skip */
	if (img_report.winpe & WINPE_MININT) {
		if (img_report.uses_minint) {
			uprintf("Detected \\minint directory with /minint option: nothing to patch\n");
			r = TRUE;
		} else if (!(img_report.winpe & (WINPE_I386 | WINPE_AMD64))) {
			uprintf("Detected \\minint directory only but no /minint option: not sure what to do\n");
		}
		goto out;
	}

	/* Open BOOTMGR for patching */
	fh = fopen(dst, "r+b");
	if (fh == NULL) {
		uprintf("Could not open %s for patching\n", dst);
		goto out;
	}
	fseek(fh, 0, SEEK_END);
	size = (size_t)ftell(fh);
	rewind(fh);
	buffer = malloc(size);
	if (buffer == NULL)
		goto out;
	read_size = fread(buffer, 1, size, fh);
	if (read_size != size) {
		uprintf("Could not read file %s\n", dst);
		goto out;
	}
	rewind(fh);

	/* Patch BOOTMGR */
	uprintf("Patching file %s\n", dst);
	/* Remove CRC check for 32-bit setupldr.bin from Win2k3 */
	if ((size > 0x2061) && ((uint8_t)buffer[0x2060] == 0x74) && ((uint8_t)buffer[0x2061] == 0x03)) {
		buffer[0x2060] = (char)0xeb;
		buffer[0x2061] = (char)0x1a;
		uprintf("  0x00002060: 0x74 0x03 -> 0xEB 0x1A (disable Win2k3 CRC check)\n");
	}
	for (i = 1; i < size - 32; i++) {
		for (j = 0; j < 2; j++) {
			if (safe_strnicmp(&buffer[i], patch_str_org[j], strlen(patch_str_org[j]) - 1) == 0) {
				assert(index < 2);
				uprintf("  0x%08X: '%s' -> '%s'\n", i, &buffer[i], patch_str_rep[index][j]);
				strcpy(&buffer[i], patch_str_rep[index][j]);
				i += (unsigned)max(strlen(patch_str_org[j]), strlen(patch_str_rep[index][j]));
			}
		}
	}
	if (!img_report.uses_minint) {
		for (i = 0; i < size - 32; i++) {
			/* rdisk(0) → rdisk(1) */
			if (safe_strnicmp(&buffer[i], rdisk_zero, strlen(rdisk_zero) - 1) == 0) {
				buffer[i + 6] = '1';
				uprintf("  0x%08X: '%s' -> 'rdisk(1)'\n", i, rdisk_zero);
			}
			/* $win_nt$.~bt → i386/amd64 */
			if (safe_strnicmp(&buffer[i], win_nt_bt_org, strlen(win_nt_bt_org) - 1) == 0) {
				uprintf("  0x%08X: '%s' -> '%s%s'\n", i, &buffer[i], basedir[index],
				        &buffer[i + strlen(win_nt_bt_org)]);
				strcpy(&buffer[i], basedir[index]);
				buffer[i + strlen(basedir[index])] = buffer[i + strlen(win_nt_bt_org)];
				buffer[i + strlen(basedir[index]) + 1] = 0;
			}
		}
	}
	if (fwrite(buffer, 1, size, fh) != size) {
		uprintf("Could not write patched file %s\n", dst);
		goto out;
	}
	r = TRUE;

out:
	if (fh) fclose(fh);
	free(buffer);
	return r;
}

BOOL SetupWinToGo(DWORD di, const char* dn, BOOL use_esp)
{
	char wim_path[4 * MAX_PATH];
	char path[MAX_PATH];
	FILE *fh;
	BOOL r = FALSE;

	(void)di; (void)use_esp;

	if (dn == NULL) {
		uprintf("SetupWinToGo: no drive path specified");
		return FALSE;
	}

	if (wintogo_index < 0) {
		uprintf("SetupWinToGo: no WIM index selected");
		return FALSE;
	}

	/* Build the WIM path (image_path, optionally with wininst sub-path) */
	assert(safe_strlen(image_path) < ARRAYSIZE(wim_path));
	static_strcpy(wim_path, image_path);
	if (!img_report.is_windows_img) {
		assert(safe_strlen(image_path) + safe_strlen(&img_report.wininst_path[wininst_index][3]) + 1 < ARRAYSIZE(wim_path));
		static_strcat(wim_path, "|");
		static_strcat(wim_path, &img_report.wininst_path[wininst_index][3]);
	}

	uprintf("Windows To Go: applying WIM '%s' (index %d) to '%s'", wim_path, wintogo_index, dn);
	if (!WimApplyImage(wim_path, wintogo_index, dn)) {
		uprintf("Windows To Go: WimApplyImage failed");
		if (!IS_ERROR(ErrorStatus))
			ErrorStatus = RUFUS_ERROR(APPERR(ERROR_ISO_EXTRACT));
		return FALSE;
	}

	/* Create EFI/Microsoft/Boot/ directory */
	snprintf(path, sizeof(path), "%s/EFI/Microsoft/Boot", dn);
	if (!mkdir_all(path)) {
		uprintf("Windows To Go: failed to create %s: %s", path, strerror(errno));
		return FALSE;
	}

	/* Write the BCD template */
	snprintf(path, sizeof(path), "%s/EFI/Microsoft/Boot/BCD", dn);
	fh = fopen(path, "wb");
	if (fh == NULL) {
		uprintf("Windows To Go: cannot create BCD: %s", strerror(errno));
		return FALSE;
	}
	if (fwrite(wintogo_bcd_template, 1, wintogo_bcd_template_len, fh) != wintogo_bcd_template_len) {
		uprintf("Windows To Go: failed to write BCD");
		fclose(fh);
		return FALSE;
	}
	fclose(fh);
	uprintf("Windows To Go: wrote BCD store (%zu bytes)", wintogo_bcd_template_len);

	/* Copy bootmgfw.efi from the applied Windows tree to EFI/Microsoft/Boot/ */
	char src_efi[MAX_PATH], dst_efi[MAX_PATH];
	snprintf(src_efi, sizeof(src_efi), "%s/Windows/Boot/EFI/bootmgfw.efi", dn);
	snprintf(dst_efi, sizeof(dst_efi), "%s/EFI/Microsoft/Boot/bootmgfw.efi", dn);

	FILE *src_fh = fopen(src_efi, "rb");
	if (src_fh != NULL) {
		fh = fopen(dst_efi, "wb");
		if (fh != NULL) {
			char buf[4096];
			size_t n;
			while ((n = fread(buf, 1, sizeof(buf), src_fh)) > 0)
				fwrite(buf, 1, n, fh);
			fclose(fh);
			uprintf("Windows To Go: copied bootmgfw.efi to EFI/Microsoft/Boot/");

			/* Also create EFI/BOOT/ with BOOTX64.EFI fallback */
			snprintf(path, sizeof(path), "%s/EFI/BOOT", dn);
			mkdir_all(path);
			snprintf(path, sizeof(path), "%s/EFI/BOOT/BOOTX64.EFI", dn);
			fh = fopen(path, "wb");
			if (fh != NULL) {
				rewind(src_fh);
				/* Re-open source since we rewound */
				fclose(src_fh);
				src_fh = fopen(src_efi, "rb");
				if (src_fh != NULL) {
					while ((n = fread(buf, 1, sizeof(buf), src_fh)) > 0)
						fwrite(buf, 1, n, fh);
				}
				fclose(fh);
			}
		} else {
			uprintf("Windows To Go: cannot create %s: %s", dst_efi, strerror(errno));
		}
	} else {
		uprintf("Windows To Go: bootmgfw.efi not found at %s (non-fatal)", src_efi);
	}
	if (src_fh != NULL)
		fclose(src_fh);

	UpdateProgressWithInfo(OP_FILE_COPY, MSG_267, 100, 100);
	r = TRUE;
	return r;
}

BOOL CopySKUSiPolicy(const char* drive_name)
{
	(void)drive_name;
	return FALSE;
}

int SetWinToGoIndex(void)
{
	int i, r;
	WIMStruct *wim = NULL;
	char wim_path[4 * MAX_PATH] = "";
	char *xml = NULL;
	size_t xml_len;
	StrArray version_name = { 0 }, version_index = { 0 };
	BOOL bNonStandard = FALSE;
	ezxml_t index_xml = NULL, image = NULL;

	wintogo_index = -1;
	wininst_index = 0;

	if (fs_type != FS_NTFS)
		return -1;

	if (!image_path || !image_path[0])
		return -1;

	/* If multiple Windows install images, ask user which to use */
	if (img_report.wininst_index > 1) {
		char *install_names[MAX_WININST];
		for (i = 0; i < img_report.wininst_index; i++)
			install_names[i] = &img_report.wininst_path[i][1];
		wininst_index = _log2(SelectionDialog(lmprintf(MSG_130), lmprintf(MSG_131),
		                                      install_names, img_report.wininst_index));
		if (wininst_index < 0)
			return -2;
		if (wininst_index >= MAX_WININST)
			wininst_index = 0;
	}

	/* Build WIM path: either direct WIM or ISO|relative/wim/path */
	assert(safe_strlen(image_path) + 1 < ARRAYSIZE(wim_path));
	static_strcpy(wim_path, image_path);
	if (!img_report.is_windows_img) {
		/* wininst_path on Linux starts with '/', strip it for wimlib pipe syntax */
		assert(safe_strlen(image_path) +
		       safe_strlen(&img_report.wininst_path[wininst_index][1]) + 1
		       < ARRAYSIZE(wim_path));
		static_strcat(wim_path, "|");
		static_strcat(wim_path, &img_report.wininst_path[wininst_index][1]);
	}

	r = wimlib_open_wimU(wim_path, 0, &wim);
	if (r != 0) {
		uprintf("Could not open WIM: Error %d", r);
		goto out;
	}

	r = wimlib_get_xml_data(wim, (void **)&xml, &xml_len);
	if (r != 0) {
		uprintf("Could not read WIM XML: Error %d", r);
		goto out;
	}

	StrArrayCreate(&version_name, 16);
	StrArrayCreate(&version_index, 16);
	index_xml = ezxml_parse_str(xml, xml_len);
	if (index_xml == NULL) {
		uprintf("Could not parse WIM XML");
		goto out;
	}

	for (i = 0, image = ezxml_child(index_xml, "IMAGE");
	     image != NULL && StrArrayAdd(&version_index, ezxml_attr(image, "INDEX"), TRUE) >= 0;
	     image = image->next, i++) {
		const char *dn = ezxml_child_val(image, "DISPLAYNAME");
		if (!dn || !dn[0])
			dn = ezxml_child_val(image, "DESCRIPTION");
		if (!dn || !dn[0]) {
			uprintf("WARNING: Could not find description for image index %d", i + 1);
			dn = "Unknown Windows Version";
			bNonStandard = TRUE;
		}
		StrArrayAdd(&version_name, dn, TRUE);
	}

	if (bNonStandard)
		uprintf("WARNING: Nonstandard Windows image (missing <DISPLAYNAME> entries)");

	if (i > 1)
		/* NB: _log2 returns -2 if SelectionDialog returns negative (user cancelled) */
		i = _log2(SelectionDialog(lmprintf(MSG_291), lmprintf(MSG_292),
		                          version_name.String, i)) + 1;
	if (i < 0)
		wintogo_index = -2;
	else if (i == 0)
		wintogo_index = 1;
	else
		wintogo_index = atoi(version_index.String[i - 1]);

	if (i > 0) {
		PopulateWindowsVersionFromXml(xml, xml_len, i - 1);
		if (img_report.win_version.major == 0 || img_report.win_version.build == 0)
			uprintf("WARNING: Could not get version info from WIM XML (nonstandard image?)");
		if (i > 0 && (size_t)i <= version_name.Index)
			uprintf("Will use '%s' (Index %s) for Windows To Go",
			        version_name.String[i - 1], version_index.String[i - 1]);
	}

out:
	StrArrayDestroy(&version_name);
	StrArrayDestroy(&version_index);
	free(xml);
	if (index_xml)
		ezxml_free(index_xml);
	if (wim)
		wimlib_free(wim);
	return wintogo_index;
}

/* Module-level mount path set by the caller before ApplyWindowsCustomization */
void wue_set_mount_path(const char *path)
{
	free(s_mount_path);
	s_mount_path = path ? strdup(path) : NULL;
}

/* Recursively create a directory hierarchy (up to 8 path components deep) */
static BOOL mkdir_all(const char *path)
{
	char buf[MAX_PATH];
	if (!path || strlen(path) >= sizeof(buf))
		return FALSE;
	strncpy(buf, path, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';
	for (char *p = buf + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			if (mkdir(buf, 0755) != 0 && errno != EEXIST)
				return FALSE;
			*p = '/';
		}
	}
	if (mkdir(buf, 0755) != 0 && errno != EEXIST)
		return FALSE;
	return TRUE;
}

/* Copy a file from src_path to dst_path */
static BOOL copy_file(const char *src, const char *dst)
{
	FILE *in = fopen(src, "rb");
	if (!in) return FALSE;
	FILE *out = fopen(dst, "wb");
	if (!out) { fclose(in); return FALSE; }
	char buf[4096];
	size_t n;
	BOOL ok = TRUE;
	while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
		if (fwrite(buf, 1, n, out) != n) { ok = FALSE; break; }
	}
	fclose(in);
	fclose(out);
	return ok;
}

extern const char* efi_archname[];

/* Remove all occurrences of sub from str in-place */
static void remove_substring(char *str, const char *sub)
{
	size_t sublen = strlen(sub);
	char *p;
	while ((p = strstr(str, sub)) != NULL)
		memmove(p, p + sublen, strlen(p + sublen) + 1);
}

/*
 * Extract Windows/Boot/EFI_EX and Windows/Boot/Fonts_EX from boot.wim
 * and copy them to the correct locations on the mounted drive.
 *
 * EFI_EX/bootmgfw_EX.efi → efi/boot/boot<arch>.efi (for each arch present)
 * EFI_EX/bootmgr_EX.efi  → bootmgr.efi
 * Fonts_EX/<name>         → efi/microsoft/boot/Fonts/<name with _EX removed>
 */
static BOOL install_ms2023_bootloaders(WIMStruct *wim, int wim_index,
                                        const char *mount_path)
{
	BOOL r = FALSE;
	char tmp_dir[] = "/tmp/rufus-ms2023-XXXXXX";
	char src_path[MAX_PATH], dst_path[MAX_PATH];

	if (mkdtemp(tmp_dir) == NULL) {
		uprintf_errno("MS2023 bootloaders: mkdtemp failed");
		return FALSE;
	}

	/* Extract EFI_EX → tmp_dir/EFI_EX/ */
	const char *efi_ex_wim_path = "\\Windows\\Boot\\EFI_EX";
	if (wimlib_extract_pathsU(wim, wim_index, tmp_dir, &efi_ex_wim_path, 1,
	        WIMLIB_EXTRACT_FLAG_NO_ACLS |
	        WIMLIB_EXTRACT_FLAG_NO_PRESERVE_DIR_STRUCTURE) != 0) {
		uprintf("MS2023 bootloaders: EFI_EX not found in boot.wim — skipping");
		goto cleanup;
	}

	/* Replace efi/boot/boot<arch>.efi for each arch present on the drive */
	snprintf(src_path, sizeof(src_path), "%s/EFI_EX/bootmgfw_EX.efi", tmp_dir);
	for (int i = 1; i < ARCH_MAX; i++) {
		snprintf(dst_path, sizeof(dst_path), "%s/efi/boot/boot%s.efi",
		         mount_path, efi_archname[i]);
		if (access(dst_path, F_OK) == 0) {
			if (copy_file(src_path, dst_path))
				uprintf("  Replaced efi/boot/boot%s.efi with MS 2023 bootloader",
				        efi_archname[i]);
			else
				uprintf("  WARNING: failed to replace efi/boot/boot%s.efi",
				        efi_archname[i]);
		}
	}

	/* Replace bootmgr.efi at the mount root */
	snprintf(src_path, sizeof(src_path), "%s/EFI_EX/bootmgr_EX.efi", tmp_dir);
	snprintf(dst_path, sizeof(dst_path), "%s/bootmgr.efi", mount_path);
	if (access(src_path, F_OK) == 0) {
		if (copy_file(src_path, dst_path))
			uprintf("  Replaced bootmgr.efi with MS 2023 bootloader");
	}

	/* Extract Fonts_EX → tmp_dir/Fonts_EX/ (non-fatal if absent) */
	const char *fonts_ex_wim_path = "\\Windows\\Boot\\Fonts_EX";
	if (wimlib_extract_pathsU(wim, wim_index, tmp_dir, &fonts_ex_wim_path, 1,
	        WIMLIB_EXTRACT_FLAG_NO_ACLS |
	        WIMLIB_EXTRACT_FLAG_NO_PRESERVE_DIR_STRUCTURE) != 0) {
		uprintf("MS2023 bootloaders: Fonts_EX not found in boot.wim — skipping fonts");
		r = TRUE;
		goto cleanup;
	}

	/* Walk Fonts_EX, copy each file with _EX stripped from the path */
	{
		char fonts_src_dir[MAX_PATH];
		snprintf(fonts_src_dir, sizeof(fonts_src_dir), "%s/Fonts_EX", tmp_dir);
		DIR *dp = opendir(fonts_src_dir);
		if (dp) {
			struct dirent *ent;
			while ((ent = readdir(dp)) != NULL) {
				if (ent->d_name[0] == '.') continue;
				snprintf(src_path, sizeof(src_path), "%s/%s",
				         fonts_src_dir, ent->d_name);
				/* Build dst: <mount>/efi/microsoft/boot/Fonts_EX/<name> */
				snprintf(dst_path, sizeof(dst_path),
				         "%s/efi/microsoft/boot/Fonts_EX/%s",
				         mount_path, ent->d_name);
				/* Remove _EX from dir name and filename */
				remove_substring(dst_path, "_EX");
				/* Ensure parent directory exists */
				char parent[MAX_PATH];
				snprintf(parent, sizeof(parent), "%s", dst_path);
				char *slash = strrchr(parent, '/');
				if (slash) {
					*slash = '\0';
					mkdir_all(parent);
				}
				if (copy_file(src_path, dst_path))
					uprintf("  Copied MS 2023 font: %s", ent->d_name);
			}
			closedir(dp);
		}
	}

	r = TRUE;
cleanup:
	{
		char cmd[MAX_PATH + 16];
		snprintf(cmd, sizeof(cmd), "rm -rf %s", tmp_dir);
		system(cmd);
	}
	return r;
}

BOOL ApplyWindowsCustomization(char drive_letter, int flags)
{
	(void)drive_letter;
	BOOL r = FALSE, update_boot_wim = FALSE, wim_write_needed = FALSE;
	int wim_index = 2, wuc_index = 0;
	char dir_path[MAX_PATH], file_path[MAX_PATH];
	char boot_wim_path[MAX_PATH];
	char appraiserres_src[MAX_PATH], appraiserres_bak[MAX_PATH];
	WIMStruct *wim = NULL;
	struct wimlib_update_command wuc[2] = { { 0 } };

	if (unattend_xml_path == NULL) {
		uprintf("ApplyWindowsCustomization: unattend_xml_path is NULL");
		return FALSE;
	}
	if (s_mount_path == NULL) {
		uprintf("ApplyWindowsCustomization: mount path not set");
		return FALSE;
	}

	uprintf("Applying Windows customization:");

	if (flags & UNATTEND_WINDOWS_TO_GO) {
		/* Windows To Go: copy to <mount>/Windows/Panther/unattend.xml */
		snprintf(dir_path, sizeof(dir_path), "%s/Windows/Panther", s_mount_path);
		if (!mkdir_all(dir_path)) {
			uprintf_errno("Could not create '%s'", dir_path);
			return FALSE;
		}
		snprintf(file_path, sizeof(file_path), "%s/unattend.xml", dir_path);
		if (!copy_file(unattend_xml_path, file_path)) {
			uprintf("Could not copy unattend.xml to '%s'", file_path);
			return FALSE;
		}
		uprintf("Created '%s'", file_path);
		return TRUE;
	}

	snprintf(boot_wim_path, sizeof(boot_wim_path), "%s/sources/boot.wim", s_mount_path);

	if (flags & UNATTEND_WINPE_SETUP_MASK) {
		/* Rename appraiserres.dll to .bak and create empty placeholder */
		snprintf(appraiserres_src, sizeof(appraiserres_src),
		         "%s/sources/appraiserres.dll", s_mount_path);
		snprintf(appraiserres_bak, sizeof(appraiserres_bak),
		         "%s/sources/appraiserres.bak", s_mount_path);

		struct stat st;
		if (stat(appraiserres_src, &st) == 0) {
			if (rename(appraiserres_src, appraiserres_bak) != 0)
				uprintf_errno("Could not rename '%s'", appraiserres_src);
			else
				uprintf("Renamed '%s' → '%s'", appraiserres_src, appraiserres_bak);
		}
		/* Create empty placeholder regardless of whether we renamed */
		FILE *fp = fopen(appraiserres_src, "wb");
		if (fp) {
			fclose(fp);
			uprintf("Created '%s' placeholder", appraiserres_src);
		}
	}

	/* Open boot.wim when WINPE_SETUP_MASK (write access needed) or
	 * MS2023_BOOTLOADERS (read-only suffices for extraction). */
	if ((flags & UNATTEND_WINPE_SETUP_MASK) || (flags & UNATTEND_USE_MS2023_BOOTLOADERS)) {
		struct stat st;
		if (stat(boot_wim_path, &st) == 0) {
			wim_write_needed = (flags & UNATTEND_WINPE_SETUP_MASK) != 0;
			int open_flags = wim_write_needed ? WIMLIB_OPEN_FLAG_WRITE_ACCESS : 0;
			wimlib_global_init(0);
			wimlib_set_print_errors(true);
			if (wimlib_open_wim(boot_wim_path, open_flags, &wim) == 0) {
				update_boot_wim = TRUE;
				/* Verify image 2 exists; fall back to 1 for unofficial ISOs */
				if (wimlib_resolve_image(wim, "2") != 2) {
					uprintf("WARNING: This image appears to be an UNOFFICIAL Windows ISO!");
					wim_index = 1;
				}
			} else {
				if (wim_write_needed) {
					uprintf("Could not open '%s' for update", boot_wim_path);
					goto out;
				}
				uprintf("Could not open '%s' for reading (MS2023 bootloaders skipped)",
				        boot_wim_path);
			}
		}
	}

	if (flags & UNATTEND_WINPE_SETUP_MASK) {
		if (update_boot_wim) {
			/* Inject Autounattend.xml into image root of boot.wim */
			wuc[wuc_index].op = WIMLIB_UPDATE_OP_ADD;
			wuc[wuc_index].add.fs_source_path = unattend_xml_path;
			wuc[wuc_index].add.wim_target_path = "Autounattend.xml";
			uprintf("Adding '%s' to '%s[%d]'",
			        wuc[wuc_index].add.wim_target_path, boot_wim_path, wim_index);
			wuc_index++;
		} else {
			/*
			 * No boot.wim present — fall back to OEM Panther.
			 * The unattend.xml will still be picked up for OOBE passes.
			 */
			uprintf("No boot.wim found; using OEM Panther fallback for unattend.xml");
			snprintf(dir_path, sizeof(dir_path),
			         "%s/sources/$OEM$/$$/Panther", s_mount_path);
			if (!mkdir_all(dir_path)) {
				uprintf_errno("Could not create '%s'", dir_path);
				goto out;
			}
			snprintf(file_path, sizeof(file_path), "%s/unattend.xml", dir_path);
			if (!copy_file(unattend_xml_path, file_path)) {
				uprintf("Could not copy unattend.xml to '%s'", file_path);
				goto out;
			}
			uprintf("Created '%s'", file_path);
		}
	} else {
		/* OOBE-only: copy to <mount>/sources/$OEM$/$$/Panther/unattend.xml */
		snprintf(dir_path, sizeof(dir_path),
		         "%s/sources/$OEM$/$$/Panther", s_mount_path);
		if (!mkdir_all(dir_path)) {
			uprintf_errno("Could not create '%s'", dir_path);
			goto out;
		}
		snprintf(file_path, sizeof(file_path), "%s/unattend.xml", dir_path);
		if (!copy_file(unattend_xml_path, file_path)) {
			uprintf("Could not copy unattend.xml to '%s'", file_path);
			goto out;
		}
		uprintf("Created '%s'", file_path);
	}

	if ((flags & UNATTEND_USE_MS2023_BOOTLOADERS) && update_boot_wim) {
		uprintf("Installing MS 2023 bootloaders...");
		if (!install_ms2023_bootloaders(wim, wim_index, s_mount_path)) {
			uprintf("WARNING: MS 2023 bootloader installation failed (non-fatal)");
			/* Non-fatal — continue */
		}
	}

	r = TRUE;

out:
	if (update_boot_wim) {
		if (wim_write_needed && r && wuc_index > 0) {
			uprintf("Updating '%s[%d]'...", boot_wim_path, wim_index);
			if (wimlib_update_image(wim, wim_index, wuc, wuc_index, 0) != 0 ||
			    wimlib_overwrite(wim, WIMLIB_WRITE_FLAG_RECOMPRESS, 1) != 0) {
				uprintf("Error: Failed to update '%s'", boot_wim_path);
				r = FALSE;
			}
		}
		wimlib_free(wim);
		wimlib_global_cleanup();
	}
	return r;
}
