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
#include <errno.h>

#include "rufus.h"
#include "vhd.h"
#include "xml.h"
#include "wue.h"
#include "wimlib.h"
#include "timezone.h"

/* bypass registry key names (same as Windows) */
const char* bypass_name[] = { "BypassTPMCheck", "BypassSecureBootCheck", "BypassRAMCheck" };

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
	(void)di; (void)dn; (void)use_esp;
	return FALSE;
}

BOOL CopySKUSiPolicy(const char* drive_name)
{
	(void)drive_name;
	return FALSE;
}

int SetWinToGoIndex(void)
{
	return -1;
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

BOOL ApplyWindowsCustomization(char drive_letter, int flags)
{
	(void)drive_letter;
	char dir_path[MAX_PATH], file_path[MAX_PATH];

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
	} else if (flags & UNATTEND_WINPE_SETUP_MASK) {
		/* TPM/SB bypass requires boot.wim patching — not yet implemented on Linux */
		uprintf("WARNING: Windows PE/setup customisation (TPM/SB bypass) requires "
		        "boot.wim patching which is not yet implemented on Linux");
		uprintf("The unattend.xml bypass will be skipped; other OOBE settings will apply");
		/* Fall through to copy the OOBE parts via the OEM Panther path */
		snprintf(dir_path, sizeof(dir_path),
		         "%s/sources/$OEM$/$$/Panther", s_mount_path);
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
	} else {
		/* OOBE-only: copy to <mount>/sources/$OEM$/$$/Panther/unattend.xml */
		snprintf(dir_path, sizeof(dir_path),
		         "%s/sources/$OEM$/$$/Panther", s_mount_path);
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
	}

	return TRUE;
}
