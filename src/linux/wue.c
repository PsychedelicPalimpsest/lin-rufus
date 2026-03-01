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

#include "rufus.h"
#include "vhd.h"
#include "xml.h"
#include "wue.h"
#include "wimlib.h"

/* bypass registry key names (same as Windows) */
const char* bypass_name[] = { "BypassTPMCheck", "BypassSecureBootCheck", "BypassRAMCheck" };

int  unattend_xml_flags = 0, wintogo_index = -1, wininst_index = 0;
int  unattend_xml_mask  = UNATTEND_DEFAULT_SELECTION_MASK;
char *unattend_xml_path = NULL, unattend_username[MAX_USERNAME_LENGTH];
BOOL is_bootloader_revoked = FALSE;

/* -----------------------------------------------------------------------
 * CreateUnattendXml
 *   Generate an autounattend.xml answer file.
 *   Timezone section is skipped on Linux (no GetTimeZoneInformation).
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
			/* UNATTEND_DUPLICATE_LOCALE: timezone section skipped on Linux */
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
		assert(safe_strlen(image_path) + safe_strlen(&img_report.wininst_path[0][3]) + 1
			< ARRAYSIZE(wim_path));
		static_strcat(wim_path, "|");
		static_strcat(wim_path, &img_report.wininst_path[0][3]);
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
BOOL SetupWinPE(char drive_letter)
{
	(void)drive_letter;
	return FALSE;
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

BOOL ApplyWindowsCustomization(char drive_letter, int flags)
{
	(void)drive_letter; (void)flags;
	return FALSE;
}
