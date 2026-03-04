/*
 * Rufus: The Reliable USB Formatting Utility
 * Windows User Experience — common (portable) implementation
 * Copyright © 2022-2025 Pete Batard <pete@akeo.ie>
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

/*
 * src/common/wue.c — Portable WUE functions.
 *
 * Provides:
 *   CreateUnattendXml()        — generate autounattend.xml answer file
 *   wue_compute_option_flags() — calculate UNATTEND_* flag bitmask
 *
 * Platform differences handled via #ifdef _WIN32:
 *   - Timezone lookup: Windows uses GetTimeZoneInformation + wchar_to_utf8;
 *     Linux uses IanaToWindowsTimezone() from linux/timezone.c.
 *   - Locale duplication (UNATTEND_OOBE_INTERNATIONAL_MASK): Windows reads
 *     from registry and Windows locale APIs; Linux uses GetLinuxOobeLocale()
 *     from linux/locale_oobe.c (reads $LANG / keyboard layout detection).
 *
 * Temp file creation uses GetTempFileNameU on both platforms; on Linux this
 * aliases to GetTempFileNameA (POSIX mkstemp-based, defined in compat/windows.h).
 * temp_dir is initialised by rufus_init_paths() on Linux (respects $TMPDIR).
 */

#ifdef _WIN32
#include <windows.h>
#include <windowsx.h>
#include "registry.h"
#else
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include "oobe_locale.h"
#include "timezone_name.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "rufus.h"
#include "localization.h"
#include "missing.h"
#include "resource.h"
#include "wue.h"

/* bypass registry key names */
extern const char* bypass_name[];

/*
 * CreateUnattendXml — generate an installation answer file containing the
 * sections specified by @flags.
 *
 * @arch:  processor architecture of the Windows image (ARCH_X86_32 … ARCH_ARM_64)
 * @flags: bitmask of UNATTEND_* constants from rufus.h
 * Returns: path to a newly created temp file, or NULL on error.
 */
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

	/* coverity[swapped_arguments] */
	if (GetTempFileNameU(temp_dir, APPLICATION_NAME, 0, path) == 0)
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
		/* WinPE requires a product key element (any key, even empty) */
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
				const char* wintz = GetLocalTimezone();
				uprintf("• Timezone: %s", wintz);
				fprintf(fd, "      <TimeZone>%s</TimeZone>\n", wintz);
			}
			if (flags & UNATTEND_SET_USER) {
				int allowed = 1;
				for (i = 0; i < ARRAYSIZE(unallowed_account_names); i++) {
					if (_stricmp(unattend_username, unallowed_account_names[i]) == 0) {
						allowed = 0;
						break;
					}
				}
				if (!allowed) {
					uprintf("WARNING: '%s' is not allowed as local account name - Option ignored",
						unattend_username);
				} else if (unattend_username[0] != 0) {
					char* org_username = safe_strdup(unattend_username);
					/* per MS docs, also disallow dots and other special chars */
					filter_chars(unattend_username, "/\\[]:|<>+=;,?*%@.", '_');
					if (org_username && strcmp(org_username, unattend_username) != 0)
						uprintf("WARNING: Local account name contained unallowed characters and has been sanitized");
					free(org_username);
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
		if (flags & UNATTEND_OOBE_INTERNATIONAL_MASK) {
			OobeLocale lol = { 0 };
			GetOobeLocale(&lol);
			uprintf("• Use the same regional options as this user's");
			fprintf(fd,
				"    <component name=\"Microsoft-Windows-International-Core\""
				" processorArchitecture=\"%s\" language=\"neutral\""
				" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\""
				" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
				" publicKeyToken=\"31bf3856ad364e35\" versionScope=\"nonSxS\">\n",
				xml_arch_names[arch]);
			fprintf(fd, "      <InputLocale>%s</InputLocale>\n",    lol.input_locale);
			fprintf(fd, "      <SystemLocale>%s</SystemLocale>\n",  lol.system_locale);
			fprintf(fd, "      <UserLocale>%s</UserLocale>\n",      lol.user_locale);
			fprintf(fd, "      <UILanguage>%s</UILanguage>\n",      lol.ui_locale);
			fprintf(fd, "      <UILanguageFallback>%s</UILanguageFallback>\n", lol.ui_fallback);
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

/*
 * wue_compute_option_flags — return the default UNATTEND_* flag bitmask for
 * the WUE dialog, based on the image report and current UI state.
 * Pure logic: no UI or platform-specific dependencies.
 */
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
