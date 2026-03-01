/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux settings — INI file-based persistence (no registry)
 * Copyright © 2015-2025 Pete Batard <pete@akeo.ie>
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
 * Linux replacement for src/windows/settings.h.
 *
 * On Linux there is no Windows Registry.  All settings are stored in an INI
 * file (ini_file, default: ~/.config/rufus/rufus.ini).  The API is identical
 * to the Windows version so the shared business-logic code can be compiled
 * unchanged on both platforms.
 *
 * ReadSetting*  — return default (0 / FALSE / "") when ini_file is NULL or
 *                 the key is absent.
 * WriteSetting* — return FALSE when ini_file is NULL.
 */

#pragma once

#include <stdint.h>
#include <inttypes.h>
#include "rufus.h"
#include "missing.h"

/* ini_file is declared in globals.c and set to the path of the INI file
 * during startup.  When NULL every read returns its default value and every
 * write is a no-op that returns FALSE. */
extern char* ini_file;

/*
 * Setting name constants — identical to the Windows version so that
 * the shared rufus.c / format.c / … code sees the same string literals.
 */
#define SETTING_ADVANCED_MODE               "AdvancedMode"
#define SETTING_ADVANCED_MODE_DEVICE        "ShowAdvancedDriveProperties"
#define SETTING_ADVANCED_MODE_FORMAT        "ShowAdvancedFormatOptions"
#define SETTING_COMM_CHECK                  "CommCheck64"
#define SETTING_DEFAULT_THREAD_PRIORITY     "DefaultThreadPriority"
#define SETTING_DARK_MODE                   "DarkMode"
#define SETTING_DISABLE_FAKE_DRIVES_CHECK   "DisableFakeDrivesCheck"
#define SETTING_DISABLE_LGP                 "DisableLGP"
#define SETTING_DISABLE_RUFUS_MBR           "DisableRufusMBR"
#define SETTING_DISABLE_SECURE_BOOT_NOTICE  "DisableSecureBootNotice"
#define SETTING_DISABLE_VHDS                "DisableVHDs"
#define SETTING_ENABLE_EXTRA_HASHES         "EnableExtraHashes"
#define SETTING_ENABLE_FILE_INDEXING        "EnableFileIndexing"
#define SETTING_ENABLE_RUNTIME_VALIDATION   "EnableRuntimeValidation"
#define SETTING_ENABLE_USB_DEBUG            "EnableUsbDebug"
#define SETTING_ENABLE_VMDK_DETECTION       "EnableVmdkDetection"
#define SETTING_ENABLE_WIN_DUAL_EFI_BIOS    "EnableWindowsDualUefiBiosMode"
#define SETTING_EXPERT_MODE                 "ExpertMode"
#define SETTING_FORCE_LARGE_FAT32_FORMAT    "ForceLargeFat32Formatting"
#define SETTING_IGNORE_BOOT_MARKER          "IgnoreBootMarker"
#define SETTING_INCLUDE_BETAS               "CheckForBetas"
#define SETTING_LAST_UPDATE                 "LastUpdateCheck"
#define SETTING_LOCALE                      "Locale"
#define SETTING_UPDATE_INTERVAL             "UpdateCheckInterval"
#define SETTING_USE_EXT_VERSION             "UseExtVersion"
#define SETTING_USE_PROPER_SIZE_UNITS       "UseProperSizeUnits"
#define SETTING_USE_UDF_VERSION             "UseUdfVersion"
#define SETTING_USE_VDS                     "UseVds"
#define SETTING_PERSISTENT_LOG              "PersistentLog"
#define SETTING_PREFERRED_SAVE_IMAGE_TYPE   "PreferredSaveImageType"
#define SETTING_PRESERVE_TIMESTAMPS         "PreserveTimestamps"
#define SETTING_VERBOSE_UPDATES             "VerboseUpdateCheck"
#define SETTING_WUE_OPTIONS                 "WindowsUserExperienceOptions"
#define SETTING_FIDO_URL                    "FidoScriptUrl"

/* ---- CheckIniKey ---- */
static __inline BOOL CheckIniKey(const char* key) {
	char* str;
	BOOL ret;
	if (ini_file == NULL) return FALSE;
	str = get_token_data_file(key, ini_file);
	ret = (str != NULL);
	safe_free(str);
	return ret;
}
#define CheckIniKey64   CheckIniKey
#define CheckIniKey32   CheckIniKey
#define CheckIniKeyBool CheckIniKey
#define CheckIniKeyStr  CheckIniKey

/* ---- ReadIniKey* ---- */
static __inline int64_t ReadIniKey64(const char* key) {
	int64_t val = 0;
	char* str;
	if (ini_file == NULL) return 0;
	str = get_token_data_file(key, ini_file);
	if (str != NULL) {
		val = (int64_t)strtoll(str, NULL, 0);
		free(str);
	}
	return val;
}

static __inline int32_t ReadIniKey32(const char* key) {
	int32_t val = 0;
	char* str;
	if (ini_file == NULL) return 0;
	str = get_token_data_file(key, ini_file);
	if (str != NULL) {
		val = (int32_t)strtol(str, NULL, 0);
		free(str);
	}
	return val;
}

static __inline char* ReadIniKeyStr(const char* key) {
	static char str[512];
	char* val;
	str[0] = '\0';
	if (ini_file == NULL) return str;
	val = get_token_data_file(key, ini_file);
	if (val != NULL) {
		static_strcpy(str, val);
		free(val);
	}
	return str;
}

#define ReadIniKeyBool(key)  (ReadIniKey32(key) != 0)

/* ---- WriteIniKey* ---- */
static __inline BOOL WriteIniKey64(const char* key, int64_t val) {
	char str[24];
	if (ini_file == NULL) return FALSE;
	snprintf(str, sizeof(str), "%" PRIi64, val);
	return (set_token_data_file(key, str, ini_file) != NULL);
}

static __inline BOOL WriteIniKey32(const char* key, int32_t val) {
	char str[12];
	if (ini_file == NULL) return FALSE;
	snprintf(str, sizeof(str), "%d", val);
	return (set_token_data_file(key, str, ini_file) != NULL);
}

static __inline BOOL WriteIniKeyStr(const char* key, const char* val) {
	if (ini_file == NULL) return FALSE;
	return (set_token_data_file(key, val, ini_file) != NULL);
}

#define WriteIniKeyBool(key, b) WriteIniKey32(key, (b) ? 1 : 0)

/* ---- Public ReadSetting* / WriteSetting* API ----
 *
 * On Linux we always use the INI file — no registry fallback.
 */
#define ReadSetting64(key)       ReadIniKey64(key)
#define WriteSetting64(key, val) WriteIniKey64(key, val)
#define ReadSetting32(key)       ReadIniKey32(key)
#define WriteSetting32(key, val) WriteIniKey32(key, val)
#define ReadSettingBool(key)     ReadIniKeyBool(key)
#define WriteSettingBool(key, b) WriteIniKeyBool(key, b)
#define ReadSettingStr(key)      ReadIniKeyStr(key)
#define WriteSettingStr(key, val) WriteIniKeyStr(key, val)
