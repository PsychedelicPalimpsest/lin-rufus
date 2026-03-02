/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: system_info.c — system information queries
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
 * system_info.c – Host hardware detection for the Linux port of Rufus.
 *
 * Implements:
 *   GetTPMVersion()       – reads /sys/class/tpm/tpm0/tpm_version_major
 *   IsSecureBootEnabled() – reads EFI variable SecureBoot-<GUID>
 *   IsSetupModeEnabled()  – reads EFI variable SetupMode-<GUID>
 *
 * EFI variable files have a 4-byte attributes header before the payload,
 * so the interesting byte for SecureBoot / SetupMode is at offset 4.
 *
 * In RUFUS_TEST builds the paths used can be overridden via
 * sysinfo_set_sysfs_root() / sysinfo_set_efi_root() for unit tests.
 */

#include "system_info.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Tuneable paths                                                       */
/* ------------------------------------------------------------------ */

/* Base of the sysfs tree; normally "/sys" */
static const char *sysfs_root = "/sys";

/* Base of the EFI firmware tree; normally "/sys/firmware/efi" */
static const char *efi_root = "/sys/firmware/efi";

#ifdef RUFUS_TEST
void sysinfo_set_sysfs_root(const char *path)
{
    sysfs_root = path;
}

void sysinfo_set_efi_root(const char *path)
{
    efi_root = path;
}
#endif /* RUFUS_TEST */

/* ------------------------------------------------------------------ */
/* GetTPMVersion                                                        */
/* ------------------------------------------------------------------ */

/*
 * Read /sys/class/tpm/tpm0/tpm_version_major and return the integer
 * value found there.  Returns 0 if the file does not exist, cannot be
 * read, or does not contain a valid positive integer.
 */
int GetTPMVersion(void)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/class/tpm/tpm0/tpm_version_major",
             sysfs_root);

    FILE *f = fopen(path, "r");
    if (!f)
        return 0;

    char buf[32];
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);

    /* Strip trailing whitespace / newline */
    char *end = buf + strlen(buf);
    while (end > buf && (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' '))
        *--end = '\0';

    if (buf[0] == '\0')
        return 0;

    /* Require at least one decimal digit */
    int ver = atoi(buf);
    /* atoi returns 0 for non-numeric strings; treat any non-positive as 0 */
    return (ver > 0) ? ver : 0;
}

/* ------------------------------------------------------------------ */
/* EFI variable reader                                                  */
/* ------------------------------------------------------------------ */

/*
 * Read an EFI variable file from the efivars filesystem.
 *
 * EFI variable files are laid out as:
 *   [0..3]  UINT32 attributes (little-endian, 4 bytes)
 *   [4..]   Variable data
 *
 * For SecureBoot and SetupMode the payload is a single byte.
 *
 * Returns the payload byte value, or -1 on any error.
 */
static int read_efi_byte_var(const char *varname)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/efivars/%s", efi_root, varname);

    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;

    uint8_t buf[5];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    /* Need at least 5 bytes: 4 attribute bytes + 1 data byte */
    if (n < 5)
        return -1;

    return (int)buf[4];
}

/* ------------------------------------------------------------------ */
/* IsSecureBootEnabled                                                  */
/* ------------------------------------------------------------------ */

/* GUID for global EFI variables (SecureBoot, SetupMode, etc.) */
#define EFI_GLOBAL_GUID "8be4df61-93ca-11d2-aa0d-00e098032b8c"

BOOL IsSecureBootEnabled(void)
{
    int val = read_efi_byte_var("SecureBoot-" EFI_GLOBAL_GUID);
    return (val == 1) ? TRUE : FALSE;
}

/* ------------------------------------------------------------------ */
/* IsSetupModeEnabled                                                   */
/* ------------------------------------------------------------------ */

BOOL IsSetupModeEnabled(void)
{
    int val = read_efi_byte_var("SetupMode-" EFI_GLOBAL_GUID);
    return (val == 1) ? TRUE : FALSE;
}
