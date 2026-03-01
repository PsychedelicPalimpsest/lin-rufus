/*
 * system_info.h – Host hardware detection for the Linux port of Rufus.
 *
 * Provides:
 *   GetTPMVersion()       – returns the major TPM version present on the host
 *                           (0 = none, 1 = TPM 1.x, 2 = TPM 2.0)
 *   IsSecureBootEnabled() – TRUE when UEFI Secure Boot is currently enforcing
 *   IsSetupModeEnabled()  – TRUE when the EFI SetupMode variable indicates that
 *                           Secure Boot keys have not yet been enrolled
 *
 * The real paths used are:
 *   /sys/class/tpm/tpm0/tpm_version_major
 *   /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
 *   /sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c
 *
 * In RUFUS_TEST builds the paths can be redirected to a temporary directory
 * via sysinfo_set_sysfs_root() and sysinfo_set_efi_root() for unit testing
 * without requiring root or real hardware.
 */
#pragma once

#ifndef _WIN32
#include <stdint.h>
#endif

#include "../windows/rufus.h"   /* BOOL */

#ifdef __cplusplus
extern "C" {
#endif

/* Returns 0 when no TPM is present or the version cannot be determined,
 * 1 for a TPM 1.x device, 2 for a TPM 2.0 device. */
int  GetTPMVersion(void);

/* Returns TRUE (non-zero) when UEFI Secure Boot is currently active and
 * enforcing signature verification on loaded EFI images. */
BOOL IsSecureBootEnabled(void);

/* Returns TRUE (non-zero) when the firmware is in EFI Setup Mode, meaning
 * the Secure Boot key databases (PK/KEK/db) are empty and any image can be
 * loaded regardless of the SecureBoot variable value. */
BOOL IsSetupModeEnabled(void);

/* Test-injection API – only available in RUFUS_TEST builds.
 * Redirect the sysfs root (normally "/sys") used by GetTPMVersion() and the
 * EFI variable root (normally "/sys/firmware/efi") used by the SecureBoot /
 * SetupMode readers to arbitrary paths so tests can create fake trees. */
#ifdef RUFUS_TEST
void sysinfo_set_sysfs_root(const char *path);
void sysinfo_set_efi_root(const char *path);
#endif

#ifdef __cplusplus
}
#endif
