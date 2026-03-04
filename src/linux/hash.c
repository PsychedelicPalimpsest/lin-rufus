/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: hash.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>

#include "rufus.h"
#include "resource.h"
#include "missing.h"

/* Globals provided by globals.c — must be visible to hash_algos.c (included below) */
extern BOOL cpu_has_sha1_accel, cpu_has_sha256_accel;
extern BOOL validate_md5sum;
extern char *sbat_level_txt, *sb_active_txt, *sb_revoked_txt;
extern BOOL expert_mode;

/*
 * Include the portable algorithm implementations (MD5, SHA1, SHA256, SHA512),
 * the hash_init / hash_write / hash_final function-pointer tables, and HashBuffer().
 */
#include "../../common/hash_algos.c"

/*
 * Linux-specific HashFile: read a file and hash it using the portable algorithm.
 */
BOOL HashFile(const unsigned type, const char* path, uint8_t* hash)
{
	BOOL r = FALSE;
	HASH_CONTEXT hash_ctx = { {0} };
	int fd = -1;
	ssize_t nr;
	uint8_t buf[4096];

	if ((type >= HASH_MAX) || (path == NULL) || (hash == NULL))
		goto out;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto out;

	hash_init[type](&hash_ctx);
	while ((nr = read(fd, buf, sizeof(buf))) > 0)
		hash_write[type](&hash_ctx, buf, (size_t)nr);

	if (nr < 0)
		goto out;   /* read error */

	hash_final[type](&hash_ctx);
	memcpy(hash, hash_ctx.buf, hash_count[type]);
	r = TRUE;

out:
	if (fd >= 0)
		close(fd);
	return r;
}

/* ---- DB lookup helpers: StringToHash, IsBufferInDB/IsFileInDB, BufferMatchesHash ---- */
#include "../windows/db.h"
#include "efi.h"

/* Externs from iso.c / rufus.c / net.c */
extern const char* efi_archname[];
extern enum ArchType MachineToArch(WORD machine);
extern BOOL UseLocalDbx(int arch);

#include "../../common/hash_db.c"

/* ---- Secure Boot helper: check if PE hash matches any entry in a DBX binary ---- */
static BOOL IsRevokedByDbx(uint8_t* hash, uint8_t* buf, uint32_t len)
{
	EFI_VARIABLE_AUTHENTICATION_2* efi_var_auth;
	EFI_SIGNATURE_LIST* efi_sig_list;
	uint8_t* dbx_data = NULL;
	BOOL ret = FALSE, needs_free = FALSE;
	uint32_t dbx_size = 0;
	char dbx_name[32], path[MAX_PATH];
	uint32_t i, fluff_size, nb_entries;

	i = (uint32_t)MachineToArch(GetPeArch(buf, len));
	if (i == ARCH_UNKNOWN)
		goto out;

	/* Check if a locally cached DBX should be used */
	snprintf(dbx_name, sizeof(dbx_name), "dbx_%s.bin", efi_archname[i]);
	if (UseLocalDbx((int)i)) {
		snprintf(path, sizeof(path), "%s/" FILES_DIR "/%s", app_data_dir, dbx_name);
		dbx_size = read_file(path, &dbx_data);
		needs_free = (dbx_data != NULL);
	}

	/* Also try system EFI variable as a fallback */
	if (dbx_size == 0) {
		/* On EFI systems the DBX may be in /sys/firmware/efi/efivars/
		 * The variable name is: dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f */
		const char* efivar_prefix =
			"/sys/firmware/efi/efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f";
		dbx_size = read_file(efivar_prefix, &dbx_data);
		if (dbx_size > 4) {
			/* EFI variable files have a 4-byte attribute header; skip it */
			memmove(dbx_data, dbx_data + 4, dbx_size - 4);
			dbx_size -= 4;
			needs_free = TRUE;
		} else {
			free(dbx_data);
			dbx_data = NULL;
			dbx_size = 0;
		}
	}

	if (dbx_data == NULL || dbx_size <= sizeof(EFI_VARIABLE_AUTHENTICATION_2))
		goto out;

	efi_var_auth = (EFI_VARIABLE_AUTHENTICATION_2*)dbx_data;
	fluff_size = efi_var_auth->AuthInfo.Hdr.dwLength + sizeof(EFI_TIME);
	if (dbx_size <= fluff_size)
		goto out;
	efi_sig_list = (EFI_SIGNATURE_LIST*)&dbx_data[fluff_size];
	fluff_size += sizeof(EFI_SIGNATURE_LIST);
	if (dbx_size <= fluff_size)
		goto out;
	/* Expect SHA-256 hashes */
	if (!CompareGUID(&efi_sig_list->SignatureType, &EFI_CERT_SHA256_GUID)) {
		uprintf("  Warning: %s is not using SHA-256 hashes - Cannot check for UEFI revocation!", dbx_name);
		goto out;
	}
	fluff_size += efi_sig_list->SignatureHeaderSize;
	assert(efi_sig_list->SignatureSize != 0);
	nb_entries = (efi_sig_list->SignatureListSize - efi_sig_list->SignatureHeaderSize
	              - sizeof(EFI_SIGNATURE_LIST)) / efi_sig_list->SignatureSize;
	assert(dbx_size >= fluff_size + nb_entries * efi_sig_list->SignatureSize);

	fluff_size += sizeof(GUID);
	for (i = 0; i < nb_entries && !ret; i++) {
		if (memcmp(hash, &dbx_data[fluff_size + i * efi_sig_list->SignatureSize], SHA256_HASHSIZE) == 0)
			ret = TRUE;
	}

out:
	if (needs_free)
		free(dbx_data);
	return ret;
}

/* ---- Secure Boot helper: check if PE SBAT section has too-old versions ---- */
static BOOL IsRevokedBySbat(uint8_t* buf, uint32_t len)
{
	char* sbat = NULL, *version_str;
	uint32_t i, j, sbat_len;
	sbat_entry_t entry;

	/* Fall back to embedded sbat_level.txt if remote hasn't been fetched */
	if (sbat_entries == NULL) {
		sbat_level_txt = safe_strdup(db_sbat_level_txt);
		sbat_entries = GetSbatEntries(sbat_level_txt);
	}
	assert(sbat_entries != NULL);
	if (sbat_entries == NULL)
		return FALSE;

	sbat = (char*)GetPeSection(buf, len, ".sbat", &sbat_len);
	if (sbat == NULL || sbat < (char*)buf || sbat >= (char*)buf + len)
		return FALSE;

	for (i = 0; sbat[i] != '\0'; ) {
		while (sbat[i] == '\n')
			i++;
		if (sbat[i] == '\0')
			break;
		entry.product = &sbat[i];
		for (; sbat[i] != ',' && sbat[i] != '\0' && sbat[i] != '\n'; i++);
		if (sbat[i] == '\0' || sbat[i] == '\n')
			break;
		sbat[i++] = '\0';
		version_str = &sbat[i];
		for (; sbat[i] != ',' && sbat[i] != '\0' && sbat[i] != '\n'; i++);
		sbat[i++] = '\0';
		entry.version = atoi(version_str);
		uuprintf("  SBAT: %s,%d", entry.product, entry.version);
		for (; sbat[i] != '\0' && sbat[i] != '\n'; i++);
		if (entry.version == 0)
			continue;
		for (j = 0; sbat_entries[j].product != NULL; j++) {
			if (strcmp(entry.product, sbat_entries[j].product) == 0
			    && entry.version < sbat_entries[j].version) {
				uprintf("  SBAT version for '%s' (%d) is lower than the current minimum SBAT version (%d)!",
				        entry.product, entry.version, sbat_entries[j].version);
				return TRUE;
			}
		}
	}

	return FALSE;
}

/* ---- Secure Boot helper: check if PE SVN resource is below minimum ---- */

/*
 * Convert a NUL-terminated UTF-8 string to a NUL-terminated UTF-16LE array
 * stored in 'dst' (allocated by caller, max_units includes the NUL).
 * Only handles BMP characters (U+0000..U+FFFF) — sufficient for product names.
 * Returns the number of UTF-16 code units written (excluding NUL), or -1 on error.
 */
static int utf8_to_utf16le(const char *src, uint16_t *dst, size_t max_units)
{
	size_t out = 0;
	const uint8_t *s = (const uint8_t *)src;
	while (*s && out < max_units - 1) {
		uint32_t c;
		if      (s[0] < 0x80)                            { c  = s[0];              s += 1; }
		else if ((s[0] & 0xE0) == 0xC0 && (s[1] & 0xC0) == 0x80) { c  = ((s[0] & 0x1F) << 6) | (s[1] & 0x3F); s += 2; }
		else if ((s[0] & 0xF0) == 0xE0 && (s[1] & 0xC0) == 0x80 && (s[2] & 0xC0) == 0x80) {
			c = ((s[0] & 0x0F) << 12) | ((s[1] & 0x3F) << 6) | (s[2] & 0x3F);
			s += 3;
		} else {
			return -1;  /* unsupported or invalid encoding */
		}
		if (c > 0xFFFF)
			return -1;  /* surrogate pairs not handled */
		dst[out++] = (uint16_t)c;
	}
	dst[out] = 0;
	return (int)out;
}

/*
 * Non-static when RUFUS_TEST is defined so tests can call it directly.
 */
#ifdef RUFUS_TEST
BOOL IsRevokedBySvn(uint8_t* buf, uint32_t len)
#else
static BOOL IsRevokedBySvn(uint8_t* buf, uint32_t len)
#endif
{
	uint32_t i, rsrc_rva, rsrc_len;
	uint16_t rsrc_name[64];
	uint8_t *root;
	uint32_t *svn_ver;
	IMAGE_DOS_HEADER *dos_header;
	IMAGE_NT_HEADERS32 *pe_header;
	IMAGE_NT_HEADERS64 *pe64_header;
	IMAGE_DATA_DIRECTORY img_data_dir;

	if (sbat_entries == NULL)
		return FALSE;
	if (buf == NULL || len < 0x100)
		return FALSE;

	dos_header = (IMAGE_DOS_HEADER *)buf;
	if ((uint32_t)dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > len)
		return FALSE;
	pe_header  = (IMAGE_NT_HEADERS32 *)&buf[dos_header->e_lfanew];

	for (i = 0; sbat_entries[i].product != NULL; i++) {
		size_t j;
		/* SVN entries are expected to be uppercase */
		for (j = 0; sbat_entries[i].product[j] != '\0'; j++) {
			if (!isupper((unsigned char)sbat_entries[i].product[j]))
				break;
		}
		if (sbat_entries[i].product[j] != '\0')
			continue;  /* not all uppercase — skip */

		/* Convert product name to UTF-16LE for PE resource lookup */
		if (utf8_to_utf16le(sbat_entries[i].product, rsrc_name, sizeof(rsrc_name) / sizeof(rsrc_name[0])) < 0)
			continue;

		if (pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 ||
		    pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM) {
			img_data_dir = pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
		} else {
			pe64_header = (IMAGE_NT_HEADERS64 *)pe_header;
			img_data_dir = pe64_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
		}

		if (img_data_dir.VirtualAddress == 0 || img_data_dir.Size == 0)
			continue;

		root = RvaToPhysical(buf, len, img_data_dir.VirtualAddress);
		if (root == NULL)
			continue;

		rsrc_rva = FindResourceRva(rsrc_name, root, root + img_data_dir.Size, root, &rsrc_len);
		if (rsrc_rva == 0)
			continue;

		if (rsrc_len == sizeof(uint32_t)) {
			svn_ver = (uint32_t *)RvaToPhysical(buf, len, rsrc_rva);
			if (svn_ver != NULL) {
				uuprintf("  SVN version: %d.%d", *svn_ver >> 16, *svn_ver & 0xffff);
				if (*svn_ver < sbat_entries[i].version) {
					uprintf("  SVN version %d.%d is lower than required minimum SVN version %d.%d!",
						*svn_ver >> 16, *svn_ver & 0xffff,
						sbat_entries[i].version >> 16, sbat_entries[i].version & 0xffff);
					return TRUE;
				}
			}
		} else {
			uprintf("  Warning: Unexpected Secure Version Number size");
		}
	}
	return FALSE;
}

/* ---- Secure Boot helper: check if issuer cert is in revoked thumbprint list ---- */
static BOOL IsRevokedByCert(cert_info_t* info)
{
	uint32_t i;

	if (!expert_mode)
		return FALSE;

	/* Fall back to embedded revoked cert thumbprints if remote hasn't been fetched */
	if (sb_revoked_certs == NULL) {
		sb_revoked_txt = safe_strdup(db_sb_revoked_txt);
		sb_revoked_certs = GetThumbprintEntries(sb_revoked_txt);
	}
	assert(sb_revoked_certs != NULL && sb_revoked_certs->count != 0);
	if (sb_revoked_certs == NULL)
		return FALSE;

	for (i = 0; i < sb_revoked_certs->count; i++) {
		if (memcmp(info->thumbprint, sb_revoked_certs->list[i], SHA1_HASHSIZE) == 0) {
			uuprintf("  Found '%s' revoked certificate", info->name);
			return TRUE;
		}
	}
	return FALSE;
}

BOOL IsSignedBySecureBootAuthority(uint8_t* buf, uint32_t len)
{
	uint32_t i;
	uint8_t* cert;
	cert_info_t info;

	if (buf == NULL || len < 0x100)
		return FALSE;

	/* Get the signer/issuer info */
	cert = GetPeSignatureData(buf, len);
	/* Secure Boot Authority is always an issuer */
	if (GetIssuerCertificateInfo(cert, &info) != 2)
		return FALSE;

	/* Fall back to embedded Secure Boot thumbprints if remote hasn't been fetched */
	if (sb_active_certs == NULL) {
		sb_active_txt = safe_strdup(db_sb_active_txt);
		sb_active_certs = GetThumbprintEntries(sb_active_txt);
	}
	assert(sb_active_certs != NULL && sb_active_certs->count != 0);
	if (sb_active_certs == NULL || sb_active_certs->count == 0)
		return FALSE;

	for (i = 0; i < sb_active_certs->count; i++) {
		if (memcmp(info.thumbprint, sb_active_certs->list[i], SHA1_HASHSIZE) == 0)
			return TRUE;
	}
	return FALSE;
}

int IsBootloaderRevoked(uint8_t* buf, uint32_t len)
{
	uint32_t i;
	uint8_t hash[SHA256_HASHSIZE];
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)buf;
	IMAGE_NT_HEADERS32* pe_header;
	uint8_t* cert;
	cert_info_t info;
	int r, revoked = 0;

	if (buf == NULL || len < 0x100 || dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return -2;
	if ((uint32_t)dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > len)
		return -2;
	pe_header = (IMAGE_NT_HEADERS32*)&buf[dos_header->e_lfanew];
	if (pe_header->Signature != IMAGE_NT_SIGNATURE)
		return -2;

	/* Get the signer/issuer info */
	cert = GetPeSignatureData(buf, len);
	r = GetIssuerCertificateInfo(cert, &info);
	if (r == 0) {
		uprintf("  (Unsigned Bootloader)");
	} else if (r > 0) {
		uprintf("  Signed by '%s'", info.name);
		/* Only perform revocation checks on signed bootloaders */
		if (!PE256Buffer(buf, len, hash))
			return -1;
		/* Check for UEFI DBX revocation */
		if (IsRevokedByDbx(hash, buf, len))
			revoked = 1;
		/* Check for Microsoft SSP revocation */
		for (i = 0; revoked == 0 && i < pe256ssp_size * SHA256_HASHSIZE; i += SHA256_HASHSIZE)
			if (memcmp(hash, &pe256ssp[i], SHA256_HASHSIZE) == 0)
				revoked = 2;
		/* Check for Linux SBAT revocation */
		if (revoked == 0 && IsRevokedBySbat(buf, len))
			revoked = 3;
		/* Check for Microsoft SVN revocation */
		if (revoked == 0 && IsRevokedBySvn(buf, len))
			revoked = 4;
		/* Check for UEFI DBX certificate revocation */
		if (revoked == 0 && IsRevokedByCert(&info))
			revoked = 5;

		/* If signed and not revoked, print Secure Boot notes */
		if (revoked == 0) {
			if (strcmp(info.name, "Microsoft Windows Production PCA 2011") == 0) {
				uprintf("  Note: This bootloader may fail Secure Boot validation on systems that");
				uprintf("  have been updated to use the 'Windows UEFI CA 2023' certificate.");
			} else if (strcmp(info.name, "Windows UEFI CA 2023") == 0) {
				uprintf("  Note: This bootloader will fail Secure Boot validation on systems that");
				uprintf("  have not been updated to use the latest Secure Boot certificates");
			} else if (strcmp(info.name, "Microsoft Corporation UEFI CA 2011") == 0 ||
			           strcmp(info.name, "Microsoft UEFI CA 2023") == 0) {
				uprintf("  Note: This bootloader may fail Secure Boot validation on *some* systems,");
				uprintf("  unless you enable \"Microsoft 3rd-party UEFI CA\" in your 'BIOS'.");
			}
		}
	}

	return revoked;
}
void UpdateMD5Sum(const char* dest_dir, const char* md5sum_name)
{
    if (!img_report.has_md5sum && !validate_md5sum)
        return;

    char md5_path[MAX_PATH];
    snprintf(md5_path, sizeof(md5_path), "%s/%s", dest_dir, md5sum_name);

    char *md5_data = NULL;
    uint32_t md5_size = read_file(md5_path, (uint8_t **)&md5_data);
    if (md5_size == 0)
        return;

    BOOL display_header = TRUE;

    /* Update MD5 entries for each modified file */
    for (uint32_t i = 0; i < modified_files.Index; i++) {
        char *file_path = modified_files.String[i];

        /* Convert all backslashes to forward slashes (Windows compat) */
        for (size_t j = 0; j < strlen(file_path); j++)
            if (file_path[j] == '\\')
                file_path[j] = '/';

        /* Find the basename portion starting after the mount point
         * (strip leading dest_dir prefix, then one path separator) */
        const char *rel = file_path;
        if (strncmp(file_path, dest_dir, strlen(dest_dir)) == 0)
            rel = file_path + strlen(dest_dir) + 1; /* skip dest_dir + '/' */

        /* Look for this relative path in the md5sum file */
        char *str_pos = strstr(md5_data, rel);
        if (str_pos == NULL)
            continue;  /* file not listed */

        if (display_header) {
            uprintf("Updating %s:", md5_path);
            display_header = FALSE;
        }
        uprintf("● %s", rel);

        /* Walk back to start of this line */
        intptr_t pos = str_pos - md5_data;
        while (pos > 0 && md5_data[pos - 1] != '\n')
            pos--;

        /* Recompute MD5 and patch the hex string in-place */
        uint8_t sum[MD5_HASHSIZE];
        HashFile(HASH_MD5, file_path, sum);
        for (uint32_t j = 0; j < MD5_HASHSIZE; j++) {
            static const char hx[] = "0123456789abcdef";
            md5_data[pos + 2*j]     = hx[sum[j] >> 4];
            md5_data[pos + 2*j + 1] = hx[sum[j] & 0x0F];
        }
    }

    write_file(md5_path, (const uint8_t *)md5_data, md5_size);
    free(md5_data);
}

/* ---- PE image region collection and PE256 hash ---- */
#include "../../common/hash_pe.c"
INT_PTR CALLBACK HashCallback(HWND h, UINT msg, WPARAM w, LPARAM lp)
                                                                   { (void)h; (void)msg; (void)w; (void)lp; return 0; }

/* ---- Parallel hashing infrastructure ---- */

/*
 * NUM_BUFFERS: double-buffer for reading while hashing.  We mirror the
 * Windows implementation (3 buffers) so the same producer/consumer
 * synchronisation logic can be used unchanged.
 */
#define NUM_BUFFERS  3

/* Per-type synchronisation events (auto-reset, initially unsignalled) */
static HANDLE data_ready[HASH_MAX];
static HANDLE thread_ready[HASH_MAX];

/* Shared read-buffer pool */
static DWORD    read_size[NUM_BUFFERS];
static uint32_t proc_bufnum;
static uint8_t  ht_buffer[NUM_BUFFERS][BUFFER_SIZE];

/* Globals provided by globals.c (or the test glue) */
extern char  hash_str[HASH_MAX][150];
extern BOOL  enable_extra_hashes;
extern HWND  hMainDialog;
extern int   default_thread_priority;

/*
 * IndividualHashThread — computes one hash algorithm in a worker thread.
 *
 * param: (uint32_t)(uintptr_t) hash-type index (HASH_MD5 … HASH_SHA512)
 *
 * Protocol (mirrors Windows implementation):
 *   1. Initialise hash context, signal thread_ready[i].
 *   2. Loop: wait on data_ready[i].
 *      • read_size[proc_bufnum] != 0 → hash the chunk, signal thread_ready[i].
 *      • read_size[proc_bufnum] == 0 → finalise, format hash_str[i], return 0.
 */
DWORD WINAPI IndividualHashThread(void* param)
{
	HASH_CONTEXT hash_ctx = { {0} };
	uint32_t i = (uint32_t)(uintptr_t)param, j;

	hash_init[i](&hash_ctx);

	if (!SetEvent(thread_ready[i]))
		goto error;

	while (1) {
		if (WaitForSingleObject(data_ready[i], WAIT_TIME) != WAIT_OBJECT_0) {
			uprintf("Hash thread #%d: timed out waiting for data", i);
			return 1;
		}

		if (read_size[proc_bufnum] != 0) {
			hash_write[i](&hash_ctx, ht_buffer[proc_bufnum],
			              (size_t)read_size[proc_bufnum]);
			if (!SetEvent(thread_ready[i]))
				goto error;
		} else {
			/* read_size == 0 → EOF: finalise and format the hex string */
			hash_final[i](&hash_ctx);
			memset(&hash_str[i], 0, sizeof(hash_str[i]));
			for (j = 0; j < hash_count[i]; j++) {
				hash_str[i][2 * j] = ((hash_ctx.buf[j] >> 4) < 10) ?
					((hash_ctx.buf[j] >> 4) + '0') :
					((hash_ctx.buf[j] >> 4) - 0xa + 'a');
				hash_str[i][2 * j + 1] = ((hash_ctx.buf[j] & 15) < 10) ?
					((hash_ctx.buf[j] & 15) + '0') :
					((hash_ctx.buf[j] & 15) - 0xa + 'a');
			}
			hash_str[i][2 * j] = '\0';
			return 0;
		}
	}
error:
	uprintf("Hash thread #%d: failed to signal event", i);
	return 1;
}

/*
 * HashThread — reads image_path and fans out to IndividualHashThread workers.
 *
 * param: DWORD_PTR* thread_affinity — array of HASH_MAX+1 CPU affinity masks.
 *   Pass NULL or an all-zeros array to skip CPU affinity (Linux default).
 *
 * On success: hash_str[0..2] (and [3] if enable_extra_hashes) contain hex
 *   digest strings; a hash-display dialog is invoked.
 * On failure: ErrorStatus set, thread exits with code 1.
 */
DWORD WINAPI HashThread(void* param)
{
	DWORD_PTR* thread_affinity = (DWORD_PTR*)param;
	HANDLE hash_thread[HASH_MAX] = { NULL, NULL, NULL, NULL };
	DWORD wr;
	int fd = -1;
	int read_bufnum, i, r = -1;
	int num_hashes = HASH_MAX - (enable_extra_hashes ? 0 : 1);
	uint64_t processed_bytes = 0;

	if (image_path == NULL)
		ExitThread(1);

	/*
	 * Thread affinity is optional on Linux: ignore NULL or all-zero arrays.
	 */
	if (thread_affinity != NULL && thread_affinity[0] != 0)
		SetThreadAffinityMask(GetCurrentThread(), thread_affinity[0]);

	uprintf("\r\nComputing hash for '%s'...", image_path);

	/* Create synchronisation events and spawn one hash-worker per algorithm */
	for (i = 0; i < num_hashes; i++) {
		data_ready[i]   = CreateEvent(NULL, FALSE, FALSE, NULL);
		thread_ready[i] = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (data_ready[i] == NULL || thread_ready[i] == NULL) {
			uprintf("HashThread: unable to create event for hash #%d", i);
			goto out;
		}
		hash_thread[i] = CreateThread(NULL, 0, IndividualHashThread,
		                              (LPVOID)(uintptr_t)i, 0, NULL);
		if (hash_thread[i] == NULL) {
			uprintf("HashThread: unable to start hash thread #%d", i);
			goto out;
		}
		SetThreadPriority(hash_thread[i], default_thread_priority);
		if (thread_affinity != NULL && thread_affinity[i + 1] != 0)
			SetThreadAffinityMask(hash_thread[i], thread_affinity[i + 1]);
	}

	/* Open the image file */
	fd = open(image_path, O_RDONLY);
	if (fd < 0) {
		uprintf_errno("HashThread: could not open '%s'", image_path);
		ErrorStatus = RUFUS_ERROR(ERROR_OPEN_FAILED);
		goto out;
	}

	read_bufnum = 0;
	proc_bufnum = 1;
	read_size[proc_bufnum] = 1;   /* sentinel: prevent early loop exit */

	UpdateProgressWithInfoInit(hMainDialog, FALSE);

	/*
	 * Double-buffered read loop: read chunk into read_bufnum while
	 * workers process proc_bufnum.
	 */
	do {
		UpdateProgressWithInfo(OP_NOOP_WITH_TASKBAR, MSG_271,
		                       processed_bytes, img_report.image_size);
		CHECK_FOR_USER_CANCEL;

		/* Fill read buffer */
		ssize_t nr = read(fd, ht_buffer[read_bufnum], BUFFER_SIZE);
		if (nr < 0) {
			uprintf("HashThread: read error on '%s': %s",
			        image_path, strerror(errno));
			ErrorStatus = RUFUS_ERROR(ERROR_READ_FAULT);
			goto out;
		}
		read_size[read_bufnum] = (DWORD)nr;

		/* Rotate read-buffer index */
		read_bufnum = (read_bufnum + 1) % NUM_BUFFERS;

		/* Wait for all workers to finish the previous chunk */
		wr = WaitForMultipleObjects(num_hashes, thread_ready, TRUE, WAIT_TIME);
		if (wr != WAIT_OBJECT_0) {
			uprintf("HashThread: workers did not signal ready in time");
			goto out;
		}

		/* Expose the freshly-read chunk to workers */
		proc_bufnum = (read_bufnum + NUM_BUFFERS - 1) % NUM_BUFFERS;

		/* Wake all workers */
		for (i = 0; i < num_hashes; i++) {
			if (!SetEvent(data_ready[i])) {
				uprintf("HashThread: could not signal hash thread #%d", i);
				goto out;
			}
		}

		processed_bytes += read_size[proc_bufnum];
	} while (read_size[proc_bufnum] != 0);

	/* All chunks dispatched; wait for workers to write hash_str[] */
	if (WaitForMultipleObjects(num_hashes, hash_thread, TRUE, WAIT_TIME)
	    != WAIT_OBJECT_0) {
		uprintf("HashThread: workers did not finalize");
		goto out;
	}

	uprintf("  MD5:    %s", hash_str[HASH_MD5]);
	uprintf("  SHA1:   %s", hash_str[HASH_SHA1]);
	uprintf("  SHA256: %s", hash_str[HASH_SHA256]);
	if (enable_extra_hashes)
		uprintf("  SHA512: %s", hash_str[HASH_SHA512]);

	r = 0;

out:
	for (i = 0; i < num_hashes; i++) {
		if (hash_thread[i] != NULL) {
			TerminateThread(hash_thread[i], 1);
			CloseHandle(hash_thread[i]);
		}
		safe_closehandle(data_ready[i]);
		safe_closehandle(thread_ready[i]);
	}
	if (fd >= 0)
		close(fd);

	PostMessage(hMainDialog, UM_FORMAT_COMPLETED, (WPARAM)FALSE, 0);
	if (r == 0)
		PostMessage(hMainDialog, UM_HASH_COMPLETED, 0, 0);
	ExitThread(r);
}
