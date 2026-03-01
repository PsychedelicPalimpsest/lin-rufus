/*
 * download_resume.h — helpers for resumable download support.
 *
 * Provides the .partial file scheme used by DownloadToFileOrBufferEx()
 * to support interrupted-download resume via CURLOPT_RESUME_FROM_LARGE.
 */
#pragma once
#ifdef __linux__

#include <stddef.h>
#include <stdint.h>
#include "compat/windows.h"

/*
 * get_partial_path - Build the ".partial" path for a download target.
 *
 * Appends ".partial" to target_path and writes the result into buf
 * (of bufsz bytes).  Returns buf on success, NULL on NULL input or
 * buffer overflow.
 */
char *get_partial_path(const char *target_path, char *buf, size_t bufsz);

/*
 * has_partial_download - Return TRUE if target_path.partial exists on disk.
 */
BOOL has_partial_download(const char *target_path);

/*
 * get_partial_size - Return the byte size of target_path.partial.
 * Returns 0 if the file does not exist or is empty.
 * The returned value is the offset to pass to CURLOPT_RESUME_FROM_LARGE.
 */
uint64_t get_partial_size(const char *target_path);

/*
 * finalize_partial_download - Rename target_path.partial → target_path.
 * Returns TRUE on success.  Returns FALSE if the .partial file does not
 * exist or the rename fails.
 */
BOOL finalize_partial_download(const char *target_path);

/*
 * abandon_partial_download - Delete target_path.partial.
 * Returns TRUE if the file was deleted, FALSE if it did not exist or
 * deletion failed.
 */
BOOL abandon_partial_download(const char *target_path);

#endif /* __linux__ */
