/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux write-and-verify pass
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
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "rufus.h"
#include "resource.h"
#include "missing.h"

#define VERIFY_CHUNK_SIZE (4u * 1024u * 1024u)  /* 4 MiB per chunk */

/*
 * verify_write_pass - compare the first `written_size` bytes of the device
 * file `device_fd` against the file at `source_path`, chunk by chunk.
 *
 * Returns TRUE if every byte matches, FALSE otherwise.
 * Sets LastWriteError = RUFUS_ERROR(ERROR_CRC) on a mismatch.
 */
BOOL verify_write_pass(const char *source_path, int device_fd,
                       uint64_t written_size)
{
	BOOL ok = FALSE;
	int src_fd = -1;
	uint8_t *src_buf = NULL, *dev_buf = NULL;

	if (!source_path || device_fd < 0)
		return FALSE;
	if (written_size == 0)
		return TRUE;

	src_fd = open(source_path, O_RDONLY | O_CLOEXEC);
	if (src_fd < 0) {
		uprintf("verify_write_pass: cannot open source '%s': %s",
		        source_path, strerror(errno));
		return FALSE;
	}

	src_buf = (uint8_t *)malloc(VERIFY_CHUNK_SIZE);
	dev_buf = (uint8_t *)malloc(VERIFY_CHUNK_SIZE);
	if (!src_buf || !dev_buf) {
		uprintf("verify_write_pass: out of memory");
		goto out;
	}

	uint64_t offset = 0;
	while (offset < written_size) {
		CHECK_FOR_USER_CANCEL;

		size_t to_check = (size_t)((written_size - offset) < VERIFY_CHUNK_SIZE
		                           ? (written_size - offset)
		                           : VERIFY_CHUNK_SIZE);

		ssize_t src_r = pread(src_fd, src_buf, to_check, (off_t)offset);
		if (src_r <= 0) {
			uprintf("verify_write_pass: short read from source at offset "
			        "0x%08llX (expected %zu, got %zd)",
			        (unsigned long long)offset, to_check, src_r);
			LastWriteError = RUFUS_ERROR(ERROR_READ_FAULT);
			goto out;
		}

		ssize_t dev_r = pread(device_fd, dev_buf, (size_t)src_r, (off_t)offset);
		if (dev_r != src_r) {
			uprintf("verify_write_pass: short read from device at offset "
			        "0x%08llX (expected %zd, got %zd)",
			        (unsigned long long)offset, src_r, dev_r);
			LastWriteError = RUFUS_ERROR(ERROR_READ_FAULT);
			goto out;
		}

		if (memcmp(src_buf, dev_buf, (size_t)src_r) != 0) {
			/* Find the first differing byte to report the exact offset */
			for (ssize_t i = 0; i < src_r; i++) {
				if (src_buf[i] != dev_buf[i]) {
					uprintf("Verify write failed at offset 0x%08llX - aborting",
					        (unsigned long long)(offset + (uint64_t)i));
					break;
				}
			}
			LastWriteError = RUFUS_ERROR(ERROR_WRITE_FAULT);
			goto out;
		}

		offset += (uint64_t)src_r;
		UpdateProgressWithInfo(OP_VERIFY, MSG_355, offset, written_size);
	}

	ok = TRUE;

out:
	free(src_buf);
	free(dev_buf);
	if (src_fd >= 0)
		close(src_fd);
	return ok;
}
