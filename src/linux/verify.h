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

#pragma once
#ifdef __linux__

#include <stdint.h>
#include "../linux/compat/windows.h"

/*
 * verify_write_pass - Re-read the first `written_size` bytes of the device
 * identified by `device_fd` and compare them against the source file at
 * `source_path`, chunk by chunk (4 MiB chunks).
 *
 * Returns TRUE when every byte matches.
 * Returns FALSE on:
 *   - NULL source_path or negative device_fd
 *   - written_size == 0 (nothing was written — treat as trivial success)
 *   - any read error on source or device
 *   - any byte mismatch (also sets LastWriteError = RUFUS_ERROR(ERROR_CRC))
 *   - user cancellation (ErrorStatus == ERROR_CANCELLED)
 *
 * Progress is reported via UpdateProgressWithInfo(OP_VERIFY, MSG_355,
 * bytes_checked, written_size) on each completed chunk.
 */
BOOL verify_write_pass(const char *source_path, int device_fd,
                       uint64_t written_size);

#endif /* __linux__ */
