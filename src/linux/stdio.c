/* Linux: stdio.c - I/O utilities and process execution */
#include "rufus.h"
#include "resource.h"
#include "localization.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/poll.h>
/* NO_ERROR and ERROR_INVALID_PARAMETER constants */
#include "compat/winioctl.h"

/* Forward declarations for cregex used by RunCommandWithProgress */
#include "cregex.h"

extern DWORD ErrorStatus;
extern void _UpdateProgressWithInfo(int op, int msg, uint64_t cur, uint64_t tot, BOOL force);


/* ---------------------------------------------------------------------------
 * Log handler — can be overridden by the GTK UI to route messages to the
 * on-screen log widget instead of / in addition to stderr.
 *
 * Call rufus_set_log_handler(fn) from ui_gtk.c to redirect log output.
 * Pass NULL to revert to stderr.
 * ---------------------------------------------------------------------------*/
static void (*log_handler_fn)(const char *msg) = NULL;

void rufus_set_log_handler(void (*fn)(const char *msg))
{
	log_handler_fn = fn;
}

void uprintf(const char *format, ...) {
    char buf[4096];
    va_list ap;
    va_start(ap, format);
    vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);
    buf[sizeof(buf) - 1] = '\0';
    if (log_handler_fn) {
        log_handler_fn(buf);
    } else {
        fputs(buf, stderr);
        fputc('\n', stderr);
    }
}

void wuprintf(const wchar_t* format, ...) {
    wchar_t wbuf[4096];
    char utf8[4096 * 4];
    size_t out = 0;

    if (format == NULL)
        return;

    va_list ap;
    va_start(ap, format);
    vswprintf(wbuf, sizeof(wbuf) / sizeof(wbuf[0]), format, ap);
    va_end(ap);

    /* Convert wchar_t (UCS-4 on Linux) to UTF-8 without locale dependency.
     * Each wchar_t is a Unicode code point; encode directly to UTF-8. */
    for (const wchar_t *p = wbuf; *p && out + 4 < sizeof(utf8); p++) {
        uint32_t cp = (uint32_t)*p;
        if (cp < 0x80) {
            utf8[out++] = (char)cp;
        } else if (cp < 0x800) {
            utf8[out++] = (char)(0xC0 | (cp >> 6));
            utf8[out++] = (char)(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            utf8[out++] = (char)(0xE0 | (cp >> 12));
            utf8[out++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            utf8[out++] = (char)(0x80 | (cp & 0x3F));
        } else if (cp < 0x110000) {
            utf8[out++] = (char)(0xF0 | (cp >> 18));
            utf8[out++] = (char)(0x80 | ((cp >> 12) & 0x3F));
            utf8[out++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            utf8[out++] = (char)(0x80 | (cp & 0x3F));
        }
        /* skip surrogates and out-of-range code points silently */
    }
    utf8[out] = '\0';

    /* Route through the same log handler as uprintf */
    if (log_handler_fn) {
        log_handler_fn(utf8);
    } else {
        fputs(utf8, stderr);
        fputc('\n', stderr);
    }
}

void uprintfs(const char* str) { if(str) fputs(str, stderr); }

void uprint_progress(uint64_t cur, uint64_t max)
{
    if (max > 0)
        _UpdateProgressWithInfo(OP_FORMAT, 0, cur, max, FALSE);
}

uint32_t read_file(const char* path, uint8_t** buf) {
    FILE* f = fopen(path, "rb");
    if (!f || !buf) return 0;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    *buf = (uint8_t*)malloc(sz);
    if (!*buf) { fclose(f); return 0; }
    uint32_t r = (uint32_t)fread(*buf, 1, sz, f);
    fclose(f);
    return r;
}

uint32_t write_file(const char* path, const uint8_t* buf, const uint32_t size) {
    FILE* f = fopen(path, "wb");
    if (!f || !buf) return 0;
    uint32_t w = (uint32_t)fwrite(buf, 1, size, f);
    fclose(f);
    return w;
}

/* Return a static string of the binary representation of an integer value.
 * size:    byte count of the value pointed to by ptr
 * ptr:     pointer to the value (little-endian)
 * lz:      if non-zero, pad with leading zeros to full bit width
 *
 * Returns pointer to an internal static buffer; not re-entrant. */
char* _printbits(size_t const size, void const* const ptr, int lz)
{
    /* sizeof(uintmax_t) so we have enough space for whatever is thrown at us */
    static char str[sizeof(uintmax_t) * 8 + 3];
    size_t i;
    const uint8_t *b = (const uint8_t *)ptr;
    uintmax_t mask, lzmask = 0, val = 0;

    if (ptr == NULL || size == 0)
        return NULL;

    /* Reconstruct the integer from little-endian bytes */
    for (i = 0; i < size && i < sizeof(uintmax_t); i++)
        val |= ((uintmax_t)b[i]) << (8 * i);

    str[0] = '0';
    str[1] = 'b';
    if (lz)
        lzmask = (uintmax_t)1 << (size * 8 - 1);
    for (i = 2, mask = (uintmax_t)1 << (sizeof(uintmax_t) * 8 - 1); mask != 0; mask >>= 1) {
        if ((i > 2) || (lzmask & mask))
            str[i++] = (val & mask) ? '1' : '0';
        else if (val & mask)
            str[i++] = '1';
    }
    str[i] = '\0';
    return str;
}

/* Display an hex dump of buffer `buf` (size bytes) via uprintf.
 * Output matches the format: "  XXXXXXXX  XX XX ... XX  .ASCII.......\n" */
void DumpBufferHex(void* buf, size_t size)
{
    unsigned char *buffer = (unsigned char *)buf;
    size_t i, j, k;
    char line[80];

    if (buffer == NULL || size == 0)
        return;

    for (i = 0; i < size; i += 16) {
        if (i != 0)
            uprintf("%s\n", line);
        line[0] = '\0';
        sprintf(line + strlen(line), "  %08x  ", (unsigned int)i);
        for (j = 0, k = 0; k < 16; j++, k++) {
            if (i + j < size)
                sprintf(line + strlen(line), "%02x", buffer[i + j]);
            else
                sprintf(line + strlen(line), "  ");
            sprintf(line + strlen(line), " ");
        }
        sprintf(line + strlen(line), " ");
        for (j = 0, k = 0; k < 16; j++, k++) {
            if (i + j < size) {
                if (buffer[i + j] < 32 || buffer[i + j] > 126)
                    sprintf(line + strlen(line), ".");
                else
                    sprintf(line + strlen(line), "%c", buffer[i + j]);
            }
        }
    }
    uprintf("%s\n", line);
}

/* Map Windows DWORD error codes (non-FACILITY_STORAGE) to POSIX errno */
static int windows_dword_to_errno(DWORD code)
{
	switch (code) {
	case ERROR_SUCCESS:             return 0;
	case ERROR_FILE_NOT_FOUND:      return ENOENT;
	case ERROR_PATH_NOT_FOUND:      return ENOENT;
	case ERROR_TOO_MANY_OPEN_FILES: return EMFILE;
	case ERROR_ACCESS_DENIED:       return EACCES;
	case ERROR_INVALID_HANDLE:      return EBADF;
	case ERROR_NOT_ENOUGH_MEMORY:   return ENOMEM;
	case ERROR_OUTOFMEMORY:         return ENOMEM;
	case ERROR_WRITE_PROTECT:       return EROFS;
	case ERROR_NO_MORE_FILES:       return ENOENT;
	case ERROR_WRITE_FAULT:         return EIO;
	case ERROR_READ_FAULT:          return EIO;
	case ERROR_NOT_SUPPORTED:       return ENOTSUP;
	case ERROR_FILE_EXISTS:         return EEXIST;
	case ERROR_INVALID_PARAMETER:   return EINVAL;
	case ERROR_INSUFFICIENT_BUFFER: return ENOBUFS;
	case ERROR_NOT_READY:           return ENODEV;
	case ERROR_DEVICE_IN_USE:       return EBUSY;
	case ERROR_OPEN_FAILED:         return ENOENT;
	case ERROR_CANCELLED:           return ECANCELED;
	default:                        return errno;
	}
}

const char* _StrError(DWORD error_code)
{
	if (!IS_ERROR(error_code) || SCODE_CODE(error_code) == ERROR_SUCCESS)
		return lmprintf(MSG_050);
	if (SCODE_FACILITY(error_code) != FACILITY_STORAGE)
		return strerror(windows_dword_to_errno(SCODE_CODE(error_code)));
	switch (SCODE_CODE(error_code)) {
	case ERROR_GEN_FAILURE:          return lmprintf(MSG_051);
	case ERROR_INCOMPATIBLE_FS:      return lmprintf(MSG_052);
	case ERROR_ACCESS_DENIED:        return lmprintf(MSG_053);
	case ERROR_WRITE_PROTECT:        return lmprintf(MSG_054);
	case ERROR_DEVICE_IN_USE:        return lmprintf(MSG_055);
	case ERROR_CANT_QUICK_FORMAT:    return lmprintf(MSG_056);
	case ERROR_LABEL_TOO_LONG:       return lmprintf(MSG_057);
	case ERROR_INVALID_HANDLE:       return lmprintf(MSG_058);
	case ERROR_INVALID_CLUSTER_SIZE: return lmprintf(MSG_059);
	case ERROR_INVALID_VOLUME_SIZE:  return lmprintf(MSG_060);
	case ERROR_NO_MEDIA_IN_DRIVE:    return lmprintf(MSG_061);
	case ERROR_NOT_SUPPORTED:        return lmprintf(MSG_062);
	case ERROR_NOT_ENOUGH_MEMORY:    return lmprintf(MSG_063);
	case ERROR_READ_FAULT:           return lmprintf(MSG_064);
	case ERROR_WRITE_FAULT:          return lmprintf(MSG_065);
	case ERROR_INSTALL_FAILURE:      return lmprintf(MSG_066);
	case ERROR_OPEN_FAILED:          return lmprintf(MSG_067);
	case ERROR_PARTITION_FAILURE:    return lmprintf(MSG_068);
	case ERROR_CANNOT_COPY:          return lmprintf(MSG_069);
	case ERROR_CANCELLED:            return lmprintf(MSG_070);
	case ERROR_CANT_START_THREAD:    return lmprintf(MSG_071);
	case ERROR_BADBLOCKS_FAILURE:    return lmprintf(MSG_072);
	case ERROR_ISO_SCAN:             return lmprintf(MSG_073);
	case ERROR_ISO_EXTRACT:          return lmprintf(MSG_074);
	case ERROR_CANT_REMOUNT_VOLUME:  return lmprintf(MSG_075);
	case ERROR_CANT_PATCH:           return lmprintf(MSG_076);
	case ERROR_CANT_ASSIGN_LETTER:   return lmprintf(MSG_077);
	case ERROR_CANT_MOUNT_VOLUME:    return lmprintf(MSG_078);
	case ERROR_NOT_READY:            return lmprintf(MSG_079);
	case ERROR_BAD_SIGNATURE:        return lmprintf(MSG_172);
	case ERROR_CANT_DOWNLOAD:        return lmprintf(MSG_242);
	default:
		return strerror(windows_dword_to_errno(SCODE_CODE(error_code)));
	}
}

const char* WindowsErrorString(void)
{
	DWORD code = _win_last_error ? _win_last_error : (DWORD)errno;
	if (IS_ERROR(code))
		return _StrError(code);
	return strerror(windows_dword_to_errno(code));
}

const char* StrError(DWORD code, BOOL use_default) { (void)use_default; return _StrError(code); }

/* ---------------------------------------------------------------------------
 * CreateFileWithTimeout — open a file/device with a deadline.
 *
 * On Linux, GENERIC_READ|WRITE + O_RDWR is used. Files that block on open()
 * (e.g., named FIFOs, or devices not yet ready) are opened with O_NONBLOCK
 * first, then the flag is cleared. The timeout is enforced via a poll()/
 * select()-free approach: we try O_NONBLOCK open, and if ENXIO/EBUSY retry
 * up to dwTimeOut milliseconds in 10 ms steps.
 * ---------------------------------------------------------------------------*/
typedef struct {
    const char* path;
    int         oflags;    /* open() flags (without O_NONBLOCK) */
    HANDLE      result;    /* set by thread */
    int         error;
} _cfwt_params_t;

DWORD WINAPI CreateFileWithTimeoutThread(void* param)
{
    _cfwt_params_t* p = (_cfwt_params_t*)param;
    int fd = open(p->path, p->oflags | O_NONBLOCK, 0666);
    if (fd >= 0) {
        /* Clear O_NONBLOCK so subsequent I/O is blocking */
        int fl = fcntl(fd, F_GETFL);
        if (fl >= 0) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
        p->result = (HANDLE)(intptr_t)fd;
        p->error  = 0;
    } else {
        p->result = INVALID_HANDLE_VALUE;
        p->error  = errno;
    }
    return (DWORD)p->error;
}

HANDLE CreateFileWithTimeout(LPCSTR lpFileName, DWORD dwDesiredAccess,
    DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSa, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplate, DWORD dwTimeOut)
{
    (void)dwShareMode; (void)lpSa; (void)dwFlagsAndAttributes; (void)hTemplate;

    int oflags = 0;
    if ((dwDesiredAccess & GENERIC_READ) && (dwDesiredAccess & GENERIC_WRITE))
        oflags = O_RDWR;
    else if (dwDesiredAccess & GENERIC_WRITE)
        oflags = O_WRONLY;
    else
        oflags = O_RDONLY;
    if (dwCreationDisposition == CREATE_ALWAYS || dwCreationDisposition == OPEN_ALWAYS)
        oflags |= O_CREAT;
    if (dwCreationDisposition == CREATE_ALWAYS || dwCreationDisposition == TRUNCATE_EXISTING)
        oflags |= O_TRUNC;
    if (dwCreationDisposition == CREATE_NEW)
        oflags |= O_CREAT | O_EXCL;

    if (dwTimeOut == 0) dwTimeOut = 5000; /* 5 s default */

    _cfwt_params_t params = { lpFileName, oflags, INVALID_HANDLE_VALUE, 0 };
    HANDLE hThread = CreateThread(NULL, 0, CreateFileWithTimeoutThread,
                                  &params, 0, NULL);
    if (hThread == NULL || hThread == INVALID_HANDLE_VALUE)
        return INVALID_HANDLE_VALUE;

    DWORD r = WaitForSingleObject(hThread, dwTimeOut);
    CloseHandle(hThread);
    if (r == WAIT_TIMEOUT) {
        uprintf("Could not open file or device within timeout duration");
        return INVALID_HANDLE_VALUE;
    }
    return params.result;
}

BOOL  CALLBACK EnumSymProc(void* info, ULONG sz, PVOID ctx)       { (void)info;(void)sz;(void)ctx; return FALSE; }
uint32_t ResolveDllAddress(dll_resolver_t* resolver)              { (void)resolver; return 0; }

/* WaitForSingleObjectWithMessages — on Linux there is no message pump,
 * so we simply delegate to WaitForSingleObject which uses pthreads. */
DWORD WaitForSingleObjectWithMessages(HANDLE h, DWORD ms)
{
    return WaitForSingleObject(h, ms);
}

/* ---------------------------------------------------------------------------
 * ListDirectoryContent — POSIX implementation
 *
 * Fills `arr` with full paths of matching entries inside `dir`.
 * `type` is a bitmask of LIST_DIR_TYPE_FILE, LIST_DIR_TYPE_DIRECTORY, and
 * optionally LIST_DIR_TYPE_RECURSIVE.
 *
 * Returns NO_ERROR (0) when at least one file was found, ERROR_FILE_NOT_FOUND
 * when the directory exists but has no matching entries, or a non-zero error
 * code on failure.
 * ---------------------------------------------------------------------------*/
DWORD ListDirectoryContent(StrArray* arr, char* dir, uint8_t type)
{
    if (!arr || !dir || (type & 0x03) == 0)
        return ERROR_INVALID_PARAMETER;

    DIR *d = opendir(dir);
    if (!d)
        return (errno == ENOENT) ? ERROR_PATH_NOT_FOUND : (DWORD)errno;

    DWORD result = ERROR_FILE_NOT_FOUND;
    struct dirent *ent;

    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        /* Build full path */
        size_t dirlen = strlen(dir);
        size_t namlen = strlen(ent->d_name);
        char *fullpath = (char*)malloc(dirlen + 1 + namlen + 2); /* +2: '/' + NUL */
        if (!fullpath) continue;
        memcpy(fullpath, dir, dirlen);
        fullpath[dirlen] = '/';
        memcpy(fullpath + dirlen + 1, ent->d_name, namlen + 1);

        struct stat st;
        if (stat(fullpath, &st) != 0) { free(fullpath); continue; }

        if (S_ISDIR(st.st_mode)) {
            if (type & LIST_DIR_TYPE_RECURSIVE) {
                if (type & LIST_DIR_TYPE_DIRECTORY) {
                    /* Append trailing slash for directories */
                    fullpath[dirlen + 1 + namlen] = '/';
                    fullpath[dirlen + 1 + namlen + 1] = '\0';
                    StrArrayAdd(arr, fullpath, TRUE);
                }
                /* Recurse; strip trailing slash before recursing */
                fullpath[dirlen + 1 + namlen] = '\0';
                DWORD sub = ListDirectoryContent(arr, fullpath, type);
                if (sub == NO_ERROR) result = NO_ERROR;
            }
        } else {
            if (type & LIST_DIR_TYPE_FILE) {
                StrArrayAdd(arr, fullpath, TRUE);
                result = NO_ERROR;
            }
        }
        free(fullpath);
    }
    closedir(d);
    return result;
}

/* ---------------------------------------------------------------------------
 * ExtractZip — extract a ZIP archive using the bundled bled library
 * ---------------------------------------------------------------------------*/
#include "bled/bled.h"

/* progress callback — update UI if available */
static void zip_progress(const uint64_t bytes)
{
    /* Route through UpdateProgressWithInfo when format thread is running;
     * for now a no-op is fine — progress can be added later. */
    (void)bytes;
}

/* per-file print callback */
static void zip_print_file(const char *path, const uint64_t size) { (void)path; (void)size; }

BOOL ExtractZip(const char* src, const char* dst)
{
    if (!src || !dst)
        return FALSE;

    if (bled_init(256 * 1024, NULL, NULL, NULL,
                  zip_progress, zip_print_file,
                  (unsigned long*)(void*)&ErrorStatus) != 0)
        return FALSE;

    uprintf("Extracting zip '%s' to '%s'", src, dst);
    int64_t extracted = bled_uncompress_to_dir(src, dst, BLED_COMPRESSION_ZIP);
    bled_exit();
    return (extracted > 0) ? TRUE : FALSE;
}
BOOL  WriteFileWithRetry(HANDLE h, const void* buf, DWORD n, DWORD* written, DWORD retries) {
    if (h == INVALID_HANDLE_VALUE || !buf) return FALSE;
    int fd = (int)(intptr_t)h;
    DWORD total = 0;
    while (total < n) {
        ssize_t r = write(fd, (const char*)buf + total, n - total);
        if (r > 0) {
            total += (DWORD)r;
        } else if (r == 0 || (errno != EINTR && errno != EAGAIN)) {
            if (retries > 0) { retries--; continue; }
            break;
        }
    }
    if (written) *written = total;
    return (total == n);
}

/* ---------------------------------------------------------------------------
 * RunCommandWithProgress — execute a shell command, optionally capturing
 * output to the log and/or tracking progress via a regex pattern.
 *
 * cmd     - shell command string (run via sh -c)
 * dir     - working directory for child, or NULL to use cwd
 * log     - if TRUE, forward child stdout/stderr to uprintf
 * msg     - if non-zero, parse progress % using pattern and call
 *           UpdateProgressWithInfo
 * pattern - regex with one capture group matching a float percentage,
 *           used when msg != 0; may be NULL if msg == 0
 *
 * Returns the child's exit code, or ERROR_CANCELLED if the user cancelled.
 * ---------------------------------------------------------------------------*/
DWORD RunCommandWithProgress(const char* cmd, const char* dir,
                             BOOL log, int msg, const char* pattern)
{
    if (cmd == NULL)
        return ERROR_INVALID_PARAMETER;

    /* Compile progress regex if needed */
    cregex_node_t*    node    = NULL;
    cregex_program_t* program = NULL;
    if (msg != 0 && pattern != NULL) {
        node = cregex_parse(pattern);
        if (node != NULL) {
            program = cregex_compile_node(node);
            cregex_parse_free(node);
        }
        if (program == NULL)
            uprintf("RunCommandWithProgress: failed to compile pattern '%s'", pattern);
        else
            UpdateProgressWithInfoInit(NULL, FALSE);
    }

    /* Check for cancellation before even launching */
    if (IS_ERROR(ErrorStatus) && (SCODE_CODE(ErrorStatus) == ERROR_CANCELLED)) {
        cregex_compile_free(program);
        return ERROR_CANCELLED;
    }

    /* Create pipe for child stdout+stderr */
    int pipefd[2] = { -1, -1 };
    if (log || program != NULL) {
        if (pipe(pipefd) != 0) {
            uprintf("RunCommandWithProgress: pipe() failed: %s", strerror(errno));
            cregex_compile_free(program);
            return (DWORD)errno;
        }
        /* Make read-end non-blocking so we can poll */
        fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
    }

    pid_t pid = fork();
    if (pid < 0) {
        uprintf("RunCommandWithProgress: fork() failed: %s", strerror(errno));
        if (pipefd[0] != -1) { close(pipefd[0]); close(pipefd[1]); }
        cregex_compile_free(program);
        return (DWORD)errno;
    }

    if (pid == 0) {
        /* Child */
        if (pipefd[1] != -1) {
            dup2(pipefd[1], STDOUT_FILENO);
            dup2(pipefd[1], STDERR_FILENO);
            close(pipefd[0]);
            close(pipefd[1]);
        }
        if (dir != NULL) {
            if (chdir(dir) != 0) {
                /* Can't report error from child after dup2 */
                _exit(127);
            }
        }
        execl("/bin/sh", "sh", "-c", cmd, (char*)NULL);
        _exit(127); /* exec failed */
    }

    /* Parent */
    if (pipefd[1] != -1)
        close(pipefd[1]); /* close write end — only child writes */

    DWORD ret = 0;
    char  buf[4096];
    const char* matches[REGEX_VM_MAX_MATCHES];

    while (1) {
        /* Check for user cancellation */
        if (IS_ERROR(ErrorStatus) && (SCODE_CODE(ErrorStatus) == ERROR_CANCELLED)) {
            kill(pid, SIGTERM);
            /* Give child up to 2s to die, then SIGKILL */
            int waited = 0;
            while (waited < 2000) {
                int status;
                pid_t r = waitpid(pid, &status, WNOHANG);
                if (r == pid) goto cancelled;
                usleep(100000);
                waited += 100;
            }
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
cancelled:
            if (pipefd[0] != -1) close(pipefd[0]);
            cregex_compile_free(program);
            return ERROR_CANCELLED;
        }

        /* Drain available output */
        if (pipefd[0] != -1) {
            ssize_t n;
            while ((n = read(pipefd[0], buf, sizeof(buf) - 1)) > 0) {
                buf[n] = '\0';
                if (program != NULL &&
                    cregex_program_run(program, buf,
                                       (const char**)matches,
                                       ARRAYSIZE(matches)) > 0 &&
                    matches[2] != NULL && matches[3] != NULL) {
                    /* matches[2]/[3] bracket the first capture group */
                    char saved = *matches[3];
                    *(char*)matches[3] = '\0';
                    float f = 0.0f;
                    sscanf(matches[2], "%f", &f);
                    *(char*)matches[3] = saved;
                    UpdateProgressWithInfo(OP_FORMAT, msg,
                                          (uint64_t)(f * 100.0f), 100 * 100ULL);
                } else if (log) {
                    uprintf("%s", buf);
                }
            }
        }

        /* Check if child exited */
        int status;
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            if (WIFEXITED(status))
                ret = (DWORD)WEXITSTATUS(status);
            else if (WIFSIGNALED(status))
                ret = (DWORD)(128 + WTERMSIG(status));
            else
                ret = 1;
            break;
        }
        /* Child still running — short sleep to avoid busy-wait */
        usleep(50000); /* 50ms */
    }

    /* Drain any remaining output after child exited */
    if (pipefd[0] != -1) {
        ssize_t n;
        while ((n = read(pipefd[0], buf, sizeof(buf) - 1)) > 0) {
            buf[n] = '\0';
            if (program != NULL &&
                cregex_program_run(program, buf,
                                   (const char**)matches,
                                   ARRAYSIZE(matches)) > 0 &&
                matches[2] != NULL && matches[3] != NULL) {
                char saved = *matches[3];
                *(char*)matches[3] = '\0';
                float f = 0.0f;
                sscanf(matches[2], "%f", &f);
                *(char*)matches[3] = saved;
                UpdateProgressWithInfo(OP_FORMAT, msg,
                                       (uint64_t)(f * 100.0f), 100 * 100ULL);
            } else if (log) {
                uprintf("%s", buf);
            }
        }
        close(pipefd[0]);
    }

    cregex_compile_free(program);
    return ret;
}

char* SizeToHumanReadable(uint64_t size, BOOL copy_to_log, BOOL fake_units)
{
    static char str[32];
    static const char* suffix[] = { "B", "KB", "MB", "GB", "TB", "PB" };
    double hr = (double)size;
    int s = 0;
    const double div = fake_units ? 1000.0 : 1024.0;
    (void)copy_to_log;
    while (s < 5 && hr >= div) { hr /= div; s++; }
    if (s == 0)
        snprintf(str, sizeof(str), "%d %s", (int)hr, suffix[s]);
    else
        snprintf(str, sizeof(str), (hr - (int)hr < 0.05) ? "%.0f %s" : "%.1f %s", hr, suffix[s]);
    return str;
}


/* -------------------------------------------------------------------------
 * GUID string conversion helpers
 * --------------------------------------------------------------------- */

char *GuidToString(const GUID *guid, BOOL bDecorated)
{
    static char guid_string[MAX_GUID_STRING_LENGTH];
    if (guid == NULL) return NULL;
    snprintf(guid_string, sizeof(guid_string),
             bDecorated
             ? "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}"
             : "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
             (uint32_t)guid->Data1, guid->Data2, guid->Data3,
             guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
             guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
    return guid_string;
}

GUID *StringToGuid(const char *str)
{
    static GUID guid;
    if (str == NULL) return NULL;
    unsigned int d[11];
    if (sscanf(str, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
               &d[0], &d[1], &d[2],
               &d[3], &d[4], &d[5], &d[6],
               &d[7], &d[8], &d[9], &d[10]) != 11)
        return NULL;
    guid.Data1    = (uint32_t)d[0];
    guid.Data2    = (uint16_t)d[1];
    guid.Data3    = (uint16_t)d[2];
    guid.Data4[0] = (uint8_t)d[3];
    guid.Data4[1] = (uint8_t)d[4];
    guid.Data4[2] = (uint8_t)d[5];
    guid.Data4[3] = (uint8_t)d[6];
    guid.Data4[4] = (uint8_t)d[7];
    guid.Data4[5] = (uint8_t)d[8];
    guid.Data4[6] = (uint8_t)d[9];
    guid.Data4[7] = (uint8_t)d[10];
    return &guid;
}
