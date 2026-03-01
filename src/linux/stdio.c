/* Linux: stdio.c - I/O utilities and process execution */
#include "rufus.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/poll.h>

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
    va_list ap;
    va_start(ap, format);
    vfwprintf(stderr, format, ap);
    va_end(ap);
    fputwc(L'\n', stderr);
}

void uprintfs(const char* str) { if(str) fputs(str, stderr); }

void uprint_progress(uint64_t cur, uint64_t max) { (void)cur;(void)max; }

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

char* _printbits(size_t const size, void const* const ptr, int lz) {
    (void)size;(void)ptr;(void)lz;
    return NULL;
}

void DumpBufferHex(void* buf, size_t size) { (void)buf;(void)size; }

const char* WindowsErrorString(void) { return strerror(errno); }
const char* _StrError(DWORD code)    { return strerror((int)code); }
const char* StrError(DWORD code, BOOL use_default) { (void)use_default; return strerror((int)code); }

DWORD WINAPI CreateFileWithTimeoutThread(void* params)            { (void)params; return 0; }
DWORD WaitForSingleObjectWithMessages(HANDLE h, DWORD ms)         { (void)h;(void)ms; return 0; }
BOOL  CALLBACK EnumSymProc(void* info, ULONG sz, PVOID ctx)       { (void)info;(void)sz;(void)ctx; return FALSE; }
uint32_t ResolveDllAddress(dll_resolver_t* resolver)                        { (void)resolver; return 0; }
BOOL  ExtractZip(const char* src, const char* dst)                { (void)src;(void)dst; return FALSE; }
DWORD ListDirectoryContent(StrArray* arr, char* dir, uint8_t type) { (void)arr;(void)dir;(void)type; return 0; }
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
