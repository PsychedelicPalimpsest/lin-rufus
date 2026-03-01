/*
 * Linux implementation: dos.c
 * ExtractFreeDOS / ExtractDOS — copy FreeDOS boot files from the resource
 * directory to a target FAT drive.
 *
 * The FreeDOS files ship in res/freedos/ alongside the binary.  We locate
 * them via app_dir (set by rufus_init_paths()) and fall back to the
 * compile-time PKGDATADIR if neither adjacent path is found.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "rufus.h"
#include "dos.h"
#include "missing.h"
#include "resource.h"

extern char app_dir[MAX_PATH];
extern int boot_type;
extern uint8_t* GetResource(HMODULE m, char* n, char* t, const char* d, DWORD* l, BOOL dup);

/* Files to extract.  Index < 2 go to path, index >= 2 go to path/LOCALE/ */
static const char* const fd_files[] = {
    "COMMAND.COM",   /* 0 - root */
    "KERNEL.SYS",    /* 1 - root */
    "DISPLAY.EXE",   /* 2+ - LOCALE/ */
    "KEYB.EXE",
    "MODE.COM",
    "KEYBOARD.SYS",
    "KEYBRD2.SYS",
    "KEYBRD3.SYS",
    "KEYBRD4.SYS",
    "EGA.CPX",
    "EGA2.CPX",
    "EGA3.CPX",
    "EGA4.CPX",
    "EGA5.CPX",
    "EGA6.CPX",
    "EGA7.CPX",
    "EGA8.CPX",
    "EGA9.CPX",
    "EGA10.CPX",
    "EGA11.CPX",
    "EGA12.CPX",
    "EGA13.CPX",
    "EGA14.CPX",
    "EGA15.CPX",
    "EGA16.CPX",
    "EGA17.CPX",
    "EGA18.CPX",
};
#define FD_ROOT_FILES  2   /* number of files that go to path/ */
#define FD_NFILES ((int)(sizeof(fd_files)/sizeof(fd_files[0])))

/*
 * get_freedos_source_dir — find the directory that contains the FreeDOS
 * resource files.  Returns a newly-allocated path string (caller must free),
 * or NULL if not found.
 *
 * Search order:
 *   1. {app_dir}res/freedos/
 *   2. {app_dir}../res/freedos/
 *   3. PKGDATADIR "/rufus/freedos/"   (if compiled with autotools)
 */
static char* get_freedos_source_dir(void)
{
    char candidate[MAX_PATH];
    struct stat st;

    /* Try {app_dir}res/freedos/ */
    snprintf(candidate, sizeof(candidate), "%sres/freedos", app_dir);
    if (stat(candidate, &st) == 0 && S_ISDIR(st.st_mode)) {
        char *ret = (char*)malloc(MAX_PATH);
        if (ret) snprintf(ret, MAX_PATH, "%s/", candidate);
        return ret;
    }

    /* Try {app_dir}../res/freedos/ */
    snprintf(candidate, sizeof(candidate), "%s../res/freedos", app_dir);
    if (stat(candidate, &st) == 0 && S_ISDIR(st.st_mode)) {
        char *ret = (char*)malloc(MAX_PATH);
        if (ret) snprintf(ret, MAX_PATH, "%s/", candidate);
        return ret;
    }

#ifdef PKGDATADIR
    /* Try installed data directory */
    snprintf(candidate, sizeof(candidate), "%s/rufus/freedos", PKGDATADIR);
    if (stat(candidate, &st) == 0 && S_ISDIR(st.st_mode)) {
        char *ret = (char*)malloc(MAX_PATH);
        if (ret) snprintf(ret, MAX_PATH, "%s/", candidate);
        return ret;
    }
#endif

    return NULL;
}

/*
 * write_resource_to_file — write buf[0..len-1] to path.  Returns TRUE on success.
 */
static BOOL write_resource_to_file(const char *path, const uint8_t *buf, DWORD len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        uprintf_errno("ExtractFreeDOS: cannot create '%s'", path);
        return FALSE;
    }
    ssize_t written = write(fd, buf, (size_t)len);
    close(fd);
    if (written < 0 || (DWORD)written != len) {
        uprintf_errno("ExtractFreeDOS: write error on '%s'", path);
        return FALSE;
    }
    return TRUE;
}

/*
 * copy_file — copy src to dst.  Returns TRUE on success.
 */
static BOOL copy_file(const char *src, const char *dst)
{
    int sfd = open(src, O_RDONLY | O_CLOEXEC);
    if (sfd < 0) {
        uprintf_errno("ExtractFreeDOS: cannot open source '%s'", src);
        return FALSE;
    }

    int dfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (dfd < 0) {
        uprintf_errno("ExtractFreeDOS: cannot create '%s'", dst);
        close(sfd);
        return FALSE;
    }

    char buf[65536];
    ssize_t n;
    BOOL ok = TRUE;
    while ((n = read(sfd, buf, sizeof(buf))) > 0) {
        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(dfd, buf + written, (size_t)(n - written));
            if (w < 0) {
                uprintf_errno("ExtractFreeDOS: write error on '%s'", dst);
                ok = FALSE;
                break;
            }
            written += w;
        }
        if (!ok) break;
    }
    if (n < 0) {
        uprintf_errno("ExtractFreeDOS: read error on '%s'", src);
        ok = FALSE;
    }

    close(sfd);
    close(dfd);
    return ok;
}

BOOL ExtractFreeDOS(const char* path)
{
    if (path == NULL) {
        uprintf("ExtractFreeDOS: NULL path");
        return FALSE;
    }

    /* Ensure target directory exists */
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        uprintf("ExtractFreeDOS: target '%s' is not a directory", path);
        return FALSE;
    }

    /* Create LOCALE/ subdirectory */
    char locale_path[MAX_PATH];
    snprintf(locale_path, sizeof(locale_path), "%sLOCALE", path);
    if (mkdir(locale_path, 0755) != 0 && errno != EEXIST) {
        uprintf("ExtractFreeDOS: cannot create LOCALE dir '%s': %s",
                locale_path, strerror(errno));
        return FALSE;
    }

    char* src_dir = NULL;  /* lazily resolved when disk fallback is needed */

    /* Extract each file: try embedded resource first, fall back to disk. */
    for (int i = 0; i < FD_NFILES; i++) {
        char dst[MAX_PATH];
        if (i < FD_ROOT_FILES)
            snprintf(dst, sizeof(dst), "%s%s", path, fd_files[i]);
        else
            snprintf(dst, sizeof(dst), "%sLOCALE/%s", path, fd_files[i]);

        /* Try embedded resource (IDR_FD_COMMAND_COM == 300, sequential) */
        DWORD res_size = 0;
        uint8_t *res_data = GetResource(NULL,
                MAKEINTRESOURCEA(IDR_FD_COMMAND_COM + i),
                _RT_RCDATA, fd_files[i], &res_size, FALSE);

        if (res_data != NULL) {
            if (!write_resource_to_file(dst, res_data, res_size)) {
                if (i < FD_ROOT_FILES) {
                    free(src_dir);
                    return FALSE;
                }
                uprintf("Warning: could not write embedded '%s' (optional)", fd_files[i]);
            } else {
                uprintf("Extracted '%s' from embedded resource", fd_files[i]);
            }
        } else {
            /* Fall back to disk */
            if (src_dir == NULL) {
                src_dir = get_freedos_source_dir();
                if (src_dir == NULL) {
                    uprintf("ExtractFreeDOS: no embedded data and no on-disk resource "
                            "directory found (checked %sres/freedos/)", app_dir);
                    if (i < FD_ROOT_FILES)
                        return FALSE;
                    continue;
                }
            }
            char src[MAX_PATH];
            snprintf(src, sizeof(src), "%s%s", src_dir, fd_files[i]);
            if (!copy_file(src, dst)) {
                if (i < FD_ROOT_FILES) {
                    free(src_dir);
                    return FALSE;
                }
                uprintf("Warning: could not copy '%s' (optional)", fd_files[i]);
            } else {
                uprintf("Extracted '%s' from disk", fd_files[i]);
            }
        }

        if ((i == 3) || (i == 9) || (i == 15) || (i == FD_NFILES - 1))
            UpdateProgress(OP_FILE_COPY, -1.0f);
    }

    free(src_dir);
    return SetDOSLocale(path, TRUE);
}

BOOL ExtractDOS(const char* path)
{
    switch (boot_type) {
    case BT_FREEDOS:
        return ExtractFreeDOS(path);
    default:
        return FALSE;
    }
}
