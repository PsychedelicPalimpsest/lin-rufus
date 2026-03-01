/*
 * Rufus: The Reliable USB Formatting Utility
 * polkit privilege elevation helper — Linux port
 * Copyright © 2025 Rufus contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "polkit.h"

/* Candidate paths for pkexec, tried in order */
static const char * const pkexec_candidates[] = {
    "/usr/bin/pkexec",
    "/usr/local/bin/pkexec",
    "/bin/pkexec",
    NULL
};

int rufus_needs_elevation(void)
{
    return (geteuid() != 0);
}

/*
 * Find pkexec by trying the candidate list.
 * Returns a pointer to the first usable path, or NULL if none found.
 * The returned pointer is into the static array — do not free.
 */
static const char *find_pkexec(void)
{
    for (int i = 0; pkexec_candidates[i] != NULL; i++) {
        if (access(pkexec_candidates[i], X_OK) == 0)
            return pkexec_candidates[i];
    }
    return NULL;
}

char **rufus_build_pkexec_argv(const char *pkexec_path,
                               const char *exe_path,
                               char * const extra_argv[],
                               int extra_argc)
{
    /* argv layout: pkexec_path, exe_path, extra_argv[0..extra_argc-1], NULL */
    int total = 2 + (extra_argc > 0 ? extra_argc : 0) + 1;
    char **argv = calloc((size_t)total, sizeof(char *));
    if (!argv)
        return NULL;

    argv[0] = (char *)pkexec_path;
    argv[1] = (char *)exe_path;
    for (int i = 0; i < extra_argc; i++)
        argv[2 + i] = extra_argv[i];
    argv[total - 1] = NULL;
    return argv;
}

void rufus_free_pkexec_argv(char **argv)
{
    free(argv);
}

int rufus_try_pkexec(int argc, char *argv[])
{
    char exe_path[1024];
    ssize_t len;
    const char *pkexec;
    char **new_argv;

    /* Resolve our own executable path */
    len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len <= 0) {
        fprintf(stderr, "rufus: could not resolve executable path\n");
        return 1;
    }
    exe_path[len] = '\0';

    pkexec = find_pkexec();
    if (!pkexec) {
        fprintf(stderr, "rufus: pkexec not found — cannot re-launch with elevated privileges\n");
        return 1;
    }

    /* Forward all command-line args after argv[0] */
    new_argv = rufus_build_pkexec_argv(pkexec, exe_path,
                                       argc > 1 ? argv + 1 : NULL,
                                       argc > 1 ? argc - 1 : 0);
    if (!new_argv) {
        fprintf(stderr, "rufus: out of memory during pkexec re-launch\n");
        return 1;
    }

    /* Replace current process image — does not return on success */
    execv(pkexec, new_argv);

    /* execv returned — something went wrong */
    perror("rufus: execv pkexec");
    rufus_free_pkexec_argv(new_argv);
    return 1;
}
