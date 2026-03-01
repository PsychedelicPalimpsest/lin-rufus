/* Linux compat stub for process.h (MSVC process control) */
#pragma once
#ifndef _WIN32
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#define _getpid getpid
#define _exit   _exit
#define _execv  execv
#define _execve execve
#endif
