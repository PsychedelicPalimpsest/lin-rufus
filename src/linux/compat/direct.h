/* Linux compat stub for direct.h */
#pragma once
#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#define _mkdir(p)   mkdir(p, 0755)
#define _chdir      chdir
#define _getcwd     getcwd
#define _rmdir      rmdir
#endif
