/* Linux compat stub for malloc.h (MSVC-specific functions) */
#pragma once
#ifndef _WIN32
#include <stdlib.h>
#include <string.h>
static inline void* _alloca(size_t n) { return __builtin_alloca(n); }
#define alloca __builtin_alloca
#ifndef _mm_malloc
#include <mm_malloc.h>
#endif
#endif
