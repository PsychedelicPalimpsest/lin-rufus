/* Linux compat stub for malloc.h (MSVC-specific functions) */
#pragma once
#ifndef _WIN32
#include <stdlib.h>
#include <string.h>
static inline void* _alloca(size_t n) { return __builtin_alloca(n); }
#ifndef alloca
#define alloca __builtin_alloca
#endif
/* mm_malloc.h is an Intel/x86 header; on other architectures we provide
 * a minimal inline replacement for _mm_malloc / _mm_free. */
#ifndef _mm_malloc
# if defined(__x86_64__) || defined(__i386__)
#  include <mm_malloc.h>
# else
#  include <stdlib.h>
static inline void* _mm_malloc(size_t size, size_t align) {
    void* ptr = NULL;
    (void)posix_memalign(&ptr, align < sizeof(void*) ? sizeof(void*) : align, size);
    return ptr;
}
static inline void _mm_free(void* ptr) { free(ptr); }
# endif
#endif
#endif
