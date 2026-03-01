/* Linux compat stub for crtdefs.h */
#pragma once
#ifndef _WIN32
#include <stddef.h>
#include <stdint.h>
typedef size_t    rsize_t;
typedef intptr_t  intptr_t;
typedef wchar_t   wint_t;
#endif
