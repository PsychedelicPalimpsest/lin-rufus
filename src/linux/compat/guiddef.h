/* Linux compat stub for guiddef.h */
#pragma once
#ifndef _WIN32
#include "windows.h"
#endif

/* DEFINE_GUID: define or declare a named GUID constant.
 * When INITGUID is defined (in the one translation unit that "owns" the
 * definition), each DEFINE_GUID expands to a const definition.
 * Otherwise it expands to an extern declaration. */
#ifndef DEFINE_GUID
#  ifdef INITGUID
#    define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
         const GUID name = { l, w1, w2, { b1, b2, b3, b4, b5, b6, b7, b8 } }
#  else
#    define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
         extern const GUID name
#  endif
#endif
