/* Linux compat stub for intrin.h - MSVC/MinGW intrinsics */
#pragma once
#ifndef _WIN32
#include "windows.h"
#include <x86intrin.h>
/* Note: cpuid.h defines __cpuid/__cpuidex as macros on Linux - no need to redefine */
#include <cpuid.h>

#ifndef _BitScanForward
#define _BitScanForward(idx,v)  ({ unsigned long _i; _i=__builtin_ctz(v); *(idx)=_i; (v)!=0; })
#define _BitScanReverse(idx,v)  ({ unsigned long _i; _i=31-__builtin_clz(v); *(idx)=_i; (v)!=0; })
#define _BitScanForward64(i,v)  ({ unsigned long _i; _i=__builtin_ctzll(v); *(i)=_i; (v)!=0; })
#define _BitScanReverse64(i,v)  ({ unsigned long _i; _i=63-__builtin_clzll(v); *(i)=_i; (v)!=0; })
#endif
#ifndef _byteswap_ushort
#define _byteswap_ushort __builtin_bswap16
#define _byteswap_ulong  __builtin_bswap32
#define _byteswap_uint64 __builtin_bswap64
#endif
#ifndef __popcnt
#define __popcnt  __builtin_popcount
#define __popcnt64 __builtin_popcountll
#endif

#endif /* !_WIN32 */
