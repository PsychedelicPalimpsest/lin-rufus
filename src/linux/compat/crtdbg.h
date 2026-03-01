/* Linux compat stub for crtdbg.h - MSVC CRT debug */
#pragma once
#ifndef _WIN32
#define _CRTDBG_MAP_ALLOC
#define _CrtCheckMemory()
#define _CrtSetDbgFlag(f)
#define _CrtSetReportMode(t,m)
#define _CrtDumpMemoryLeaks()
#define _ASSERT(e)   ((void)(e))
#define _ASSERTE(e)  ((void)(e))
#endif
