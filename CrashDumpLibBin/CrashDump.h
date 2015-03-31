#pragma once
#include <Windows.h>

#ifdef _CRASH_DUMP_DLL
#define _CRASH_DUMP_API __declspec(dllexport)
#else 
#define _CRASH_DUMP_API __declspec(dllimport)
#endif

EXTERN_C _CRASH_DUMP_API void SetGlobalCrashDump();