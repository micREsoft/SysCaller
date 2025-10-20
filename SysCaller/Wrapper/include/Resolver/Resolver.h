#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winternl.h>

#ifdef __cplusplus
extern "C" {
#endif

DWORD GetSyscallNumber(const char* functionName);

BOOL InitializeResolver();

void CleanupResolver();

#ifdef __cplusplus
}
#endif
