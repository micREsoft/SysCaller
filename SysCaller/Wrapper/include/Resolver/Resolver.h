#pragma once

#include <windows.h>
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
