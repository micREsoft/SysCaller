#pragma once

#include <windows.h>
#include <winternl.h>
#include <string>
#include <unordered_map>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief resolves a syscall number by function name at runtime
 * @param functionName the name of the Nt/Zw function
 * @return the syscall number or -1 if not found
 */
DWORD GetSyscallNumber(const char* functionName);

/**
 * @brief initializes the resolver (optional, called automatically on first use)
 * @return TRUE if successful or FALSE otherwise
 */
BOOL InitializeResolver();

/**
 * @brief cleans up resolver resources (optional)
 */
void CleanupResolver();

#ifdef __cplusplus
}
#endif

/* internal functions for resolver methods */
HMODULE GetNtdllHandleInternal();
std::unordered_map<std::string, DWORD> ExtractSyscallsFromDllInternal();
DWORD ExtractSyscallNumber(LPVOID functionAddress);
