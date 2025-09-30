#pragma once

#include <windows.h>
#include <winternl.h>
#include <excpt.h>

#ifdef __cplusplus
extern "C" {
#endif

__forceinline PPEB GetPeb()
{
#ifdef _WIN64
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)__readfsdword(0x30);
#endif
}

typedef struct _LDR_DATA_TABLE_ENTRY_SYSCALLER {
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved1[2];
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_SYSCALLER, *PLDR_DATA_TABLE_ENTRY_SYSCALLER;

HMODULE FindNtdllBase();

#ifdef __cplusplus
}
#endif
