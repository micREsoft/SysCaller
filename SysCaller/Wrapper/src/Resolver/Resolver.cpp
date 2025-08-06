#include "../../include/Resolver/Resolver.h"
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <string>
#include <unordered_map>
#include <vector>

static std::unordered_map<std::string, DWORD> syscallCache;
static HMODULE ntdllHandle = NULL;
static BOOL resolverInitialized = FALSE;

HMODULE GetNtdllHandle() {
    if (ntdllHandle == NULL) {
        ntdllHandle = GetModuleHandleA("ntdll.dll");
        if (ntdllHandle == NULL) {
            ntdllHandle = LoadLibraryA("ntdll.dll");
        }
    }
    return ntdllHandle;
}

DWORD ExtractSyscallNumber(LPVOID functionAddress) {
    if (functionAddress == NULL) {
        return 0;
    }
    BYTE* bytes = (BYTE*)functionAddress;
    for (int i = 0; i < 64; i++) {
        if (bytes[i] == 0xB8) {
            DWORD syscallNumber = *(DWORD*)(&bytes[i + 1]);
            if (syscallNumber <= 0xFFFF) {
                return syscallNumber;
            }
        }
    }
    return 0;
}

std::unordered_map<std::string, DWORD> ExtractSyscallsFromDll() {
    std::unordered_map<std::string, DWORD> syscallNumbers;
    HMODULE hNtdll = GetNtdllHandle();
    if (!hNtdll) {
        return syscallNumbers;
    }
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return syscallNumbers;
    }
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return syscallNumbers;
    }
    if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
        return syscallNumbers;
    }
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hNtdll + 
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* functions = (DWORD*)((BYTE*)hNtdll + exportDir->AddressOfFunctions);
    DWORD* names = (DWORD*)((BYTE*)hNtdll + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)hNtdll + exportDir->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* funcName = (const char*)((BYTE*)hNtdll + names[i]);
        if (strncmp(funcName, "Nt", 2) != 0 && strncmp(funcName, "Zw", 2) != 0) {
            continue;
        }
        DWORD funcRVA = functions[ordinals[i]];
        LPVOID funcAddress = (LPVOID)((BYTE*)hNtdll + funcRVA);        
        DWORD syscallNumber = ExtractSyscallNumber(funcAddress);
        if (syscallNumber > 0 && syscallNumber <= 0xFFFF) {
            syscallNumbers[funcName] = syscallNumber;
        }
    }
    return syscallNumbers;
}

BOOL InitializeResolver() {
    if (resolverInitialized) {
        return TRUE;
    }
    syscallCache = ExtractSyscallsFromDll();
    if (syscallCache.empty()) {
        return FALSE;
    }
    resolverInitialized = TRUE;
    return TRUE;
}

DWORD GetSyscallNumber(const char* functionName) {
    if (!resolverInitialized) {
        if (!InitializeResolver()) {
            return 0;
        }
    }
    auto it = syscallCache.find(functionName);
    if (it != syscallCache.end()) {
        return it->second;
    }
    return 0;
}

void CleanupResolver() {
    syscallCache.clear();
    resolverInitialized = FALSE;
}
