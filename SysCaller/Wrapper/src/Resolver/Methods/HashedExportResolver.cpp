#if defined(SYSCALLER_DIRECT)
#pragma message("SysCaller: Building via DIRECT syscall mode")
#elif defined(SYSCALLER_INDIRECT)
#pragma message("SysCaller: Building via INDIRECT syscall mode")
#elif defined(SYSCALLER_INLINE)
#pragma message("SysCaller: Building via INLINE ASM syscall mode")
#else
#pragma message("SysCaller: No build mode specified, defaulting to DIRECT")
#endif

#if defined(SYSCALLER_BINDINGS)
#pragma message("SysCaller: Building with BINDINGS support (DLL export)")
#endif

#ifdef SYSCALLER_INDIRECT
#ifdef SYSCALLER_RESOLVER_HASHED_EXPORT

#include <Resolver/ResolverBase.h>
#include <Resolver/Methods/HashedExportResolver.h>
#include <Resolver/PebUtils.h>

/* simple djb2 hash function for strings */
constexpr DWORD HashString(const char* str)
{
    DWORD hash = 5381;
    int c;
    while ((c = *str++))
    {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash;
}

/* known syscall name hashes */
static const DWORD knownSyscallHashes[] = {
    HashString("NtQuerySystemInformation")
};

static const size_t numKnownHashes = sizeof(knownSyscallHashes) / sizeof(knownSyscallHashes[0]);

DWORD HashStringRuntime(const char* str)
{
    DWORD hash = 5381;
    int c;
    while ((c = *str++))
    {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash;
}

bool IsKnownSyscallHash(DWORD hash)
{
    for (size_t i = 0; i < numKnownHashes; i++)
    {
        if (knownSyscallHashes[i] == hash)
        {
            return true;
        }
    }
    return false;
}

std::unordered_map<std::string, DWORD> ExtractSyscallsFromDllHashedInternal()
{
    std::unordered_map<std::string, DWORD> syscallNumbers;
    HMODULE hNtdll = GetNtdllHandleInternal();

    if (!hNtdll)
    {
        return syscallNumbers;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hNtdll;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return syscallNumbers;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return syscallNumbers;
    }

    if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
    {
        return syscallNumbers;
    }

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hNtdll +
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* functions = (DWORD*)((BYTE*)hNtdll + exportDir->AddressOfFunctions);
    DWORD* names = (DWORD*)((BYTE*)hNtdll + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)hNtdll + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
    {
        const char* funcName = (const char*)((BYTE*)hNtdll + names[i]);
        DWORD nameHash = HashStringRuntime(funcName);

        if (IsKnownSyscallHash(nameHash))
        {
            DWORD funcRVA = functions[ordinals[i]];
            LPVOID funcAddress = (LPVOID)((BYTE*)hNtdll + funcRVA);
            DWORD syscallNumber = ExtractSyscallNumber(funcAddress);

            if (syscallNumber > 0 && syscallNumber <= 0xFFFF)
            {
                syscallNumbers[funcName] = syscallNumber;
            }
        }
    }

    return syscallNumbers;
}

HMODULE GetNtdllHandleInternal()
{
    static HMODULE cachedNtdllHandle = NULL;

    if (cachedNtdllHandle == NULL)
    {
        cachedNtdllHandle = FindNtdllBase();

        if (cachedNtdllHandle == NULL)
        {
            /* peb traversal failed so this is a critical error, no fallback */
            return NULL;
        }
    }

    return cachedNtdllHandle;
}

#else
/* not using HashedExportResolver */
#pragma message("SysCaller: HashedExportResolver.cpp skipped (SYSCALLER_RESOLVER_HASHED_EXPORT not defined)")
#endif

#else
/* not in indirect mode file compiles to nothing */
#pragma message("SysCaller: HashedExportResolver.cpp skipped (SYSCALLER_INDIRECT not defined)")
#endif
