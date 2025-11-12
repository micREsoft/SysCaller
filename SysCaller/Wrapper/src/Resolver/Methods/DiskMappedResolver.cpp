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
#ifdef SYSCALLER_RESOLVER_DISK_MAPPED

#include <Resolver/ResolverBase.h>
#include <Resolver/Resolver.h>

typedef struct _MAPPED_NTDLL_INFO {
    HANDLE hFile;
    HANDLE hMapping;
    LPVOID pMappedBase;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_EXPORT_DIRECTORY pExportDir;
} MAPPED_NTDLL_INFO, *PMAPPED_NTDLL_INFO;

PMAPPED_NTDLL_INFO MapNtdllFromDisk()
{
    static MAPPED_NTDLL_INFO mappedInfo = {0};
    static BOOL initialized = FALSE;

    if (initialized)
    {
        return &mappedInfo;
    }

    CHAR systemPath[MAX_PATH] = {0};
    if (GetSystemDirectoryA(systemPath, MAX_PATH) == 0)
    {
        return NULL;
    }

    CHAR ntdllPath[MAX_PATH] = {0};
    if (sprintf_s(ntdllPath, MAX_PATH, "%s\\ntdll.dll", systemPath) < 0)
    {
        return NULL;
    }

    mappedInfo.hFile = CreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ,
                                   NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (mappedInfo.hFile == INVALID_HANDLE_VALUE)
    {
        return NULL;
    }

    /* create file mapping */
    mappedInfo.hMapping = CreateFileMappingA(mappedInfo.hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (mappedInfo.hMapping == NULL)
    {
        CloseHandle(mappedInfo.hFile);
        return NULL;
    }

    /* map the file into memory */
    mappedInfo.pMappedBase = MapViewOfFile(mappedInfo.hMapping, FILE_MAP_READ, 0, 0, 0);
    if (mappedInfo.pMappedBase == NULL)
    {
        CloseHandle(mappedInfo.hMapping);
        CloseHandle(mappedInfo.hFile);
        return NULL;
    }

    /* validate PE headers */
    mappedInfo.pDosHeader = (PIMAGE_DOS_HEADER)mappedInfo.pMappedBase;
    if (mappedInfo.pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        UnmapViewOfFile(mappedInfo.pMappedBase);
        CloseHandle(mappedInfo.hMapping);
        CloseHandle(mappedInfo.hFile);
        return NULL;
    }

    mappedInfo.pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)mappedInfo.pMappedBase + mappedInfo.pDosHeader->e_lfanew);
    if (mappedInfo.pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        UnmapViewOfFile(mappedInfo.pMappedBase);
        CloseHandle(mappedInfo.hMapping);
        CloseHandle(mappedInfo.hFile);
        return NULL;
    }

    /* get export directory */
    if (mappedInfo.pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
    {
        UnmapViewOfFile(mappedInfo.pMappedBase);
        CloseHandle(mappedInfo.hMapping);
        CloseHandle(mappedInfo.hFile);
        return NULL;
    }

    mappedInfo.pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)mappedInfo.pMappedBase +
        mappedInfo.pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    initialized = TRUE;
    return &mappedInfo;
}

/* cleanup mapped file */
void UnmapNtdllFromDisk()
{
    static MAPPED_NTDLL_INFO mappedInfo = {0};
    static BOOL initialized = FALSE;

    if (!initialized)
    {
        /* check if we have mapped info */
        PMAPPED_NTDLL_INFO pInfo = MapNtdllFromDisk();
        if (!pInfo || !pInfo->pMappedBase) return;

        /* copy the info to our static variable */
        memcpy(&mappedInfo, pInfo, sizeof(MAPPED_NTDLL_INFO));
        initialized = TRUE;
    }

    if (mappedInfo.pMappedBase)
    {
        UnmapViewOfFile(mappedInfo.pMappedBase);
        mappedInfo.pMappedBase = NULL;
    }

    if (mappedInfo.hMapping)
    {
        CloseHandle(mappedInfo.hMapping);
        mappedInfo.hMapping = NULL;
    }

    if (mappedInfo.hFile)
    {
        CloseHandle(mappedInfo.hFile);
        mappedInfo.hFile = NULL;
    }
}

std::unordered_map<std::string, DWORD> ExtractSyscallsFromDllDiskMappedInternal()
{
    std::unordered_map<std::string, DWORD> syscallNumbers;

    /* map ntdll.dll from disk */
    PMAPPED_NTDLL_INFO pMappedInfo = MapNtdllFromDisk();
    if (!pMappedInfo || !pMappedInfo->pExportDir)
    {
        return syscallNumbers;
    }

    DWORD* functions = (DWORD*)((BYTE*)pMappedInfo->pMappedBase + pMappedInfo->pExportDir->AddressOfFunctions);
    DWORD* names = (DWORD*)((BYTE*)pMappedInfo->pMappedBase + pMappedInfo->pExportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)pMappedInfo->pMappedBase + pMappedInfo->pExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pMappedInfo->pExportDir->NumberOfNames; i++)
    {
        const char* funcName = (const char*)((BYTE*)pMappedInfo->pMappedBase + names[i]);

        if (strncmp(funcName, "Nt", 2) != 0 && strncmp(funcName, "Zw", 2) != 0)
        {
            continue;
        }

        DWORD funcRVA = functions[ordinals[i]];
        LPVOID funcAddress = (LPVOID)((BYTE*)pMappedInfo->pMappedBase + funcRVA);
        DWORD syscallNumber = ExtractSyscallNumber(funcAddress);

        if (syscallNumber > 0 && syscallNumber <= 0xFFFF)
        {
            syscallNumbers[funcName] = syscallNumber;
        }
    }

    return syscallNumbers;
}

/* (not needed for disk mapping but required by interface) */
HMODULE GetNtdllHandleInternal()
{
    /* return a dummy handle since we read from disk */
    return (HMODULE)0x1;
}

#else
/* not using Disk Mapped resolver */
#pragma message("SysCaller: DiskMappedResolver.cpp skipped (SYSCALLER_RESOLVER_DISK_MAPPED not defined)")
#endif

#else
/* not in indirect mode file compiles to nothing */
#pragma message("SysCaller: DiskMappedResolver.cpp skipped (SYSCALLER_INDIRECT not defined)")
#endif
