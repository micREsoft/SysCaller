#include <Resolver/ResolverBase.h>
#include <string>
#include <unordered_map>

/* shared global state */
static std::unordered_map<std::string, DWORD> syscallCache;
static HMODULE ntdllHandle = NULL;
static BOOL resolverInitialized = FALSE;
static CRITICAL_SECTION resolverLock;

HMODULE GetNtdllHandleInternal();
std::unordered_map<std::string, DWORD> ExtractSyscallsFromDllInternal();

/* initialize the critical section for thread safety */
void InitializeResolverLock()
{
    static BOOL lockInitialized = FALSE;
    if (!lockInitialized)
    {
        InitializeCriticalSection(&resolverLock);
        lockInitialized = TRUE;
    }
}

DWORD ExtractSyscallNumber(LPVOID functionAddress)
{
    if (functionAddress == NULL)
    {
        return 0;
    }

    BYTE* bytes = (BYTE*)functionAddress;

    for (int i = 0; i < 64; i++)
    {
        if (bytes[i] == 0xB8)
        {
            DWORD syscallNumber = *(DWORD*)(&bytes[i + 1]);

            if (syscallNumber <= 0xFFFF)
            {
                return syscallNumber;
            }
        }
    }

    return 0;
}

std::unordered_map<std::string, DWORD> ExtractSyscallsFromDllInternal()
{
#if defined(SYSCALLER_RESOLVER_HASHED_EXPORT)
    /* forward declaration for the hashed resolver implementation */
    std::unordered_map<std::string, DWORD> ExtractSyscallsFromDllHashedInternal();
    return ExtractSyscallsFromDllHashedInternal();
#elif defined(SYSCALLER_RESOLVER_DISK_MAPPED)
    /* forward declaration for the disk mapped resolver implementation */
    std::unordered_map<std::string, DWORD> ExtractSyscallsFromDllDiskMappedInternal();
    return ExtractSyscallsFromDllDiskMappedInternal();
#else
    /* default implementation for other resolver methods */
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

        if (strncmp(funcName, "Nt", 2) != 0 && strncmp(funcName, "Zw", 2) != 0)
        {
            continue;
        }

        DWORD funcRVA = functions[ordinals[i]];
        LPVOID funcAddress = (LPVOID)((BYTE*)hNtdll + funcRVA);
        DWORD syscallNumber = ExtractSyscallNumber(funcAddress);

        if (syscallNumber > 0 && syscallNumber <= 0xFFFF)
        {
            syscallNumbers[funcName] = syscallNumber;
        }
    }

    return syscallNumbers;
#endif
}

BOOL InitializeResolver()
{
    /* ensure the lock is initialized */
    InitializeResolverLock();

    /* first check if already initialized (without lock for performance) */
    if (resolverInitialized)
    {
        return TRUE;
    }

    /* acquire lock for initialization */
    EnterCriticalSection(&resolverLock);

    /* double check to see if another thread has initialized while we waited */
    if (resolverInitialized)
    {
        LeaveCriticalSection(&resolverLock);
        return TRUE;
    }

    /* clear the cache first to prevent destructor issues with corrupted state */
    syscallCache.clear();
    syscallCache = ExtractSyscallsFromDllInternal();

    if (syscallCache.empty())
    {
        LeaveCriticalSection(&resolverLock);
        return FALSE;
    }

    resolverInitialized = TRUE;
    LeaveCriticalSection(&resolverLock);
    return TRUE;
}

DWORD GetSyscallNumber(const char* functionName)
{
    if (!resolverInitialized)
    {
        if (!InitializeResolver())
        {
            return 0;
        }
    }

    auto it = syscallCache.find(functionName);

    if (it != syscallCache.end())
    {
        return it->second;
    }

    return 0;
}

void CleanupResolver()
{
    /* ensure the lock is initialized */
    InitializeResolverLock();

    EnterCriticalSection(&resolverLock);
    syscallCache.clear();
    resolverInitialized = FALSE;
    LeaveCriticalSection(&resolverLock);

#if defined(SYSCALLER_RESOLVER_DISK_MAPPED)
    /* cleanup disk mapped resources */
    extern void UnmapNtdllFromDisk();
    UnmapNtdllFromDisk();
#endif
}
