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
#ifdef SYSCALLER_RESOLVER_MEMORY_EXPORT

#include <Resolver/ResolverBase.h>
#include <Resolver/Methods/MemoryExportResolver.h>

HMODULE GetNtdllHandleInternal()
{
    static HMODULE cachedNtdllHandle = NULL;

    if (cachedNtdllHandle == NULL)
    {
        cachedNtdllHandle = GetModuleHandleA("ntdll.dll");

        if (cachedNtdllHandle == NULL)
        {
            cachedNtdllHandle = LoadLibraryA("ntdll.dll");
        }
    }

    return cachedNtdllHandle;
}

#else
/* not using MemoryExportResolver */
#pragma message("SysCaller: MemoryExportResolver.cpp skipped (SYSCALLER_RESOLVER_MEMORY_EXPORT not defined)")
#endif

#else
/* not in indirect mode file compiles to nothing */
#pragma message("SysCaller: MemoryExportResolver.cpp skipped (SYSCALLER_INDIRECT not defined)")
#endif
