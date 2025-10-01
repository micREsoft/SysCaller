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
#ifdef SYSCALLER_RESOLVER_PEB_LDR

#include <Resolver/ResolverBase.h>
#include <Resolver/Resolver.h>
#include <Resolver/PebUtils.h>

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
/* not using PEBLDRResolver */
#pragma message("SysCaller: PebLdrResolver.cpp skipped (SYSCALLER_RESOLVER_PEB_LDR not defined)")
#endif

#else
/* not in indirect mode file compiles to nothing */
#pragma message("SysCaller: PebLdrResolver.cpp skipped (SYSCALLER_INDIRECT not defined)")
#endif
