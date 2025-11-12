/*
 * SysCaller Build Information
 * this file is always compiled to show the current build configuration
 */

#if defined(SYSCALLER_DIRECT)
#pragma message("[SysCaller] Build Mode: DIRECT syscalls")
#elif defined(SYSCALLER_INDIRECT)
#pragma message("[SysCaller] Build Mode: INDIRECT syscalls (runtime resolver)")
#elif defined(SYSCALLER_INLINE)
#pragma message("[SysCaller] Build Mode: INLINE ASM syscalls")
#else
#pragma message("[SysCaller] Build Mode: DEFAULTING to DIRECT")
#endif

#if defined(SYSCALLER_BINDINGS)
#pragma message("[SysCaller] Bindings: ENABLED (building as DLL with exports)")
#else
#pragma message("[SysCaller] Bindings: DISABLED (building as static library)")
#endif

#if defined(SYSCALLER_INDIRECT)
#pragma message("[SysCaller] Resolver: INCLUDED (indirect mode requires resolver.cpp/.h)")
#else
#pragma message("[SysCaller] Resolver: SKIPPED (not required for direct/inline)")
#endif

#include <SysCaller.h>

/* empty function ensures this TU is compiled and processed */
void SysCallerBuildInfo() {}