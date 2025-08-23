#if defined(SYSCALLER_DIRECT)
#pragma message("SysCaller: Building via DIRECT syscall mode")
#elif defined(SYSCALLER_INDIRECT)
#pragma message("SysCaller: Building via INDIRECT syscall mode")
#elif defined(SYSCALLER_INLINE)
#pragma message("SysCaller: Building via INLINE ASM syscall mode")
#else
#pragma message("SysCaller: Building via DIRECT syscall mode (default)")
#endif

#if defined(SYSCALLER_BINDINGS)
#pragma message("SysCaller: Building with BINDINGS support (DLL export)")
#endif

#ifdef SYSCALLER_BINDINGS
// Bindings mode enabled, include DLL export functionality
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    return TRUE;
}

#else
// Not in bindings mode file compiles to nothing
#pragma message("SysCaller: dllmain.cpp skipped (SYSCALLER_BINDINGS not defined)")
#endif
