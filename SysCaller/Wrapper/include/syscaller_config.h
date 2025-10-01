#pragma once
#ifndef SYSCALLER_BUILD_CONFIG
#error "Do not include syscaller_config.h directly, use syscaller.h instead"
#endif

/*
 * SysCaller Build Configuration
 *
 * Uncomment one of the following lines & add to preprocessor definitions to select your build mode:
 */

/* Direct syscalls (default), no runtime resolution */
#define SYSCALLER_DIRECT

/* Indirect syscalls, runtime resolution */
// #define SYSCALLER_INDIRECT

/* Inline ASM syscalls, embedded assembly */
// #define SYSCALLER_INLINE

/*
 * Optional: Uncomment if building for multi language bindings
 * This will include dllmain.cpp in the build
 */
// #define SYSCALLER_BINDINGS

/*
 * Resolver Configuration (for SYSCALLER_INDIRECT mode)
 *
 * Choose one resolver method:
 */

/* Use PEB LDR traversal (no WinAPI calls) */
// #define SYSCALLER_RESOLVER_PEB_LDR

/* Use memory export parsing with GetModuleHandle (uses WinAPI to locate ntdll) */
// #define SYSCALLER_RESOLVER_MEMORY_EXPORT

/* Use hashed export parsing (no WinAPI calls) */
// #define SYSCALLER_RESOLVER_HASHED_EXPORT

/* Use disk mapped ntdll.dll parsing (uses WinAPI for I/O funcs not locating ntdll) */
// #define SYSCALLER_RESOLVER_DISK_MAPPED
