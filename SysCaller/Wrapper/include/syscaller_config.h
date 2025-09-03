#pragma once
#ifndef SYSCALLER_BUILD_CONFIG
#error "Do not include syscaller_config.h directly, use syscaller.h instead"
#endif

/*
 * SysCaller Build Configuration
 * 
 * Uncomment one of the following lines & add to preprocessor definitions to select your build mode:
 */

// Direct syscalls (default), no runtime resolution
#define SYSCALLER_DIRECT

// Indirect syscalls, runtime resolution
// #define SYSCALLER_INDIRECT

// Inline ASM syscalls, embedded assembly
// #define SYSCALLER_INLINE

/*
 * Optional: Uncomment if building for multi language bindings
 * This will include dllmain.cpp in the build
 */
// #define SYSCALLER_BINDINGS
