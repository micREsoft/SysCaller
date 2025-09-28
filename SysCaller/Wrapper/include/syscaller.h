#pragma once

/*
 * SysCaller SDK
 * Copyright (c) 2025 micREsoft
 *
 * License: GPLv3
 *
 * This software is free to use, modify, and distribute under the terms
 * of the GNU General Public License version 3.
 *
 * You MAY NOT sell this software or derivative versions without also releasing
 * their full source code under the same license.
 *
 * For more information, see https://www.gnu.org/licenses/gpl-3.0.html
 */

 /*
 * SysCaller Build Configuration
 * 
 * Define one of these macros in syscaller_config.h:
 * - SYSCALLER_DIRECT   : Direct syscalls (default if none specified)
 * - SYSCALLER_INDIRECT : Indirect syscalls with runtime resolution
 * - SYSCALLER_INLINE   : Inline ASM syscalls
 * 
 * Optional: Define SYSCALLER_BINDINGS if building for multi language bindings
 * 
 * Examples:
 * - Direct syscalls (C++ only): SYSCALLER_DIRECT
 * - Direct syscalls (bindings): SYSCALLER_DIRECT;SYSCALLER_BINDINGS  
 * - Indirect syscalls (C++ only): SYSCALLER_INDIRECT
 * - Indirect syscalls (bindings): SYSCALLER_INDIRECT;SYSCALLER_BINDINGS
 * - Inline syscalls (C++ only): SYSCALLER_INLINE
 * - Inline syscalls (bindings): SYSCALLER_INLINE;SYSCALLER_BINDINGS
 * 
 */

#define SYSCALLER_BUILD_CONFIG
#include "syscaller_config.h"
#undef SYSCALLER_BUILD_CONFIG

#if !defined(SYSCALLER_DIRECT) && !defined(SYSCALLER_INDIRECT) && !defined(SYSCALLER_INLINE)
#define SYSCALLER_DIRECT
#endif

#if (defined(SYSCALLER_DIRECT) && defined(SYSCALLER_INDIRECT)) || \
    (defined(SYSCALLER_DIRECT) && defined(SYSCALLER_INLINE)) || \
    (defined(SYSCALLER_INDIRECT) && defined(SYSCALLER_INLINE))
#error "Only one syscall mode can be defined: SYSCALLER_DIRECT, SYSCALLER_INDIRECT, or SYSCALLER_INLINE"
#endif

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#ifdef _WIN64
#define _AMD64_
#endif

#include <sdkddkver.h>
#include <WinSock2.h>
#include <Windows.h>
#include <winhttp.h>
#include <ws2tcpip.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <ntstatus.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")

#include <cstdint>
#include <string>
#include <vector>
#include <fstream>

#include "Sys/sysTypes.h"
#include "Sys/sysExternals.h"
#include "Sys/sysFunctions.h"

#if defined(SYSCALLER_INDIRECT)
#include "Resolver/Resolver.h"
#endif