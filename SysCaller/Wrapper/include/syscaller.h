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
#include "Resolver/Resolver.h"
