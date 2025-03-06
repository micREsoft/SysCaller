#pragma once
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
#include "Nt/sysNtTypes.h"
#include "Nt/sysNtExternals.h"
#include "Nt/sysNtFunctions.h"
