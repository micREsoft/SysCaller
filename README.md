# SysCaller Library

## Overview

The SysCaller Library is a powerful and flexible wrapper for Windows NT system calls, designed to simplify the process of interacting with low level system functions. This library provides a set of functions that allow developers to perform various system level operations, such as process management, memory management, and security checks.

## Features

- **Comprehensive API**: Access all the NT system calls through a simple and intuitive interface.
- **Cross Platform Compatibility**: Designed to work seamlessly on Windows 10/11 64 bit systems. (Tested that Win7 is compatible not recommended!)
- **Easy Integration**: Simple to include and link in your projects, with minimal setup required.
- **Extensive Documentation**: Detailed API documentation and usage examples to help you get started quickly.

## Getting Started

### Prerequisites

- Visual Studio 2022 or later (Will make custom Cmake build soon!)
- C++ 20
- Tested Windows 7+ x64
- Python 3.8.10+ (For build tools)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/WindowsAPI/SysCaller.git
   cd SysCaller
   ```

2. Build the library:
   - Open the project in `Visual Studio`.
   - Change the `configuration type` to `"Static Library"` if not already set.
   - Make sure build is set to `x64` and `Release Mode`.
   - run `pip install -r requirements.txt`.
   - Naviate to the `Check` dir and run `syscaller.py `.
   - Run Option 1. / Validation Check first
   - Run Option 2. / Compatibility Check to see if it was successful.
   - Build the SysCaller project to generate the `SysCaller.lib` file.

3. Include the library in your project:
   - Add the SysCaller `include` path to `C/C++ -> General -> Additional Include Directories`.
   - Add the dir that has `SysCaller.lib` to in `Linker -> General -> Additional Library Directories`.
   - Add `SysCaller.lib` to `Linker -> Input -> Additional Dependencies` .
   - Now you can `#include "syscaller.h"` in your project and start using SysCaller.

### Usage Example

Heres a simple example of how to use the SysCaller Library:

```cpp
#include "bypass.h"
#include <iostream>
#include <sstream>
#include <iomanip>

#define THREAD_ACCESS (THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION)

Bypass::Bypass(DWORD pid) : processPID(pid) {
    OBJECT_ATTRIBUTES objAttr = { 0 };
    InitializeObjectAttributes(&objAttr, nullptr, 0, nullptr, nullptr);
    CLIENT_ID clientId = { 0 };
    clientId.UniqueProcess = (HANDLE)(DWORD_PTR)pid;
    clientId.UniqueThread = nullptr;
    NTSTATUS status = SysOpenProcess(
        &processHandle,
        PROCESS_ALL_ACCESS,
        &objAttr,
        &clientId
    );
    if (!NT_SUCCESS(status)) {
        Log("Failed to open process. Status: " + std::to_string(status));
        processHandle = nullptr;
    }
}
Bypass::~Bypass() {
    if (processHandle) {
        CloseHandle(processHandle);
    }
}

void Bypass::Log(const std::string& message) {
    std::cout << "[*] " << message << std::endl;
}

bool Bypass::LoadLibraryInj(const std::wstring& dllPath) {
    try {
        Log("Starting LoadLibraryA injection...");
        std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            Log("Failed to open DLL file");
            return false;
        }
        size_t dllSize = file.tellg();
        Log("DLL size: " + std::to_string(dllSize) + " bytes");
        std::string ansiPath(dllPath.begin(), dllPath.end());
        size_t pathSize = ansiPath.length() + 1;
        PVOID pathAddress = (PVOID)0x30000000;
        SIZE_T pathAllocSize = pathSize;
        NTSTATUS status = SysAllocateVirtualMemory(
            processHandle,
            &pathAddress,
            0,
            &pathAllocSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (!NT_SUCCESS(status)) {
            Log("Failed to allocate memory for DLL path. Status: " + std::to_string(status));
            return false;
        }
        std::stringstream ss;
        ss << "Allocated DLL path memory at: 0x" << std::hex << std::uppercase << (DWORD64)pathAddress;
        Log(ss.str());
        SIZE_T bytesWritten;
        status = SysWriteVirtualMemory(
            processHandle,
            pathAddress,
            (PVOID)ansiPath.c_str(),
            pathSize,
            &bytesWritten
        );
        if (!NT_SUCCESS(status)) {
            Log("Failed to write DLL path. Status: " + std::to_string(status));
            return false;
        }
        HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
        if (!kernel32) {
            Log("Failed to get kernel32.dll handle");
            return false;
        }
        PVOID loadLibraryAddr = GetProcAddress(kernel32, "LoadLibraryA");
        if (!loadLibraryAddr) {
            Log("Failed to get LoadLibraryA address");
            return false;
        }
        ss.str("");
        ss << "LoadLibraryA address: 0x" << std::hex << std::uppercase << (DWORD64)loadLibraryAddr;
        Log(ss.str());
        std::vector<unsigned char> shellcode = {
            0x48, 0x83, 0xEC, 0x28,             // sub rsp, 0x28
            0x48, 0xB9                          // mov rcx,
        };
        DWORD64 pathAddr = (DWORD64)pathAddress;
        shellcode.insert(shellcode.end(),
            (unsigned char*)&pathAddr,
            (unsigned char*)&pathAddr + 8);
        shellcode.push_back(0x48);
        shellcode.push_back(0xB8);              // mov rax,
        DWORD64 loadLibAddr = (DWORD64)loadLibraryAddr;
        shellcode.insert(shellcode.end(),
            (unsigned char*)&loadLibAddr,
            (unsigned char*)&loadLibAddr + 8);
        std::vector<unsigned char> endCode = {
            0xFF, 0xD0,                         // call rax
            0x48, 0x83, 0xC4, 0x28,            // add rsp, 0x28
            0xC3                                // ret
        };
        shellcode.insert(shellcode.end(), endCode.begin(), endCode.end());
        PVOID shellcodeAddress = nullptr;
        SIZE_T shellcodeSize = shellcode.size();
        status = SysAllocateVirtualMemory(
            processHandle,
            &shellcodeAddress,
            0,
            &shellcodeSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (!NT_SUCCESS(status)) {
            Log("Failed to allocate memory for shellcode. Status: " + std::to_string(status));
            return false;
        }
        ss.str("");
        ss << "Allocated shellcode memory at: 0x" << std::hex << std::uppercase << (DWORD64)shellcodeAddress;
        Log(ss.str());
        status = SysWriteVirtualMemory(
            processHandle,
            shellcodeAddress,
            shellcode.data(),
            shellcode.size(),
            &bytesWritten
        );
        if (!NT_SUCCESS(status)) {
            Log("Failed to write shellcode. Status: " + std::to_string(status));
            return false;
        }
        HANDLE threadHandle = nullptr;
        status = SysCreateThreadEx(
            &threadHandle,
            THREAD_ALL_ACCESS,
            nullptr,
            processHandle,
            (PUSER_THREAD_START_ROUTINE)shellcodeAddress,
            nullptr,
            0,
            0,
            0,
            0,
            nullptr
        );
        if (!NT_SUCCESS(status)) {
            Log("Failed to create remote thread. Status: " + std::to_string(status));
            return false;
        }
        Log("Created remote thread successfully");
        LARGE_INTEGER timeout;
        timeout.QuadPart = -50000000;
        status = SysWaitForSingleObject(threadHandle, FALSE, &timeout);
        if (!NT_SUCCESS(status)) {
            Log("Thread wait failed. Status: " + std::to_string(status));
        }
        SysClose(threadHandle);
        Log("Injection completed successfully!");
        return true;
    }
    catch (...) {
        Log("Exception during LoadLibraryA injection");
        return false;
    }
}
```

### API Documentation

For detailed API documentation, please refer to the [API Documentation](#). (Coming soon until then refer to [NtDoc](https://ntdoc.m417z.com/) or check `sysNtFunctions.cpp` !)

### Contributing

Contributions will be welcome soon! If you want to contribute or had plans to please be on the lookout for more information!

### License

This project is licensed under the MIT License see the [LICENSE](https://github.com/WindowsAPI/SysCaller/blob/main/LICENSE) file for details.

## Acknowledgments

Thanks to:
+ [NtDoc](https://ntdoc.m417z.com/)

+ [Pekora](https://pekora.zip/)

+ [Microsoft](https://microsoft.com/)

- The community for their support and feedback.

### Disclaimer

- **Passion Project**: This is an experimental project created for educational purposes.
- **Learning Tool**: SysCaller is intended to help users learn about Windows NT system calls and low level programming.
- **No Liability**: I am not responsible or liable for any actions taken using SysCaller.
- **Usage**: While I have personally used SysCaller for various purposes, including bypassing some AntiCheat systems for fun, I will not provide guidance on such activities.
- **Potential Applications**: There are many legitimate ways to utilize this library, and I encourage users to explore its capabilities responsibly.

![image](https://github.com/user-attachments/assets/ad00dadd-0f4a-45f8-b668-a269f62431b4)
