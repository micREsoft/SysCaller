# SysCaller Library

<p align="center">
  <img src="https://github.com/user-attachments/assets/ad00dadd-0f4a-45f8-b668-a269f62431b4" alt="SysCaller Logo" width="400"/>
</p>

## Overview

SysCaller is a robust wrapper for Windows NT system calls (syscalls) that provides direct access to the Windows NT API with added security and obfuscation benefits. By using direct syscalls instead of the standard Windows API functions, applications can bypass certain security monitoring tools and anticheat systems that hook into user mode API calls.

## Features

- **Direct Syscall Access**: Bypasses user mode API hooks by directly invoking syscalls
- **Comprehensive Coverage**: Includes wrappers for hundreds of NT system calls
- **Obfuscation Layer**: Hides syscall IDs and provides protection against static analysis
- **Cross Compatibility**: Works across different Windows versions (tested on Windows 10+ x64)
- **Easy Integration**: Simple to include in your projects with minimal dependencies
- **GUI/Build Tools**: Includes validation, compatibility checking, and GUI tools

## Getting Started

### Prerequisites

- **Windows 10+ (x64)**: The library is designed for 64 bit Windows systems (may work > Windows 10 )
- **Visual Studio** with MASM support (any recent version should work)
- **Python 3.8+**: Required for build tools (only during development)

### Building the Library

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/WindowsAPI/SysCaller.git
   cd SysCaller
   ```

2. **Configure the Project**:
   - Open the solution in Visual Studio
   - Make sure the build is set to `release` & `x64` configuration
   - Ensure MASM is enabled for assembly file compilation

3. **Run the BuildTools**:
   ```bash
   cd BuildTools
   pip install -r requirements.txt
   python syscaller.py
   ```
   - Use Option 1 to run validation checks
   - Use Option 2 to verify compatibility with your system
   - Use Option 3 to verify/xref func definitions
   - Use Option 4 to obfuscate your syscaller build
   - Use Option 5 to launch the GUI version of BuildTools (recommended)

4. **Build the Library**:
   - Build the solution to generate `SysCaller.lib`

### Integration

To use SysCaller in your project:

1. **Include the Library in your Project Settings**:
   - Add the SysCaller `Wrapper/include` directory to your project's include paths
   - Add the directory containing `SysCaller.lib` to your linker's library paths
   - Add `SysCaller.lib` to your linker's input dependencies

2. **Include the Header in your code**:
   ```cpp
   #include "syscaller.h"
   ```

3. **Use the `Sys` prefixed functions instead of Nt/Zw functions**:
   ```cpp
   // Instead of NtAllocateVirtualMemory
   SysAllocateVirtualMemory(processHandle, &baseAddress, 0, &regionSize, MEM_COMMIT, PAGE_READWRITE);
   
   // Instead of NtWriteVirtualMemory
   SysWriteVirtualMemory(processHandle, baseAddress, buffer, bufferSize, &bytesWritten);
   ```

## Usage Example

Here's a simple example demonstrating how to use SysCaller for DLL Injection using LoadLibA (check examples dir for entire code):

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

## Documentation

For detailed API documentation, please refer to the wrapper header files in the `Wrapper/include/Nt` directory. Each function is based on the Windows NT native API, and further information can be found at:

- [Windows Syscall Documentation](https://ntdoc.m417z.com/)
- Any file in the  `Nt` directory

## Contributing

Contributions are welcome! While this is primarily a passion project, I'm open to improvements and bug fixes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [NtDoc](https://ntdoc.m417z.com/) for the comprehensive Windows NT API documentation
- [Microsoft](https://microsoft.com/) for the Windows operating system

## Disclaimer

- **Educational Purpose**: SysCaller is created for educational and research purposes.
- **Legitimate Use**: While the library can be used to bypass certain security mechanisms, it is intended for legitimate security research, penetration testing, and software development.
- **No Liability**: The author is not responsible for any misuse of this library or any actions taken with it.
- **Legal Compliance**: Users must ensure they comply with all applicable laws and regulations when using this software.

---

<p align="center">
  <i>SysCaller - Bridging the gap between user mode and kernel mode</i>
</p> 
