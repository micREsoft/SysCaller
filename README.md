# SysCaller SDK

*Windows Syscall SDK with dynamic offset resolution, validation, and obfuscation. — C++ primary, Rust, Python & others planned!*

<p align="center">
  <img src="https://github.com/user-attachments/assets/ad00dadd-0f4a-45f8-b668-a269f62431b4" alt="SysCaller Logo" width="400"/>
</p>

## Overview

SysCaller is a powerful SDK providing direct, low level access to Windows NT system calls (syscalls) across multiple languages.  
Bypassing traditional Windows API hooks, SysCaller enables stealthy and efficient syscall invocation for user-mode and kernel-mode development, with automatic offset validation and builtin obfuscation.

## Features

- **Direct Syscall Invocation**: Avoid user-mode API hooks by calling syscalls directly.
- **Extensive Coverage**: Hundreds of Nt/Zw syscalls. (Zw is currently still experimental!)
- **Dual Mode Operation**: Supports both Nt (user-mode) and Zw (kernel-mode) syscall variants.
- **Kernel Mode Driver Support**: Ideal for low level driver development via Zw syscalls.
- **Obfuscation Layer**: Optional but Conceals syscall IDs, hinders static analysis, and more.
- **Cross Version Compatibility**: Works & tested across Windows 10 and 11 (x64).
- **Easy Integration**: Minimal dependencies and straightforward project setup.
- **GUI Build Tools**: Validate, verify, and obfuscate syscalls through a clean user friendly interface.
- **Cross Language SDK**: Designed for C++ now, with planned bindings for Python, Rust, Go, and others.

## Getting Started

### Prerequisites

- **Windows 10+ (x64)**: The library is designed for 64-bit Windows systems
- **Visual Studio** with MASM support (any recent version should work)
- **Python 3.8+**: Required for GUI build tools (only during development)

### Building the Library

> **Important:** Before building, always run the BuildTools GUI to validate and update syscall offsets to match your system's `ntdll.dll` version.

### Option 1: Visual Studio 2022

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/WindowsAPI/SysCaller.git
   cd SysCaller
   ```

2. **Configure the Project**:
   - Open the solution in Visual Studio
   - Set the CPP std to your target projects version (e.g., 17+)
   - Make sure the build is set to `release` & `x64` configuration if not already
   - Ensure MASM is enabled for assembly file compilation if not already

3. **Run the BuildTools GUI**:
   ```bash
   cd BuildTools
   pip install -r requirements.txt
   python syscaller.py
   ```
   
   The GUI provides several functions:
   - **Validation Check**: Analyzes and updates syscall offsets against ntdll.dll
   - **Compatibility Check**: Verifies syscall compatibility with your system
   - **Verification Check**: Validates return types and parameter types
   - **Syscall Obfuscation**: Randomizes syscall names and adds protection
   - **Settings**: Configure syscall mode (Nt or Zw) and other options

4. **Build the Library**:
   - Make sure at the minimum you have ran the `Validation Check` in the PY BuildTools (recommended to run all integrity checks, obfuscation is optional)
   - Build the solution to generate `SysCaller.lib`

### Option 2: CMake (For CPP 17+)

1. **Update `CMakeLists.txt`**:
    - It can be found in the `Wrapper` directory
    - Open `CMakeLists.txt`
    - Modify this line to match your project’s C++ version (17, 20, 23, etc.)

    ```cmake
    set(CMAKE_CXX_STANDARD 20) # Change this to your target standard
    ```

3. **Run CMake Build**:

    ```bash
    cd Wrapper
    mkdir build && cd build
    cmake .. -A x64
    cmake --build . --config Release
    ```

4. **Result**:
    - The `SysCaller.lib` static library will be generated in `Wrapper/build/Release`

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

3. **Use the `Sys` prefixed functions for Nt syscalls or `SysK` for Zw syscalls**:
   ```cpp
   // For user mode (Nt syscalls)
   SysAllocateVirtualMemory(processHandle, &baseAddress, 0, &regionSize, MEM_COMMIT, PAGE_READWRITE);
   
   // For kernel mode (Zw syscalls)
   SysKAllocateVirtualMemory(processHandle, &baseAddress, 0, &regionSize, MEM_COMMIT, PAGE_READWRITE);
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

For detailed API documentation, please refer to the wrapper header files in the `Wrapper/include/Sys` directory. Each function is based on the Windows NT native API, and further information can be found at:

- [Windows Syscall Documentation](https://ntdoc.m417z.com/)
- Any file in the `Sys` directory

## Future Development

- **Cross/Multi Language Support**: Upcoming bindings for multiple programming languages:
  - Rust
  - Python
  - Go
  - And more...

## Contributing

Contributions are welcome! While this is primarily a passion project, I'm open to improvements and bug fixes.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [NtDoc](https://ntdoc.m417z.com/) for the comprehensive Windows NT API documentation
- [Microsoft](https://microsoft.com/) for the Windows operating system

## Disclaimer

- **Educational Purpose**: SysCaller is created for educational and research purposes.
- **Legitimate Use**: While the library can be used to bypass certain security mechanisms, it is intended for legitimate security research, penetration testing, and software development.
- **No Liability**: The author or any contributors are not responsible for any misuse of this library or any actions taken with it.
- **Legal Compliance**: Users must ensure they comply with all applicable laws and regulations when using this software.

---

<p align="center">
  <i>SysCaller - Bridging the gap between user mode and kernel mode</i>
</p> 
