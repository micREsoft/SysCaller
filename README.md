# SysCaller Library

## Overview

The SysCaller Library is a powerful and flexible wrapper for Windows NT system calls, designed to simplify the process of interacting with low level system functions. This library provides a set of functions that allow developers to perform various system level operations, such as process management, memory management, and security checks.

## Features

- **Comprehensive API**: Access all the NT system calls through a simple and intuitive interface.
- **Cross Platform Compatibility**: Designed to work seamlessly on Windows 10/11 64 bit systems.
- **Easy Integration**: Simple to include and link in your projects, with minimal setup required.
- **Extensive Documentation**: Detailed API documentation and usage examples to help you get started quickly.

## Getting Started

### Prerequisites

- Visual Studio 2022 or later (Will make custom Cmake build soon!)
- C++ 20
- Windows 10/11 x64 (Windows 7 support soon!)
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
   - Naviate to the `Check/Validator` dir and run `valid.py `.
   - Check if it was successful by running `compatibility.py` in `Check/Compatibility`.
   - Build the SysCaller project to generate the `SysCaller.lib` file.

3. Include the library in your project:
   - Add the SysCaller `include` path to `C/C++ -> General -> Additional Include Directories`.
   - Add the dir that has `SysCaller.lib` to in `Linker -> General -> Additional Library Directories`.
   - Add `SysCaller.lib` to `Linker -> Input -> Additional Dependencies` .
   - Now you can `#include "syscaller.h"` in your project and start using SysCaller.

### Usage Example

Heres a simple example of how to use the SysCaller Library:

```cpp
// Snippet to find Process by name
DWORD GetProcessIdByName(const wchar_t* processName) {
    DWORD procId = 0;
    ULONG bufferSize = 0;
    NTSTATUS status = SysQuerySystemInformation(
        SystemProcessInformation,
        nullptr,
        0,
        &bufferSize
    );
    std::vector<BYTE> buffer(bufferSize);
    status = SysQuerySystemInformation(
        SystemProcessInformation,
        buffer.data(),
        bufferSize,
        &bufferSize
    );
    if (!NT_SUCCESS(status)) return 0;
    PSYSTEM_PROCESS_INFO processInfo = (PSYSTEM_PROCESS_INFO)buffer.data();
    while (true) {
        if (processInfo->ImageName.Buffer && 
            _wcsicmp(processInfo->ImageName.Buffer, processName) == 0) {
            procId = (DWORD)(DWORD_PTR)processInfo->UniqueProcessId;
            break;
        }
        if (processInfo->NextEntryOffset == 0) break;
        processInfo = (PSYSTEM_PROCESS_INFO)((BYTE*)processInfo + processInfo->NextEntryOffset);
    }
    return procId;
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
