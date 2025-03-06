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

### Disclaimer

- **Passion Project**: This is an experimental project created for educational purposes.
- **Learning Tool**: SysCaller is intended to help users learn about Windows NT system calls and low level programming.
- **No Liability**: I am not responsible or liable for any actions taken using SysCaller.
- **Usage**: While I have personally used SysCaller for various purposes, including bypassing some AntiCheat systems for fun, I will not provide guidance on such activities.
- **Potential Applications**: There are many legitimate ways to utilize this library, and I encourage users to explore its capabilities responsibly.

![image](https://github.com/user-attachments/assets/ad00dadd-0f4a-45f8-b668-a269f62431b4)
