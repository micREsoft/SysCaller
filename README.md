# SysCaller SDK

<p align="center">
  <img src="https://github.com/user-attachments/assets/243f7fe5-b461-460d-8c38-3858512e90de" alt="SysCaller Logo" width="400"/>
</p>

<p align="center">
  <b>Windows Syscall SDK with dynamic offset resolution, validation, and obfuscation</b><br>
  <i>Direct syscall access across Windows versions with ease</i>
</p>

<p align="center">
  <a href="#key-features">Features</a> •
  <a href="#technical-overview">Overview</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#documentation">Documentation</a> •
  <a href="#considerations">Considerations</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a> •
  <a href="#disclaimer">Disclaimer</a>
</p>

## Key Features

- **Direct Syscall Access**: Bypass Windows API hooks by communicating directly with the NT kernel
- **Dual Mode Operation**: Support for both `Nt` (user-mode) and `Zw` (kernel-mode) syscalls (Zw is still experimental!)
- **Dynamic Offset Resolution**: Automatic syscall ID detection for compatibility across Windows versions
- **Advanced Protection**: Optional obfuscation layer to conceal syscall patterns and evade detection
- **Comprehensive GUI Tools**: Validate, verify, and protect syscalls through an intuitive interface
- **Cross Version Compatible**: Fully tested on Windows 10 and 11 (x64)
- **Multi Language Support**: Primary C++ implementation with planned bindings for Rust, GO, and more

## Technical Overview

SysCaller provides a thin abstraction layer over Windows NT system calls, allowing developers to:

1. **Bypass API Hooking**: Access syscalls directly without relying on hooked user-mode DLLs
2. **Maximize Compatibility**: Dynamically resolve syscall IDs to work across different Windows versions
3. **Enhance Security**: Apply obfuscation techniques to prevent static analysis and detection
4. **Simplify Development**: Use a consistent API for syscalls across user-mode and kernel-mode applications

The SDK implements hundreds of Windows NT native functions with proper type definitions and parameter validation, making low level programming more accessible.

## Installation

### Prerequisites

- Windows 10+ (x64) operating system
- Visual Studio with MASM support (2019 or newer recommended)
- Python 3.8+ (for build tools)

### Option 1: Visual Studio

1. **Clone the repository**
   ```bash
   git clone https://github.com/WindowsAPI/SysCaller.git
   cd SysCaller
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the BuildTools GUI**
   ```bash
   cd BuildTools
   python syscaller.py
   ```

4. **Run Integrity Checks**
   - In the GUI, click "Validation Check" to update syscall offsets
   - Run "Compatibility Check" and "Verification Check" to ensure full compatibility
   - Optionally run "Obfuscation" to add protection layer
   - (NOTE: Obfuscation is still heavily experimental! Sometimes it doesnt work, and you have to generate a new `SysCaller.lib`)

5. **Build the library**
   - Open `SysCaller.sln` in Visual Studio
   - Set configuration to `Release` and platform to `x64`
   - Set C++ Standard to `17+`
   - Build the solution to generate `SysCaller.lib`

### Option 2: CMake (C++17 or newer)

1. **Run Integrity Checks**

   - In the GUI, click "Validation Check" to update syscall offsets
   - Run "Compatibility Check" and "Verification Check" to ensure full compatibility
   - Optionally run "Obfuscation" to add protection layer
   - (NOTE: Obfuscation is still heavily experimental! Sometimes it doesnt work, and you have to generate a new `SysCaller.lib`)

2. **Configure CMake**
   ```bash
   cd Wrapper
   ```

3. **Update C++ standard in CMakeLists.txt**
   Open `CMakeLists.txt` and set your C++ standard version (17, 20, or 23):
   ```cmake
   set(CMAKE_CXX_STANDARD #CHANGEME)  # Change to your required version
   ```

4. **Build the library**
   ```bash
   mkdir build && cd build
   cmake .. -A x64
   cmake --build . --config Release
   ```

## Usage

### Integration

1. **Add to your project**
   - Include the `Wrapper/include` directory in your include paths
   - Add the path and input for `SysCaller.lib` to your linker dependencies

2. **Import the header**
   ```cpp
   #include "syscaller.h"
   ```

3. **Use syscalls directly**
   ```cpp
   // user-mode syscall (Nt/Sys)
   NTSTATUS status = SysAllocateVirtualMemory(
       processHandle,
       &baseAddress,
       0,
       &regionSize,
       MEM_COMMIT | MEM_RESERVE,
       PAGE_READWRITE
   );
   
   // kernel-mode syscall (Zw/SysK)
   NTSTATUS status = SysKAllocateVirtualMemory(
       processHandle,
       &baseAddress,
       0,
       &regionSize,
       MEM_COMMIT | MEM_RESERVE,
       PAGE_READWRITE
   );
   ```

### Example:

```cpp
#include "syscaller.h"

bool WriteToProcessMemory(HANDLE processHandle, PVOID targetAddress, PVOID data, SIZE_T size) {
    SIZE_T bytesWritten;
    // direct syscall to write memory - bypasses potential hooks in WriteProcessMemory
    NTSTATUS status = SysWriteVirtualMemory(
        processHandle,
        targetAddress,
        data,
        size,
        &bytesWritten
    );
    return NT_SUCCESS(status) && (bytesWritten == size);
}
```
- For more examples look at the `Examples` directory.

### Advanced Features

The SysCaller GUI provides additional tools for working with syscalls:

- **Stub Mapper**: Create custom syscall mappings using predefined techniques to enhance obfuscation
- **Stub Craft**: Design and validate custom syscall stubs manually (WIP)
- **Settings**: Configure global syscall behavior and protection options

## Documentation

### External Resources

- [Windows NT Syscall Documentation](https://ntdoc.m417z.com/)
- [Windows Kernel Reference](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/_kernel/)
- [Windows API Reference](https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list)
- [Windows NT Reference](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/)

### SysCaller API Reference

The full API documentation is available in the header files:

- `Wrapper/include/syscaller.h` - Main SDK header
- `Wrapper/include/Sys/sysFunctions.h` - Syscall function declarations
- `Wrapper/include/Sys/sysTypes.h` - Windows NT type definitions
- `Wrapper/include/Sys/sysExternals.h` - External function references

## Considerations

SysCaller is intended for educational and legitimate security research. When using this library:

- Ensure proper error handling for all syscalls
- Be aware that direct syscalls may bypass security mechanisms
- Test thoroughly in controlled environments before deployment

## Contributing

Contributions to SysCaller are welcome! Please feel free to submit pull requests, create issues, or suggest new features.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Disclaimer

- **Educational Purpose**: SysCaller is created for educational and research purposes.
- **Legitimate Use**: While the library can be used to bypass certain security mechanisms, it is intended for legitimate security research, penetration testing, and software development.
- **No Liability**: The authors are not responsible for any misuse of this library or any actions taken with it.
- **Legal Compliance**: Users must ensure they comply with all applicable laws and regulations when using this software.

---

<p align="center">
  <i>SysCaller - Bridging the gap between user mode and kernel mode</i>
</p> 
