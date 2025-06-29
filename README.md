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
- **Dual Mode Operation**: Single code-base delivers two static libraries:
  * **SysCaller** – user-mode (`Nt`/`Sys` prefix) 
  * **SysCallerK** – kernel-mode (`Zw`/`SysK` prefix)
- **Kernel Ready**: Build the *SysCallerK* variant with the Windows Driver Kit (WDK) and VS22 *Kernel Mode Driver* toolset (VS 2022 supported)
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

    
5. **Build the User Mode library** (SysCaller)
   - Open **`SysCaller.sln`** in Visual Studio
   - Select the *SysCaller* project
   - Set **Configuration** to *Release* and **Platform** to *x64*
   - Ensure the C++ standard is *17 or newer*
   - Build → *Build SysCaller* → produces `x64/Release/SysCaller.lib`

### Option 2: CMake (C++17 or newer)

1. **Run Integrity Checks**

   - In the GUI, click "Validation Check" to update syscall offsets
   - Run "Compatibility Check" and "Verification Check" to ensure full compatibility
   - Optionally run "Obfuscation" to add protection layer
   - (NOTE: Obfuscation is still heavily experimental! Sometimes it doesnt work, and you have to generate a new `SysCaller.lib`)

2. **Configure CMake**
   ```bash
   cd SysCaller/Wrapper
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

### Building the Kernel Mode library (SysCallerK)

The solution contains a second project named **SysCallerK**.  To compile it you need the WDK components that come with the *Kernel-Mode Driver* workload.

1. Install the WDK (during VS installation setup choose *Windows Driver Kit* or install the *Kernel-Mode Driver, C++* workload).
2. In **`SysCaller.sln`** change the *Startup Project* (or selection in *Solution Explorer*) to **SysCallerK**.
3. Select the **`Release | x64`** configuration.
4. Run the GUI/BuildTools to your liking. (make sure Kernel Mode is selected under settings)
5. Build → *Build SysCallerK* → produces `x64/Release/SysCallerK.lib`.

> ⚠️ CMake for Kernel Mode coming soon. Also note Kernel Mode is still super experimental I suggest using VM to test any kernel implementations using SysCaller.
> 
> ⚠️ Building kernel components usually requires **driver signing certificates** or disabling *Secure Boot / Driver Signature Enforcement* on the test machine. Follow the [Microsoft Docs](https://learn.microsoft.com/windows-hardware/drivers/install/) before loading code built with SysCallerK.

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

### Kernel Mode snippet:

```cpp
#include "syscaller.h"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path) {
    SIZE_T regionSize = 0x1000;
    PVOID  base       = nullptr;

    NTSTATUS st = SysKAllocateVirtualMemory(
        ZwCurrentProcess(),
        &base,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    return st;
}
```
- For more examples look at the [Examples](https://github.com/micREsoft/SysCallerExamples) repo.

### Advanced Features

The SysCaller GUI provides additional tools for working with syscalls:

- **Stub Mapper**: Create custom syscall mappings using predefined techniques to enhance obfuscation
- **Hash Stubs**: Create Hashes for each Assembly Stub + Build Config
- **Hash Compare**: Compare two or more files containing Stub Hashes
- **Stub Craft**: Design and validate custom syscall stubs manually (WIP)
- **Settings**: Configure global syscall behavior and protection options

## Documentation

### External Resources

- [Windows NT Syscall Documentation](https://ntdoc.m417z.com/)
- [Windows Kernel Reference](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/_kernel/)
- [Windows API Reference](https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list)
- [Windows NT Reference](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/)

**For comprehensive documentation and guides, check out the [SysCaller Wiki](https://github.com/WindowsAPI/SysCaller/wiki).**

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

If you've cloned or are enjoying this project, please consider [⭐ it on GitHub](https://github.com/WindowsAPI/SysCaller) to help others discover SysCaller!

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
