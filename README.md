# SysCaller SDK

<p align="center">
  <img src="https://github.com/user-attachments/assets/243f7fe5-b461-460d-8c38-3858512e90de" alt="SysCaller Logo" width="400"/>
</p>

<p align="center">
  <b>Direct Windows Syscalls. Dynamic offsets. Validation. Obfuscation.</b><br>
  <i>Bypass user-mode hooks and work across Windows versions with a single SDK.</i>
</p>

---

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Install</a> •
  <a href="#usage">Usage</a> •
  <a href="#buildtools">BuildTools</a> •
  <a href="#documentation">Docs</a> •
  <a href="#contributing">Contribute</a> •
  <a href="#license">License</a>
</p>

---

## Features

- **Direct Syscall Access:** Bypass Windows API hooks by calling NT kernel syscalls directly.
- **Dual Mode:** Single codebase, two static libraries:
  - `SysCaller` (user mode, `Nt`/`Sys` prefix)
  - `SysCallerK` (kernel mode, `Zw`/`SysK` prefix)
- **Dynamic Offset Resolution:** Automatically detects syscall IDs for compatibility across Windows 10/11 (x64).
- **Obfuscation Layer:** Optional, randomized stub generation and anti pattern junk for stealth.
- **Comprehensive GUI:** Validate, verify, and protect syscalls with a modern interface.
- **Multi Language Ready:** C++ primary, with planned Rust/Go bindings.
- **Modular Build System:** Visual Studio (MASM) and CMake support.

---

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [SysCaller BuildTools](#buildtools)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## Installation

### Prerequisites
- Windows 10 or 11 (x64)
- Visual Studio 2019+ (with MASM)
- Python 3.8+ (for build tools)

### Quick Start (Visual Studio)

```sh
# Clone the repo
$ git clone https://github.com/micREsoft/SysCaller.git
$ cd SysCaller

# Install Python dependencies
$ pip install -r requirements.txt

# Launch the BuildTools GUI
$ cd BuildTools
$ python syscaller.py
```

- Use the GUI to run **Validation**, **Compatibility**, and **Verification** checks.
- Optionally enable **Obfuscation** (experimental).

#### Build the User Mode Library
- Open `SysCaller.sln` in Visual Studio
- Select the **SysCaller** project
- Set configuration to `Release | x64`
- Build via GUI → *Build SysCaller* → outputs `x64/Release/SysCaller.lib`

#### Build the Kernel Mode Library
- Install the Windows Driver Kit (WDK)
- In `SysCaller.sln`, select **SysCallerK**
- Set configuration to `Release | x64`
- Build via GUI → *Build SysCallerK* → outputs `x64/Release/SysCallerK.lib`

> **Note:** Kernel mode is experimental. Use a VM for testing. Driver signing or Secure Boot off may be required.

### CMake (Alternative)

```sh
# Run integrity checks in the GUI first
$ cd SysCaller/Wrapper
# Edit CMakeLists.txt to set your C++ standard (17/20/23)
$ mkdir build && cd build
$ cmake .. -A x64
$ cmake --build . --config Release
```

> **Note:** CMake script for Kernel mode does not exist, but it is planned.

---

## Usage

### Integrate in Your Project

1. **Include headers:**
   - Add `Wrapper/include` to your include paths
   - Link against `SysCaller.lib` (user) or `SysCallerK.lib` (kernel)
2. **Import the main header:**
   ```cpp
   #include "syscaller.h"
   ```
3. **Call syscalls directly:**
   ```cpp
   // User mode example
   NTSTATUS status = SysAllocateVirtualMemory(
       processHandle, &baseAddress, 0, &regionSize,
       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
   ```
   ```cpp
   // Kernel mode example
   NTSTATUS status = SysKAllocateVirtualMemory(
       ZwCurrentProcess(), &base, 0, &regionSize,
       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
   ```

#### Example: Write to Process Memory
```cpp
#include "syscaller.h"

bool WriteToProcessMemory(HANDLE processHandle, PVOID targetAddress, PVOID data, SIZE_T size) {
    SIZE_T bytesWritten;
    NTSTATUS status = SysWriteVirtualMemory(
        processHandle, targetAddress, data, size, &bytesWritten);
    return NT_SUCCESS(status) && (bytesWritten == size);
}
```

> **Note:** For more usage demos & examples checkout [Examples](https://github.com/micREsoft/SysCallerExamples)!

---

## BuildTools

SysCaller includes a full featured BuildTools GUI with capabilities like:

| Tool                | Description                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| **Validation**      | Updates syscall offsets, checks for missing/invalid stubs                   |
| **Compatibility**   | Analyzes syscall compatibility across Windows versions                      |
| **Verification**    | Checks return/parameter types, offset ranges, and header consistency        |
| **Obfuscation**     | Randomizes names/offsets, adds junk instructions for stealth, and more      |
| **Stub Mapper**     | Custom obfuscation and mapping for individual syscalls                      |
| **Hash Compare**    | Compare stub hashes across builds/files                                     |
| **Global Profile**  | Import/Export SysCaller profiles via .ini config                            |
| **Settings**        | Configure global syscall and protection options                             |

- All tools are accessible via the BuildTools GUI (`python syscaller.py` in `BuildTools/`).

---

## Documentation

- [SysCaller Wiki](https://github.com/micREsoft/SysCaller/wiki)
- [SysCaller Nt Usage](https://github.com/micREsoft/SysCaller/tree/main/SysCaller/Wrapper/include)
- [SysCaller Zw Usage](https://github.com/micREsoft/SysCaller/tree/main/SysCallerK/Wrapper/include)
- [Windows NT Syscall Reference](https://ntdoc.m417z.com/)
- [Windows Kernel Docs](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/_kernel/)

---

## Contributing

Pull requests, issues, and feature suggestions are welcome! Please:
- Read the [CONTRIBUTING.md](https://github.com/micREsoft/SysCaller/blob/main/.github/CONTRIBUTING.md)
- Follow the [GPLv3 license](LICENSE)
- Use issues for bug reports and feature requests

If you find SysCaller useful, consider starring the repo to help others discover it.

---

## License

SysCaller is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE) for details.

---

## Disclaimer

> **Educational Use Only:** SysCaller is for research and educational purposes. Use responsibly and legally.
> 
> **No Warranty:** The authors are not liable for misuse or damages. Always test in controlled environments.

<p align="center">
  <i>SysCaller — Bridging the gap between user mode and kernel mode</i>
</p>
