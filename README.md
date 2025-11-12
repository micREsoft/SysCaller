# SysCaller SDK v1.3.2

<p align="center">
  <img src="https://github.com/user-attachments/assets/243f7fe5-b461-460d-8c38-3858512e90de" alt="SysCaller Logo" width="400"/>
</p>

<p align="center">
  <b>Windows Syscalls. Direct, Indirect, and Inline. Dynamic Offsets. Validation. Obfuscation.</b><br>
  <i>Bypass user mode hooks and ensure cross version compatibility with one SDK.</i>
</p>


<div align="center">

[![Version](https://img.shields.io/badge/Version-1.3.2-blue.svg)](https://github.com/micREsoft/SysCaller)
[![License](https://img.shields.io/badge/License-GPLv3-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%2064--bit-lightgrey.svg)](https://github.com/micREsoft/SysCaller)
[![C++](https://img.shields.io/badge/C%2B%2B-17%2B-blue.svg)](https://isocpp.org/)

</div>

---

<img width="1919" height="1030" alt="image" src="https://github.com/user-attachments/assets/d84aecd0-bbea-49d8-981f-eba1f2bfda83" />


---

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Install</a> •
  <a href="#usage">Usage</a> •
  <a href="#bind">Bind (BuildTools)</a> •
  <a href="#documentation">Docs</a> •
  <a href="#contributing">Contribute</a> •
  <a href="#license">License</a>
</p>

---

## Features

### Core Functionality
- **Three Syscall Modes:**
  - **Direct Syscalls** (`SYSCALLER_DIRECT`): Fastest execution, compile time resolution
  - **Indirect Syscalls** (`SYSCALLER_INDIRECT`): Runtime resolution, cross version compatibility
  - **Inline ASM** (`SYSCALLER_INLINE`): Embedded assembly, maximum stealth
- **Bindings Support** (`SYSCALLER_BINDINGS`): Optional DLL export for multi language support
- **Direct Syscall Access:** Bypass Windows API hooks by calling NT kernel syscalls directly
- **Dual Architecture:** Single codebase, dual libraries:
  - `SysCaller` (user mode, `Nt`/`Sys` prefix)
  - `SysCallerK` (kernel mode, `Zw`/`SysK` prefix (EXPERIMENTAL))
- **Dynamic Offset Resolution:** Automatically detects syscall IDs for compatibility across Windows 10/11 (x64).
- **Obfuscation Layer:** Optional, randomized stub generation and anti pattern junk for stealth.
- **Comprehensive GUI:** Validate, verify, and protect syscalls with a modern interface.
- **Multi Language Ready:** Official bindings and examples for C, C++, C#, Rust, Python, Go, Nim, LuaJIT, Java (JNA/JNI), Julia, and D. Easily extendable to more languages.
- **Modular Build System:** Visual Studio (MASM) and CMake support.

---

## Multi Language Bindings & Examples

SysCaller is now not just for C++! The SDK now provides official bindings and ready to use DLL injection examples for:

- **C++** ([C++ Example](https://github.com/micREsoft/SysCallerExamples/tree/main/Projects/SimpleInj))
- **C** ([C Example](Bindings/Examples/C/))
- **C#** ([C# Example](Bindings/Examples/CSharp/))
- **Rust** ([Rust Example](Bindings/Examples/Rust/))
- **Nim** ([Nim Example](Bindings/Examples/Nim/))
- **Python** ([Python Example](Bindings/Examples/Python/))
- **Go** ([Go Example](Bindings/Examples/GO/))
- **LuaJIT** ([LuaJIT Example](Bindings/Examples/LuaJIT/))
- **Java** ([Java/JNA Example](Bindings/Examples/Java/JNA/) | [Java/JNI Example](Bindings/Examples/Java/JNI/))
- **Julia** ([Julia Example](Bindings/Examples/Julia/))
- **D** ([D Example](Bindings/Examples/D/))

Each example demonstrates direct DLL injection using the SysCaller API, with full source and build instructions in each language's folder. These are bare minimum examples meant to show simple usage, now you can expand syscalls and methodology.

> Want to add support for another language? PRs and suggestions are welcome!

---

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [How to Build and Use Bindings (All Languages)](#how-to-build-and-use-bindings-all-languages)
- [Usage](#usage)
- [Bind (BuildTools)](#bind)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## Installation

### SysCaller Prerequisites
- Windows 10 or 11 (x64)
- Visual Studio 2019+ (with MASM for building SysCaller)
- C++ 17+ 

### Build Modes

SysCaller supports three build modes that you can configure via preprocessor definitions:

- **`SYSCALLER_DIRECT`** (default): Fastest execution, syscall numbers resolved at compile time
- **`SYSCALLER_INDIRECT`**: Runtime resolution via ntdll.dll analysis, more flexible across Windows versions. Supports multiple resolver methods:
  - Memory Export (GetModuleHandle)
  - PEB LDR Traversal (No WinAPI calls)
  - Hashed Export (No string comparisons)
  - Disk Mapped (Anti hook, reads from disk)  
- **`SYSCALLER_INLINE`**: Assembly code embedded directly, most stealthy but larger binary size

**Optional**: Add `SYSCALLER_BINDINGS` for multi language DLL support.

For detailed configuration instructions, see [BUILD_MODES.md](Wrapper/BUILD_MODES.md).

---

### Bind Prerequisites
- Windows 10 or 11 (x64)
- Visual Studio 2019+ (with MSVC v142 toolset for building Bind)
- C++20
- Qt 5.12
- [vcpkg](https://github.com/microsoft/vcpkg)
- Install `cmark` and `pe-parse` via vcpkg

### Environment Variable Configuration

You can configure the SysCaller project root path using the `SYSCALLER_ROOT` environment variable:

```sh
# Windows Command Prompt
set SYSCALLER_ROOT=C:\Path\To\SysCaller

# PowerShell
$env:SYSCALLER_ROOT = "C:\Path\To\SysCaller"
```

This is useful when:
- Running Bind from a different location
- Using a custom project structure
- Deploying Bind in a portable configuration

If not set, Bind will automatically detect the project root by searching for the `SysCaller` and `SysCallerK` directories.

### Quick Start (Visual Studio)

1. **Clone the SysCaller repo:**
   ```sh
   git clone https://github.com/micREsoft/SysCaller.git
   cd SysCaller
   ```
2. **Download the latest Bind release zip** from the [Releases](https://github.com/micREsoft/SysCaller/releases) page.
3. **Replace the Bind directory:**
   - Delete the existing `Bind` directory in your cloned repo.
   - Extract the downloaded Bind zip into the repo root (so `Bind/` is restored with the new files).
4. **Run Bind:**
   - Launch the Bind executable from the `Bind` directory.

### Building Bind (BuildTools) from Source

If you want to build Bind yourself:

1. **Install prerequisites** (see above).
2. **Install dependencies with vcpkg:**
   ```sh
   vcpkg install cmark pe-parse
   ```
3. **Setup Qt 5.12 and ensure it's in your PATH.**
4. **Generate MOC files** (Qt's meta object compiler, usually handled by CMake or qmake).
5. **Open `Bind.sln` in Visual Studio.**
6. **Build the project** (Release | x64).

### CMake (Alternative)
SysCaller v1.3.2 CMake Support:

```bash
# Direct mode
cmake -B build -S . -DSYSCALLER_BUILD_MODE=DIRECT

# Indirect mode with different resolver methods
cmake -B build -S . -DSYSCALLER_BUILD_MODE=INDIRECT -DSYSCALLER_RESOLVER_MEMORY_EXPORT=ON
cmake -B build -S . -DSYSCALLER_BUILD_MODE=INDIRECT -DSYSCALLER_RESOLVER_PEB_LDR=ON
cmake -B build -S . -DSYSCALLER_BUILD_MODE=INDIRECT -DSYSCALLER_RESOLVER_HASHED_EXPORT=ON
cmake -B build -S . -DSYSCALLER_BUILD_MODE=INDIRECT -DSYSCALLER_RESOLVER_DISK_MAPPED=ON

# Inline asm mode
cmake -B build -S . -DSYSCALLER_BUILD_MODE=INLINE

# As dynamic link library
cmake -B build -S . -DBUILD_SHARED_LIBS=ON

# Indirect mode with bindings and shared library (example with disk mapped resolver)
cmake -B build -S . -DSYSCALLER_BUILD_MODE=INDIRECT -DSYSCALLER_RESOLVER_DISK_MAPPED=ON -DSYSCALLER_BINDINGS=ON -DBUILD_SHARED_LIBS=ON
```

> **Note:** CMake script for Kernel mode does not exist, but it is planned.

---

## How to Build and Use Bindings (All Languages)

To use SysCaller from C, C++, Rust, Python, Go, LuaJIT, Java, Julia, D, or any other language that supports C bindings, follow these steps:

1. **Launch the Bind GUI:**
   - Run the Bind executable from the `Bind` directory (see Installation above).
2. **Enable Bindings:**
   - Go to the **Settings** tab in the GUI.
   - Enable the **Bindings** option.
   - Adjust any other settings you want (select syscalls, enable obfuscation, etc).

3. **Run Validation:**
   - In the GUI, run the **Validation** tool.
   - This will generate a `SysCaller.def` file in `SysCaller/Wrapper/`.

4. **Build the DLL:**
   - Add `Wrapper/SysCaller.def` to your module definitions in your build system.
   - Build the SysCaller project as a DLL (`SysCaller.dll`).

5. **Use in Your Language of Choice:**
   - Follow the language specific README in `Bindings/Examples/<language>/` for how to use the DLL in C, Rust, Python, Go, etc.

> **Tip:**  The language example folders contain minimal working injectors and build instructions for each language. Expand from there for your own projects!

---

## Usage

### Integrate in Your Project

1. **Include headers:**
   - Add `Wrapper/include` to your include paths
   - Link against `SysCaller.lib` (user) or `SysCallerK.lib` (kernel)
2. **Import the main header:**
   ```cpp
   #include "SysCaller.h"
   ```
3. **Call syscalls directly:**
   ```cpp
   /* User mode example */
   NTSTATUS status = SysAllocateVirtualMemory(
       processHandle, &baseAddress, 0, &regionSize,
       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
   ```
   ```cpp
   /* Kernel mode example */
   NTSTATUS status = SysKAllocateVirtualMemory(
       ZwCurrentProcess(), &base, 0, &regionSize,
       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
   ```

#### Example: Write to Process Memory
```cpp
#include "SysCaller.h"

bool WriteToProcessMemory(HANDLE processHandle, PVOID targetAddress, PVOID data, SIZE_T size) {
    SIZE_T bytesWritten;
    NTSTATUS status = SysWriteVirtualMemory(
        processHandle, targetAddress, data, size, &bytesWritten);
    return NT_SUCCESS(status) && (bytesWritten == size);
}
```

> **Note:** For more usage demos & examples checkout [Examples](https://github.com/micREsoft/SysCallerExamples)!

> **Note:** Kernel mode is experimental. Use a VM for testing. Driver signing or Secure Boot off may be required.

---

## Bind

SysCaller includes full featured GUI "Bind" (formerly BuildTools) with capabilities like:

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

- All tools are accessible via the Bind GUI (see Installation above).
- Bind is a native C++ Qt application. The Python buildtools have been Deprecated.

---

## Documentation

> [SysCaller Docs](https://reverseengineeri.ng) |
> Website for documentation is currently down!

> [SysCaller Nt Usage](https://github.com/micREsoft/SysCaller/tree/main/SysCaller/Wrapper/include)

> [SysCaller Zw Usage](https://github.com/micREsoft/SysCaller/tree/main/SysCallerK/Wrapper/include)

> [Windows NT Syscall Reference](https://ntdoc.m417z.com/)

> [Windows Kernel Docs](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/_kernel/)

---

## Contributing

Pull requests, issues, and feature suggestions are welcome! Please:
- Read the [CONTRIBUTING.md](https://github.com/micREsoft/SysCaller/blob/main/.github/CONTRIBUTING.md)
- Follow the [GPLv3 license](LICENSE)
- Use issues for bug reports and feature requests

If you find SysCaller useful, consider starring the repo to help others discover it.

---

## Credits

SysCaller wouldnt be possible without:

- [PeParse](https://github.com/trailofbits/pe-parse)
- [CMark](https://github.com/commonmark/cmark)
- [Fugue Icons](https://p.yusukekamiyamane.com/)
- [Microsoft](https://microsoft.com)
- [NTDoc](https://ntdoc.m417z.com/)

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