# DLL Injection via Direct Syscalls w/ SysCaller (C)

This C example demonstrates injecting a DLL into a target process using direct syscalls via the SysCaller bindings.

---

## Requirements

- Microsoft Visual Studio (MSVC), MinGW, or any Windows C compiler
- `SysCaller.dll` present in the same directory and built with required exports

- Create an empty C++ project & name it InjectDLL in vs2022
- Right click the project & go to properties
- Go to: Configuration Properties > C/C++ > Advanced
- Set Compile As = Compile as C Code (/TC)

---

## Usage

```bash
$ InjectDLL.exe <pid> <dll_path>
```

- `<pid>`: The process ID of the target process.
- `<dll_path>`: Path to the DLL you want to inject (e.g., `test.dll`).

**Example:**

```bash
$ InjectDLL.exe 4242 test.dll
```

---

## Notes

- Make sure `SysCaller.dll` is in the same directory as `InjectDLL.exe` or in your system PATH.
- The DLL path can be relative or absolute; the injector will resolve it.
- Requires appropriate privileges to open the target process and inject code.
- Tested & Works only on Windows x64.

--- 
