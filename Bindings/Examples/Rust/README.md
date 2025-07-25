# DLL Injection via Direct Syscalls w/ SysCaller (Rust)

This Rust example demonstrates injecting a DLL into a target process using direct syscalls via the SysCaller bindings.

---

## Requirements

- Rust 1.7x (1.70+ recommended, tested with 1.88+)
- `SysCaller.dll` and `SysCaller.lib` present in the same directory (or in your linker path) and built with required exports

---

## Usage

```bash
$ cargo build --release
- move `SysCaller.dll` to `target\release` (where the exe is located)
$ target\release\injectdll.exe <pid> <dll_path>
```

- `<pid>`: The process ID of the target process.
- `<dll_path>`: Path to the DLL you want to inject (e.g., `test.dll`).

**Example:**

```bash
$ target\release\injectdll.exe 5056 test.dll
```

---

## Notes

- Make sure `SysCaller.dll` is in the same directory as the executable or in your system PATH.
- The DLL path can be relative or absolute; the injector will resolve it.
- Requires appropriate privileges to open the target process and inject code.
- Tested & Works only on Windows x64.

---
