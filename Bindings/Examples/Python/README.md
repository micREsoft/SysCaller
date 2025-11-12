# DLL Injection via Direct Syscalls w/ SysCaller (Python)

This Python example demonstrates injecting a DLL into a target process using direct syscalls via the SysCaller bindings.

---

## Requirements

- Python 3.x (3.6+ recommended, tested with 3.12+)
- `SysCaller.dll` present in the same directory and built with required exports

---

## Usage

```bash
$ python InjectDLL.py <pid> <dll_path>

- `<pid>`: The process ID of the target process.
- `<dll_path>`: Path to the DLL you want to inject (e.g., `test.dll`).
```

**Example:**

```bash
$ python InjectDLL.py 4728 test.dll
```

## Notes

- Make sure `SysCaller.dll` is in the same directory as `InjectDLL.py` or in your system PATH.
- The DLL path can be relative or absolute; the injector will resolve it.
- Requires appropriate privileges to open the target process and inject code.
- Tested & Works only on Windows x64.

---