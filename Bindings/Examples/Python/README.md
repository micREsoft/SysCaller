# DLL Injection via Direct Syscalls w/ SysCaller (Python)

This Python example demonstrates injecting a DLL into a target process using direct syscalls via the SysCaller bindings.

---

## Requirements

- Python 3.x (3.6+ recommended, tested with 3.12+)
- `SysCaller.dll` present in the same directory and built with required exports

---

## Usage

```bash
$ python InjectDLL.py <pid> payload.dll
