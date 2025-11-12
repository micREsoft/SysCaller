# DLL Injection via Direct Syscalls w/ SysCaller (Go)

This Go example demonstrates injecting a DLL into a target process using SysCaller for direct system call access.

---

## Requirements

- Go 1.18 (1.21+ recommended, tested with 1.23+)
- `SysCaller.dll` present in the same directory and built with required exports

---

## Usage

```bash
$ go mod init InjectDLL
$ go build
$ InjectDLL.exe <pid> payload.dll
```

- `<pid>`: The process ID of the target process.
- `<dll_path>`: Path to the DLL you want to inject (e.g., `test.dll`).

**Example:**

```bash
$ InjectedDLL.exe 1337 test.dll
```

---

## Notes

- Make sure `SysCaller.dll` is in the same directory as `InjectDLL.exe` or in your system PATH.
- The DLL path can be relative or absolute; the injector will resolve it.
- Requires appropriate privileges to open the target process and inject code.
- Tested & Works only on Windows x64.

---