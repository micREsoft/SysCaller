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
