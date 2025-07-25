# DLL Injection via Direct Syscalls w/ SysCaller (Go)

This Go example demonstrates injecting a DLL into a target process using SysCaller for direct system call access.

---

## Requirements

- Go 1.18 or later (tested with Go 1.23–1.24)
- `SysCaller.dll` built with required exports and placed in the same directory

---

## Usage

```bash
$ go mod init InjectDLL
$ go build
$ InjectDLL.exe <pid> payload.dll
