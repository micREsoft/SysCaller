# DLL Injection via Direct Syscalls w/ SysCaller (D)

## Requirements

- D compiler (DMD)
- `SysCaller.dll` in this folder (or on PATH)

## Usage

From this folder:
```
dmd InjectDLL.d
InjectDLL <pid> <dll_path>
```

## Notes

- Resolves the DLL absolute path via `GetFullPathNameA` to avoid remote LoadLibrary path issues.
- Uses the same allocation/write/thread creation flow as other samples.
- Shellcode is built in D and embeds 64-bit addresses for the path buffer and `LoadLibraryA`.
