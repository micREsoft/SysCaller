# DLL Injection via Direct Syscalls w/ SysCaller (Julia)

## Requirements

- Julia 1.12+
- `SysCaller.dll` in this folder (or on PATH)

## Usage

From this folder:
```
julia InjectDLL.jl <pid> <dll_path>
```

## Notes

- Resolves the DLL absolute path via `GetFullPathNameA` to avoid remote LoadLibrary path issues.
- Uses the same allocation/write/thread creation flow as other samples.
- Shellcode is generated in Julia and embeds 64-bit addresses for the path buffer and `LoadLibraryA`.
