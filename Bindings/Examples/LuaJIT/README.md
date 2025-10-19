# DLL Injection via Direct Syscalls w/ SysCaller (LuaJIT/FFI)

## Requirements

- LuaJIT (2.x)
- `SysCaller.dll` placed alongside the Lua script (or on PATH)

## Usage

Run the script:
```
luajit injectdll.lua <pid> <dll_path>
```

## Notes

- The script resolves the DLL absolute path via `GetFullPathNameA` to avoid remote LoadLibrary path issues.
- Uses the same allocation/write/thread creation flow as other samples.
- Shellcode is built dynamically with proper 64-bit address packing to prevent precision loss.