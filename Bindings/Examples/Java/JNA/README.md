# DLL Injection via Direct Syscalls w/ SysCaller (Java/JNA)

## Requirements

- JDK 21
- JNA jar on classpath (jna-5.x.jar)
- `SysCaller.dll` and target `test.dll` placed alongside the Java sources (or on PATH)

## Usage

1) Compile:
   javac -cp .;jna-5.18.1.jar InjectDLL.java
2) Run:
   java -cp .;jna-5.18.1.jar InjectDLL <pid> <dll_path>

## Notes

- The code resolves the DLL absolute path via `GetFullPathNameA` to avoid remote LoadLibrary path issues.
- Uses the same allocation/write/thread creation flow as other samples.
