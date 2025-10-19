# DLL Injection via Direct Syscalls w/ SysCaller (Java/JNI)

## Requirements

- JDK 21 (javac/java)
- MSVC build tools (x64)
- `SysCaller.dll` and `test.dll` in this directory (or on PATH)

## Usage

1) Generate JNI header inline (not strictly required with this C file):
   javac .\InjectDLL.java

2) Build native DLL (x64):
   - Open "x64 Native Tools Command Prompt for VS" or call vcvars64.bat
   - Compile:
     cl /LD /I "%JAVA_HOME%\include" /I "%JAVA_HOME%\include\win32" InjectDLLNative.c /link /OUT:InjectDLLNative.dll

3) Run:
   java InjectDLL <pid> <dll_path>

## Notes

- The code resolves the DLL absolute path via `GetFullPathNameA` to avoid remote LoadLibrary path issues.
- Uses the same allocation/write/thread creation flow as other samples.
