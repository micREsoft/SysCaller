# DLL Injection via Direct Syscalls w/ SysCaller (C#)

This C# example demonstrates injecting a DLL into a target process using direct syscalls via the SysCaller bindings, built as a NativeAOT .NET 8 console application.

---

## Requirements

- .NET 8 SDK (NativeAOT support)
- Windows x64
- `SysCaller.dll` present in the same directory as the published executable and built with required exports

---

## Build & Publish

1. Build the project:

```bash
$ dotnet build -c Release
```

2. Publish as a NativeAOT self contained executable:

```bash
$ dotnet publish -c Release -r win-x64 /p:PublishAot=true --self-contained true
```

- The output executable will be in `bin\Release\net8.0\win-x64\publish\`.
- Copy `SysCaller.dll` to the same directory as the published executable.

---

## Usage

```bash
$ InjectDLL.exe <pid> <dll_path>
```

- `<pid>`: The process ID of the target process.
- `<dll_path>`: Path to the DLL you want to inject (e.g., `test.dll`).

**Example:**

```bash
$ InjectDLL.exe 4242 test.dll
```

---

## Notes

- Make sure `SysCaller.dll` is in the same directory as the published executable or in your system PATH.
- The DLL path can be relative or absolute; the injector will resolve it.
- Requires appropriate privileges to open the target process and inject code.
- Tested & Works only on Windows x64 with .NET 8 NativeAOT.

---
