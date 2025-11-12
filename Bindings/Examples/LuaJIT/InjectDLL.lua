local ffi = require("ffi")

ffi.cdef[[
typedef unsigned long       DWORD;
typedef int                 BOOL;
typedef void*               PVOID;
typedef PVOID               HANDLE;
typedef size_t              SIZE_T;
typedef unsigned long long  ULONG_PTR;
typedef unsigned long       ULONG;
typedef long                NTSTATUS;

NTSTATUS SysAllocateVirtualMemoryEx(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    SIZE_T *RegionSize,
    ULONG AllocationType,
    ULONG Protect,
    PVOID ExtendedParameters,
    ULONG ExtendedCount
);

NTSTATUS SysWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    SIZE_T *NumberOfBytesWritten
);

NTSTATUS SysCreateThreadEx(
    HANDLE *ThreadHandle,
    ULONG DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

NTSTATUS SysClose(HANDLE Handle);

HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
BOOL CloseHandle(HANDLE hObject);
HANDLE GetModuleHandleA(const char *lpModuleName);
void* GetProcAddress(HANDLE hModule, const char *lpProcName);
DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
DWORD GetFullPathNameA(const char* lpFileName, DWORD nBufferLength, char* lpBuffer, char** lpFilePart);
]]

local syscaller = ffi.load("SysCaller")
local kernel32  = ffi.C

local function NT_SUCCESS(status)
    return tonumber(status) >= 0
end

local function pack_u64(val)
    local buf = ffi.new("uint64_t[1]")
    buf[0] = ffi.cast("uint64_t", val)
    return ffi.string(buf, 8)
end

local function ptr_to_uint64(p)
    return tonumber(ffi.cast("uintptr_t", p))
end

local function InjectDLL(process_handle, dll_path)
    local MAX_PATH = 260
    local outbuf = ffi.new("char[?]", MAX_PATH)
    local ret = kernel32.GetFullPathNameA(dll_path, MAX_PATH, outbuf, nil)
    local abs_path
    if ret ~= 0 and ret < MAX_PATH then
        abs_path = ffi.string(outbuf, ret)
    else
        abs_path = dll_path
    end

    local path_bytes = abs_path .. "\0"
    local path_size = #path_bytes

    local baseaddr = ffi.new("PVOID[1]")
    local region_size = ffi.new("SIZE_T[1]", path_size)

    local STATUS = syscaller.SysAllocateVirtualMemoryEx(
        process_handle,
        baseaddr,
        region_size,
        0x3000,
        0x40,
        nil,
        0
    )
    if not NT_SUCCESS(STATUS) then
        print(string.format("[!] Failed to allocate memory for DLL path. Status: 0x%08X", tonumber(ffi.cast("unsigned int", STATUS))))
        return false
    end
    local dll_path_addr = ptr_to_uint64(baseaddr[0])
    print(string.format("[+] Allocated DLL path memory at: 0x%016X", dll_path_addr))

    local bytes_written = ffi.new("SIZE_T[1]", 0)
    local local_buf = ffi.new("char[?]", path_size, path_bytes)
    STATUS = syscaller.SysWriteVirtualMemory(
        process_handle,
        baseaddr[0],
        ffi.cast("PVOID", local_buf),
        path_size,
        bytes_written
    )
    if not NT_SUCCESS(STATUS) or tonumber(bytes_written[0]) ~= path_size then
        print(string.format("[!] Failed to write DLL path. Status: 0x%08X, Bytes written: %d", tonumber(ffi.cast("unsigned int", STATUS)), tonumber(bytes_written[0])))
        return false
    end
    print("[+] Successfully wrote DLL path to memory")

    local h_kernel32 = kernel32.GetModuleHandleA("kernel32.dll")
    if h_kernel32 == nil then
        print("[!] Failed to get kernel32.dll handle")
        return false
    end
    local load_library = kernel32.GetProcAddress(h_kernel32, "LoadLibraryA")
    if load_library == nil then
        print("[!] Failed to get LoadLibraryA address")
        return false
    end
    local load_library_addr = ptr_to_uint64(load_library)
    print(string.format("[+] LoadLibraryA address: 0x%016X", load_library_addr))

    local sc = {}
    sc[#sc+1] = string.char(0x48, 0x83, 0xEC, 0x28)
    sc[#sc+1] = string.char(0x48, 0xB9) .. pack_u64(baseaddr[0])
    sc[#sc+1] = string.char(0x48, 0xB8) .. pack_u64(load_library)
    sc[#sc+1] = string.char(0xFF, 0xD0)
    sc[#sc+1] = string.char(0x48, 0x83, 0xC4, 0x28)
    sc[#sc+1] = string.char(0xC3)
    local shellcode = table.concat(sc)
    local shellcode_size = #shellcode

    local shelladdr = ffi.new("PVOID[1]")
    local shell_region = ffi.new("SIZE_T[1]", shellcode_size)
    STATUS = syscaller.SysAllocateVirtualMemoryEx(
        process_handle,
        shelladdr,
        shell_region,
        0x3000,
        0x40,
        nil,
        0
    )
    if not NT_SUCCESS(STATUS) then
        print(string.format("[!] Failed to allocate memory for shellcode. Status: 0x%08X", tonumber(ffi.cast("unsigned int", STATUS))))
        return false
    end
    local shellcode_addr_val = ptr_to_uint64(shelladdr[0])
    print(string.format("[+] Allocated shellcode memory at: 0x%016X", shellcode_addr_val))

    local local_sc_buf = ffi.new("char[?]", shellcode_size, shellcode)
    bytes_written[0] = 0
    STATUS = syscaller.SysWriteVirtualMemory(
        process_handle,
        shelladdr[0],
        ffi.cast("PVOID", local_sc_buf),
        shellcode_size,
        bytes_written
    )
    if not NT_SUCCESS(STATUS) or tonumber(bytes_written[0]) ~= shellcode_size then
        print(string.format("[!] Failed to write shellcode. Status: 0x%08X, Bytes written: %d", tonumber(ffi.cast("unsigned int", STATUS)), tonumber(bytes_written[0])))
        return false
    end
    print("[+] Successfully wrote shellcode")

    local thread_handle = ffi.new("HANDLE[1]")
    STATUS = syscaller.SysCreateThreadEx(
        thread_handle,
        0x1FFFFF,
        nil,
        process_handle,
        shelladdr[0],
        nil,
        0,
        0,
        0,
        0,
        nil
    )
    if not NT_SUCCESS(STATUS) or thread_handle[0] == nil then
        print(string.format("[!] Failed to create remote thread. Status: 0x%08X, Handle: %s", tonumber(ffi.cast("unsigned int", STATUS)), tostring(thread_handle[0])))
        return false
    end
    print(string.format("[+] Created remote thread: 0x%016X", ptr_to_uint64(thread_handle[0])))

    kernel32.WaitForSingleObject(thread_handle[0], 5000)
    STATUS = syscaller.SysClose(thread_handle[0])
    print(string.format("[+] Successfully injected %s!", dll_path))
    return true
end

local argc = #arg
if argc ~= 2 then
    print("Usage: luajit inject.lua <pid> <dll_path>")
    os.exit(1)
end

local pid = tonumber(arg[1])
local dll_path = arg[2]

local PROCESS_ALL_ACCESS = 0x1F0FFF
local process_handle = ffi.C.OpenProcess(PROCESS_ALL_ACCESS, false, pid)
if process_handle == nil then
    print(string.format("[!] Failed to open process %d", pid))
    os.exit(1)
end

local ok = InjectDLL(process_handle, dll_path)

ffi.C.CloseHandle(process_handle)

if not ok then
    os.exit(1)
end