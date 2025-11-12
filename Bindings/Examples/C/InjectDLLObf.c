#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// Type definitions for SysCaller
typedef DWORD NTSTATUS;
typedef HANDLE (__stdcall *PFN_oznbvo_655212)(
    HANDLE,
    PVOID*,
    SIZE_T*,
    DWORD,
    DWORD,
    PVOID,
    DWORD
);
typedef DWORD (__stdcall *PFN_yexedj_555900)(
    HANDLE,
    PVOID,
    PVOID,
    SIZE_T,
    SIZE_T*
);
typedef DWORD (__stdcall *PFN_jljtug_682236)(
    PHANDLE,
    DWORD,
    PVOID,
    HANDLE,
    PVOID,
    PVOID,
    DWORD,
    SIZE_T,
    SIZE_T,
    SIZE_T,
    PVOID
);
typedef DWORD (__stdcall *PFN_ezhgwv_592746)(HANDLE);

#define NT_SUCCESS(Status) ((int32_t)(Status) >= 0)

int InjectDLL(HANDLE hProcess, const char* dll_path,
    PFN_oznbvo_655212 oznbvo_655212,
    PFN_yexedj_555900 yexedj_555900,
    PFN_jljtug_682236 jljtug_682236,
    PFN_ezhgwv_592746 ezhgwv_592746)
{
    // Get absolute path
    char abs_path[MAX_PATH];
    if (!GetFullPathNameA(dll_path, MAX_PATH, abs_path, NULL)) {
        printf("[!] Failed to get full DLL path.\n");
        return 0;
    }
    size_t path_len = strlen(abs_path) + 1;
    // Allocate memory for DLL path
    PVOID base_address = NULL;
    SIZE_T region_size = path_len;
    NTSTATUS status = oznbvo_655212(
        hProcess,
        &base_address,
        &region_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
        NULL,
        0
    );
    if (!NT_SUCCESS(status)) {
        printf("[!] Failed to allocate memory for DLL path. Status: 0x%08X\n", status);
        return 0;
    }
    printf("[+] Allocated DLL path memory at: 0x%p\n", base_address);
    // Write DLL path
    SIZE_T bytes_written = 0;
    status = yexedj_555900(
        hProcess,
        base_address,
        (PVOID)abs_path,
        path_len,
        &bytes_written
    );
    if (!NT_SUCCESS(status) || bytes_written != path_len) {
        printf("[!] Failed to write DLL path. Status: 0x%08X, Bytes written: %llu\n", status, (unsigned long long)bytes_written);
        return 0;
    }
    printf("[+] Successfully wrote DLL path to memory\n");
    // Get LoadLibraryA address
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        printf("[!] Failed to get kernel32.dll handle\n");
        return 0;
    }
    FARPROC loadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!loadLibraryA) {
        printf("[!] Failed to get LoadLibraryA address\n");
        return 0;
    }
    printf("[+] LoadLibraryA address: 0x%p\n", loadLibraryA);
    // Build x64 shellcode
    uint8_t shellcode[32];
    int idx = 0;
    // sub rsp, 0x28
    shellcode[idx++] = 0x48; shellcode[idx++] = 0x83; shellcode[idx++] = 0xEC; shellcode[idx++] = 0x28;
    // mov rcx, <base_address>
    shellcode[idx++] = 0x48; shellcode[idx++] = 0xB9;
    *(uint64_t*)(shellcode + idx) = (uint64_t)base_address; idx += 8;
    // mov rax, <LoadLibraryA>
    shellcode[idx++] = 0x48; shellcode[idx++] = 0xB8;
    *(uint64_t*)(shellcode + idx) = (uint64_t)loadLibraryA; idx += 8;
    // call rax
    shellcode[idx++] = 0xFF; shellcode[idx++] = 0xD0;
    // add rsp, 0x28
    shellcode[idx++] = 0x48; shellcode[idx++] = 0x83; shellcode[idx++] = 0xC4; shellcode[idx++] = 0x28;
    // ret
    shellcode[idx++] = 0xC3;
    size_t shellcode_size = idx;
    // Allocate memory for shellcode
    PVOID shellcode_addr = NULL;
    region_size = shellcode_size;
    status = oznbvo_655212(
        hProcess,
        &shellcode_addr,
        &region_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
        NULL,
        0
    );
    if (!NT_SUCCESS(status)) {
        printf("[!] Failed to allocate memory for shellcode. Status: 0x%08X\n", status);
        return 0;
    }
    printf("[+] Allocated shellcode memory at: 0x%p\n", shellcode_addr);
    // Write shellcode
    bytes_written = 0;
    status = yexedj_555900(
        hProcess,
        shellcode_addr,
        shellcode,
        shellcode_size,
        &bytes_written
    );
    if (!NT_SUCCESS(status) || bytes_written != shellcode_size) {
        printf("[!] Failed to write shellcode. Status: 0x%08X, Bytes written: %llu\n", status, (unsigned long long)bytes_written);
        return 0;
    }
    printf("[+] Successfully wrote shellcode\n");
    // Create remote thread
    HANDLE hThread = NULL;
    status = jljtug_682236(
        &hThread,
        0x1FFFFF, // THREAD_ALL_ACCESS
        NULL,
        hProcess,
        shellcode_addr,
        NULL,
        0, 0, 0, 0,
        NULL
    );
    if (!NT_SUCCESS(status) || !hThread) {
        printf("[!] Failed to create remote thread. Status: 0x%08X, Handle: 0x%p\n", status, hThread);
        return 0;
    }
    printf("[+] Created remote thread: 0x%p\n", hThread);
    // Wait for thread and close handle
    WaitForSingleObject(hThread, 5000);
    ezhgwv_592746(hThread);
    printf("[+] Successfully injected %s!\n", dll_path);
    return 1;
}

int main(int argc, char* argv[])
{
    if (argc != 3) {
        printf("Usage: %s <pid> <dll_path>\n", argv[0]);
        return 1;
    }
    DWORD pid = (DWORD)atoi(argv[1]);
    const char* dll_path = argv[2];
    HMODULE hSysCaller = LoadLibraryA("SysCaller.dll");
    if (!hSysCaller) {
        printf("[!] Failed to load SysCaller.dll\n");
        return 1;
    }
    PFN_oznbvo_655212 oznbvo_655212 = (PFN_oznbvo_655212)GetProcAddress(hSysCaller, "oznbvo_655212");
    PFN_yexedj_555900 yexedj_555900 = (PFN_yexedj_555900)GetProcAddress(hSysCaller, "yexedj_555900");
    PFN_jljtug_682236 jljtug_682236 = (PFN_jljtug_682236)GetProcAddress(hSysCaller, "jljtug_682236");
    PFN_ezhgwv_592746 ezhgwv_592746 = (PFN_ezhgwv_592746)GetProcAddress(hSysCaller, "ezhgwv_592746");
    if (!oznbvo_655212 || !yexedj_555900 || !jljtug_682236 || !ezhgwv_592746) {
        printf("[!] Failed to resolve SysCaller functions\n");
        return 1;
    }
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[!] Failed to open process %lu\n", pid);
        return 1;
    }
    InjectDLL(hProcess, dll_path, oznbvo_655212, yexedj_555900, jljtug_682236, ezhgwv_592746);
    CloseHandle(hProcess);
    return 0;
} 