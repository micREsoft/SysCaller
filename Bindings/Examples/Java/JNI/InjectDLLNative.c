#include <windows.h>
#include <jni.h>
#include <stdint.h>
#include <stdio.h>

typedef DWORD NTSTATUS;
typedef NTSTATUS (__stdcall *PFN_SysAllocateVirtualMemoryEx)(
    HANDLE, PVOID*, SIZE_T*, DWORD, DWORD, PVOID, DWORD);
typedef NTSTATUS (__stdcall *PFN_SysWriteVirtualMemory)(
    HANDLE, PVOID, PVOID, SIZE_T, SIZE_T*);
typedef NTSTATUS (__stdcall *PFN_SysCreateThreadEx)(
    PHANDLE, DWORD, PVOID, HANDLE, PVOID, PVOID, DWORD,
    SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (__stdcall *PFN_SysClose)(HANDLE);

#define NT_SUCCESS(Status) ((int32_t)(Status) >= 0)

static jboolean inject_internal(DWORD pid, const char* dllPath) {
    HMODULE hSysCaller = LoadLibraryA("SysCaller.dll");
    if (!hSysCaller) {
        return JNI_FALSE;
    }
    PFN_SysAllocateVirtualMemoryEx SysAllocateVirtualMemoryEx = (PFN_SysAllocateVirtualMemoryEx)GetProcAddress(hSysCaller, "SysAllocateVirtualMemoryEx");
    PFN_SysWriteVirtualMemory SysWriteVirtualMemory = (PFN_SysWriteVirtualMemory)GetProcAddress(hSysCaller, "SysWriteVirtualMemory");
    PFN_SysCreateThreadEx SysCreateThreadEx = (PFN_SysCreateThreadEx)GetProcAddress(hSysCaller, "SysCreateThreadEx");
    PFN_SysClose SysClose = (PFN_SysClose)GetProcAddress(hSysCaller, "SysClose");
    if (!SysAllocateVirtualMemoryEx || !SysWriteVirtualMemory || !SysCreateThreadEx || !SysClose) {
        return JNI_FALSE;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return JNI_FALSE;

    char absPath[MAX_PATH];
    DWORD n = GetFullPathNameA(dllPath, MAX_PATH, absPath, NULL);
    const char* usePath = (n > 0 && n < MAX_PATH) ? absPath : dllPath;
    SIZE_T pathLen = (SIZE_T)strlen(usePath) + 1;

    PVOID base = NULL; SIZE_T region = pathLen; NTSTATUS status;
    status = SysAllocateVirtualMemoryEx(hProcess, &base, &region, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE, NULL, 0);
    if (!NT_SUCCESS(status)) { CloseHandle(hProcess); return JNI_FALSE; }

    SIZE_T written = 0;
    status = SysWriteVirtualMemory(hProcess, base, (PVOID)usePath, pathLen, &written);
    if (!NT_SUCCESS(status) || written != pathLen) { CloseHandle(hProcess); return JNI_FALSE; }

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLib = GetProcAddress(k32, "LoadLibraryA");
    if (!pLoadLib) { CloseHandle(hProcess); return JNI_FALSE; }

    uint8_t sc[32]; int idx = 0;
    sc[idx++] = 0x48; sc[idx++] = 0x83; sc[idx++] = 0xEC; sc[idx++] = 0x28;
    sc[idx++] = 0x48; sc[idx++] = 0xB9; *(uint64_t*)(sc+idx) = (uint64_t)base; idx += 8;
    sc[idx++] = 0x48; sc[idx++] = 0xB8; *(uint64_t*)(sc+idx) = (uint64_t)pLoadLib; idx += 8;
    sc[idx++] = 0xFF; sc[idx++] = 0xD0;
    sc[idx++] = 0x48; sc[idx++] = 0x83; sc[idx++] = 0xC4; sc[idx++] = 0x28;
    sc[idx++] = 0xC3;
    SIZE_T scSize = (SIZE_T)idx;

    PVOID scAddr = NULL; region = scSize;
    status = SysAllocateVirtualMemoryEx(hProcess, &scAddr, &region, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE, NULL, 0);
    if (!NT_SUCCESS(status)) { CloseHandle(hProcess); return JNI_FALSE; }
    written = 0;
    status = SysWriteVirtualMemory(hProcess, scAddr, sc, scSize, &written);
    if (!NT_SUCCESS(status) || written != scSize) { CloseHandle(hProcess); return JNI_FALSE; }

    HANDLE hThread = NULL;
    status = SysCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProcess, scAddr, NULL, 0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status) || !hThread) { CloseHandle(hProcess); return JNI_FALSE; }
    WaitForSingleObject(hThread, 5000);
    SysClose(hThread);

    CloseHandle(hProcess);
    return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL Java_InjectDLL_inject(JNIEnv* env, jclass cls, jint pid, jstring jpath) {
    (void)cls;
    const char* path = (*env)->GetStringUTFChars(env, jpath, NULL);
    if (!path) return JNI_FALSE;
    jboolean ok = inject_internal((DWORD)pid, path);
    (*env)->ReleaseStringUTFChars(env, jpath, path);
    return ok;
}
