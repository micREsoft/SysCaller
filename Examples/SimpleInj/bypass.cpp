#include "bypass.h"
#include <iostream>
#include <sstream>
#include <iomanip>

#define THREAD_ACCESS (THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION)

Bypass::Bypass(DWORD pid) : processPID(pid) {
    OBJECT_ATTRIBUTES objAttr = { 0 };
    InitializeObjectAttributes(&objAttr, nullptr, 0, nullptr, nullptr);
    CLIENT_ID clientId = { 0 };
    clientId.UniqueProcess = (HANDLE)(DWORD_PTR)pid;
    clientId.UniqueThread = nullptr;
    NTSTATUS status = SysOpenProcess(
        &processHandle,
        PROCESS_ALL_ACCESS,
        &objAttr,
        &clientId
    );
    if (!NT_SUCCESS(status)) {
        Log("Failed to open process. Status: " + std::to_string(status));
        processHandle = nullptr;
    }
}
Bypass::~Bypass() {
    if (processHandle) {
        CloseHandle(processHandle);
    }
}

void Bypass::Log(const std::string& message) {
    std::cout << "[*] " << message << std::endl;
}

bool Bypass::LoadLibraryInj(const std::wstring& dllPath) {
    try {
        Log("Starting LoadLibraryA injection...");
        std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            Log("Failed to open DLL file");
            return false;
        }
        size_t dllSize = file.tellg();
        Log("DLL size: " + std::to_string(dllSize) + " bytes");
        std::string ansiPath(dllPath.begin(), dllPath.end());
        size_t pathSize = ansiPath.length() + 1;
        PVOID pathAddress = (PVOID)0x30000000;
        SIZE_T pathAllocSize = pathSize;
        NTSTATUS status = SysAllocateVirtualMemory(
            processHandle,
            &pathAddress,
            0,
            &pathAllocSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (!NT_SUCCESS(status)) {
            Log("Failed to allocate memory for DLL path. Status: " + std::to_string(status));
            return false;
        }
        std::stringstream ss;
        ss << "Allocated DLL path memory at: 0x" << std::hex << std::uppercase << (DWORD64)pathAddress;
        Log(ss.str());
        SIZE_T bytesWritten;
        status = SysWriteVirtualMemory(
            processHandle,
            pathAddress,
            (PVOID)ansiPath.c_str(),
            pathSize,
            &bytesWritten
        );
        if (!NT_SUCCESS(status)) {
            Log("Failed to write DLL path. Status: " + std::to_string(status));
            return false;
        }
        HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
        if (!kernel32) {
            Log("Failed to get kernel32.dll handle");
            return false;
        }
        PVOID loadLibraryAddr = GetProcAddress(kernel32, "LoadLibraryA");
        if (!loadLibraryAddr) {
            Log("Failed to get LoadLibraryA address");
            return false;
        }
        ss.str("");
        ss << "LoadLibraryA address: 0x" << std::hex << std::uppercase << (DWORD64)loadLibraryAddr;
        Log(ss.str());
        std::vector<unsigned char> shellcode = {
            0x48, 0x83, 0xEC, 0x28,             // sub rsp, 0x28
            0x48, 0xB9                          // mov rcx,
        };
        DWORD64 pathAddr = (DWORD64)pathAddress;
        shellcode.insert(shellcode.end(),
            (unsigned char*)&pathAddr,
            (unsigned char*)&pathAddr + 8);
        shellcode.push_back(0x48);
        shellcode.push_back(0xB8);              // mov rax,
        DWORD64 loadLibAddr = (DWORD64)loadLibraryAddr;
        shellcode.insert(shellcode.end(),
            (unsigned char*)&loadLibAddr,
            (unsigned char*)&loadLibAddr + 8);
        std::vector<unsigned char> endCode = {
            0xFF, 0xD0,                         // call rax
            0x48, 0x83, 0xC4, 0x28,            // add rsp, 0x28
            0xC3                                // ret
        };
        shellcode.insert(shellcode.end(), endCode.begin(), endCode.end());
        PVOID shellcodeAddress = nullptr;
        SIZE_T shellcodeSize = shellcode.size();
        status = SysAllocateVirtualMemory(
            processHandle,
            &shellcodeAddress,
            0,
            &shellcodeSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (!NT_SUCCESS(status)) {
            Log("Failed to allocate memory for shellcode. Status: " + std::to_string(status));
            return false;
        }
        ss.str("");
        ss << "Allocated shellcode memory at: 0x" << std::hex << std::uppercase << (DWORD64)shellcodeAddress;
        Log(ss.str());
        status = SysWriteVirtualMemory(
            processHandle,
            shellcodeAddress,
            shellcode.data(),
            shellcode.size(),
            &bytesWritten
        );
        if (!NT_SUCCESS(status)) {
            Log("Failed to write shellcode. Status: " + std::to_string(status));
            return false;
        }
        HANDLE threadHandle = nullptr;
        status = SysCreateThreadEx(
            &threadHandle,
            THREAD_ALL_ACCESS,
            nullptr,
            processHandle,
            (PUSER_THREAD_START_ROUTINE)shellcodeAddress,
            nullptr,
            0,
            0,
            0,
            0,
            nullptr
        );
        if (!NT_SUCCESS(status)) {
            Log("Failed to create remote thread. Status: " + std::to_string(status));
            return false;
        }
        Log("Created remote thread successfully");
        LARGE_INTEGER timeout;
        timeout.QuadPart = -50000000;
        status = SysWaitForSingleObject(threadHandle, FALSE, &timeout);
        if (!NT_SUCCESS(status)) {
            Log("Thread wait failed. Status: " + std::to_string(status));
        }
        SysClose(threadHandle);
        Log("Injection completed successfully!");
        return true;
    }
    catch (...) {
        Log("Exception during LoadLibraryA injection");
        return false;
    }
}
