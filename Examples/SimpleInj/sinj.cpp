#include "bypass.h"
#include <iostream>

DWORD GetProcessIdByName(const wchar_t* processName) {
    DWORD procId = 0;
    ULONG bufferSize = 0;
    NTSTATUS status = SysQuerySystemInformation(
        SystemProcessInformation,
        nullptr,
        0,
        &bufferSize
    );
    std::vector<BYTE> buffer(bufferSize);
    status = SysQuerySystemInformation(
        SystemProcessInformation,
        buffer.data(),
        bufferSize,
        &bufferSize
    );
    if (!NT_SUCCESS(status)) return 0;
    PSYSTEM_PROCESS_INFO processInfo = (PSYSTEM_PROCESS_INFO)buffer.data();
    while (true) {
        if (processInfo->ImageName.Buffer && 
            _wcsicmp(processInfo->ImageName.Buffer, processName) == 0) {
            procId = (DWORD)(DWORD_PTR)processInfo->UniqueProcessId;
            break;
        }
        if (processInfo->NextEntryOffset == 0) break;
        processInfo = (PSYSTEM_PROCESS_INFO)((BYTE*)processInfo + processInfo->NextEntryOffset);
    }
    return procId;
}

void RunInjectionLogic() {
    while (true) {
        DWORD pid = 0;
        const std::wstring dllPath = L"dll.dll";
        std::cout << "Options:\n";
        std::cout << "1. Process Name\n";
        std::cout << "2. Process ID\n";
        std::cout << "Enter choice (1 or 2): ";
        int choice;
        std::cin >> choice;
        std::cin.ignore();
        if (choice == 1) {
            std::wstring processName;
            std::cout << "Enter process name: ";
            std::getline(std::wcin, processName);
            processName += L".exe";
            pid = GetProcessIdByName(processName.c_str());
            if (pid == 0) {
                std::cout << "Process not found! Try again." << std::endl;
                continue;
            }
            std::cout << "Process found! PID: " << pid << std::endl;
        }
        else if (choice == 2) {
            std::cout << "Enter process PID: ";
            std::cin >> pid;
            std::cin.ignore();
            if (pid == 0) {
                std::cout << "Invalid PID! Try again." << std::endl;
                continue;
            }
            std::cout << "Targeting PID: " << pid << std::endl;
        }
        else {
            std::cout << "Invalid choice! Try again." << std::endl;
            continue;
        }
        Bypass bypass(pid);
        if (bypass.LoadLibraryInj(dllPath)) {
            std::cout << "Injection successful!" << std::endl;
        }
        else {
            std::cout << "Injection failed! Try again." << std::endl;
        }
    }
}

DWORD WINAPI ThreadProc(LPVOID param) {
    AllocConsole();
    FILE* stream;
    freopen_s(&stream, "CONOUT$", "w", stdout);
    freopen_s(&stream, "CONIN$", "r", stdin);
    std::cout << "SysCaller Active" << std::endl;
    RunInjectionLogic();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, ThreadProc, nullptr, 0, nullptr);
        break;
    case DLL_PROCESS_DETACH:
        FreeConsole();
        break;
    }
    return TRUE;
}
