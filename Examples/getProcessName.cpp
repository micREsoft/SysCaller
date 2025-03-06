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
