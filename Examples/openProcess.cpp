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
