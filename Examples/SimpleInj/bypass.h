#pragma once
#include "sinj.h"
#include <string>

class Bypass {
private:
    HANDLE processHandle;
    DWORD processPID;
    void Log(const std::string& message);

public:
    Bypass(DWORD pid);
    ~Bypass();
    bool LoadLibraryInj(const std::wstring& dllPath);
};
