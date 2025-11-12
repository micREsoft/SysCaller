#pragma once

#include <QString>

namespace Constants {
    /* timeout values (milliseconds) */
    constexpr int THREAD_TERMINATION_TIMEOUT_MS = 5000;
    constexpr int THREAD_FORCE_TERMINATION_TIMEOUT_MS = 1000;
    
    constexpr int MAX_FILE_PATH_LENGTH = 260;
    constexpr int MIN_REQUIRED_PROJECT_ITEMS = 3;
    
    const QString DEFAULT_NTDLL_PATH = "C:\\Windows\\System32\\ntdll.dll";
    
    const QString ENV_SYSCALLER_ROOT = "SYSCALLER_ROOT";
}

/* error code enums */
enum class ErrorCode : int {
    Success = 0,
    GeneralError = -1,
    FileNotFound = -2,
    FileAccessDenied = -3,
    InvalidPath = -4,
    InvalidSettings = -5,
    ThreadTimeout = -6,
    OperationCancelled = -7,
    ValidationFailed = -8,
    CompatibilityFailed = -9,
    VerificationFailed = -10,
    ObfuscationFailed = -11
};