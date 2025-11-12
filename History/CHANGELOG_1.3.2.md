# v1.3.2 - Changelog

Released: **November 11, 2025**

---

## **What's New?**

---

- Refactored SysCaller, SysCallerK, and Bind architecture.
- Added bindings examples for LuaJIT, Java (JNA/JNI), Julia, D
- Added disk mapped resolver function
- Replaced all C++ style comments with C style comments
- Compatibility and Verification buttons are automatically disabled in Indirect Syscall Mode, as these integrity checks are not applicable to indirect syscalls.
- Added support for `SYSCALLER_ROOT` environment variable to override default project root detection.
- Redesigned Changelog Dialog
- Redesigned Confirmation Dialog
- Redesigned Obfuscation Selection Dialog
- Consistent button styling across all dialogs
- Improved Settings Dialog tab bar alignment
- Replaced StatusBar emoji icons with fugue icons
- Centralized error code enumeration (`ErrorCode` enum) for consistent error handling
- Added thread timeout constants (`THREAD_TERMINATION_TIMEOUT_MS`, `THREAD_FORCE_TERMINATION_TIMEOUT_MS`) for better resource management
- Enhanced settings validation with proper error handling
- Improved thread safety with proper cleanup and timeout handling
- Added input validation throughout the codebase
- Extracted magic numbers to named constants
- Improved resource cleanup in thread management
- Added proper path separator consistency handling
- Enhanced error handling with try catch blocks and proper error reporting

---

## **Bug Fixes**

---

- Fixed duplicate close block in func definition header file
- Fixed compiler warning C4067: unexpected tokens following preprocessor directive in Verification.cpp and Compatibility.cpp
- Fixed compiler warning C4267: conversion from 'size_t' to 'int' in Verification.cpp and Utils.cpp
- Fixed compiler warning C4101: unreferenced local variable in IndirectControlFlow.cpp
- Fixed potential thread timeout hangs by implementing proper thread cleanup with timeout constants
- Fixed settings save delay by removing duplicate `sync()` calls
- Fixed UI lag during verification checks with large syscall counts by implementing output batching (flushes every 20 messages)
- Fixed Settings Dialog tab bar alignment issue where Profile tab had a gap on the right side
- Fixed Changelog Dialog title bar rounded edges to match squared dialog window
- Improved settings persistence with proper `QSettings::sync()` error handling
- Fixed potential memory leaks in thread management with proper cleanup on application close
- Resolved path separator inconsistencies across different platforms

---