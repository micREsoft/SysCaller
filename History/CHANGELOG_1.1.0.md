# v1.1.0 - Changelog

Released: **July 22, 2025**

---

## What's New?

- **Kernel Mode Support**: Added support for kernel mode / `Zw` syscalls.
- **Debug Mode**: You can now build in debug mode with full support.
- **Multiple Syscall Tables**: Support for switching and managing syscall tables.
- **Stronger Regex Patterns**: Improved regex resilience and matching.
- **Stub Hashing**: Each stub now has integrity hashes.
- **Stub Hash Comparison**: Added support to compare hash values of stubs.
- **Documentation**: New **README** and a detailed **WIKI** added.
- **Global Profiles**: Save configurations globally as `.ini` files.
- **Stub Mapper**: Added custom obfuscation via stub mapping.
- **Changelog Viewer**: Changelog history now available in the GUI.
- **GUI / UX Improvements**: Fixed layout, colors, DPI scaling, and architecture inconsistencies.
- **Modular Wrappers**: Wrapper and build tools are now modularized.
- **Project Updates**: Added `SysCaller` and `SysCallerK` directly into the solution.

---

## Bug Fixes:

- **Removed Conflicts**: Removed `64bit` macro (already defined by WDK).
- **Cleaned Structs**: Removed forward declaration of `MEMORY_RESERVE_TYPE`.
- **Suppressed Warnings**: Disabled nameless struct/union compiler warnings.
- **Grammar Fixes**: Fixed multiple grammatical issues across UI and docs.
- **Regex Fixes**: Rewrote broken patterns using integrity check feedback.
