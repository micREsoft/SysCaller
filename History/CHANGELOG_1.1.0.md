# v1.1.0 - Changelog

Released: **July 22, 2025**

---

## **What's New?**

- Added support for kernel mode / `Zw` syscalls.
- You can now build in debug mode with full support.
- Support for switching and managing syscall tables.
- Improved regex resilience and matching.
- Each stub now has integrity hashes.
- Added support to compare hash values of stubs.
- New **README** and a detailed **WIKI** added.
- Save configurations globally as `.ini` files.
- Added custom obfuscation via stub mapping.
- Changelog history now available in the GUI.
- Fixed layout, colors, DPI scaling, and architecture inconsistencies.
- Wrapper and build tools are now modularized.
- Added `SysCaller` and `SysCallerK` directly into the solution.

---

## **Bug Fixes**

- Removed `64bit` macro (already defined by WDK).
- Removed forward declaration of `MEMORY_RESERVE_TYPE`.
- Disabled nameless struct/union compiler warnings.
- Fixed multiple grammatical issues across UI and docs.
- Rewrote broken patterns using integrity check feedback.