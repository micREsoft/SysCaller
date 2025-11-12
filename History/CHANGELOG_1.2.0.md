# v1.2.0 - Changelog

Released: **July 29, 2025**

---

## **What's New?**

- Rewrote the entire BuildTools/GUI from Python (PyQt) to native C++ using Qt improving performance, stability maintainability, and integration with the core SDK.
- Added support for any programming language with C bindings, making SysCaller accessible across a wider ecosystem.
- The BuildTools has been officially renamed to **Bind**, reflecting its role in connecting your project with SysCaller using clean GUI based binding, wrapping, and obfuscation features.
- Improved error reporting and exception handling throughout Bind.
- C++ BuildTools delivers significantly improved speed, native integration, and reduced memory footprint.

---

## **Bug Fixes**

- Fixed edge case where stub hashes could mismatch during integrity comparison.
- Resolved console output issues that caused issues.
- Removed placeholder comments, WIP debug code, and development macros.
- Resolved various compilation issues and dependency conflicts.
- Eliminated memory leaks present in the Python implementation.