# v1.3.0 - Changelog

Released: **September 3, 2025**

---

## **What's New?**

---

- Added comprehensive support for Direct, Inline, and Indirect assembly modes
- Added general tab support with assembly mode selection
- Improved validation system supporting all three modes
- Improved memory management in obfuscation pipeline
- Improved error reporting throughout the system
- Improved CMake support for all assembly modes
- Improved Visual Studio solution files
- Complete restructure of obfuscation system into focused, maintainable modules
- Clear namespace separation: DO (Direct Obfuscation), ID (Indirect Obfuscation), SO (Shared Obfuscation)
- Specialized components for better code organization and performance
- Full implementation of inline/indirect syscalls, and obfuscation with runtime resolver support for indirect mode.
- Resolver string encryption and conditional resolver logic
- control flow, junk generation, string randomization and more for indirect stubs
- (Inline obfuscation is coming in a future release!)
- Unified custom title bars across all dialogs (Settings, Hash Compare, Stub Mapper, Changelog)
- External QSS stylesheets for better maintainability
- Enhanced dialog layouts and improved visual consistency
- New ConfirmationDialog for better user interactions
- Comprehensive build configuration macros and conditional compilation
- Better error handling and build messages
- Eliminated namespace conflicts through proper organization
- Consistent header formatting across all files

---

## **Bug Fixes**

- Removed rcx/r10 conflicting junk instructions that could interfere with syscall execution
- Resolved missing module definition directives and exported functions
- Resolved various compilation issues and dependency conflicts from modularization
- Improved header formatting consistency across all source files
- Improved CMake and Visual Studio solution files for new modular structure
- Improved memory handling in obfuscation pipeline
- Improved error reporting and build message system
- Improved separation of concerns and consistent naming conventions
- Many gui/grammer fixes.