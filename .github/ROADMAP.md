# SysCaller SDK | Roadmap  
_Last updated: 6/19/25 by Maintainer_

---

## High Priority

- [ ] **Finish Custom Stub Maker**  
  Manually create syscall stubs yourself

- [ ] **Support Multiple Syscall Tables Per Build**  
  Enable dual/multi version stub sets for compatibility across Windows versions for a single build.

- [ ] **Comprehensive README & Docs**  
  Finalize usage documentation, internal flow explanations, and examples.

---

## Feature Enhancements

- [ ] **Global Profile System**  
  Allow saving/loading build profiles (.json/.ini) for reuse and automation.

- [ ] **Add More Obfuscation/Encryption Techniques**  
  Junk logic, encryption layers, stub layout shuffling, sig disorientation.

- [ ] **Add Hashes for Stub Integrity**  
  Optionally tag each stub or full build with unique hash for future lookups.

- [ ] **Support Debug Mode**  
  Support debug mode for VS alongside release mode

- [ ] **Enhance GUI**  
  More consistent layout, better tooltips, real time logging panel, and easier navigation.

---

## Language & Integration

- [ ] **Multi language Bindings**  
  Add support for: Rust, Python, Go, C#, etc.

- [ ] **Language Translations for GUI**  
  Begin internationalizing UI/UX: Russian, Spanish, French, etc.

---

## Learning & Documentation

- [ ] **Add More Usage Examples**  
  Include basic to advanced syscall usage patterns and integration in real tools.

- [ ] **Syscall Knowledgebase**  
  Reference sheet in the repo (`docs/`) listing common NT syscalls, descriptions, return types, etc.

---

## Ideas

- [ ] **Runtime Stub Loading**  
  Enable loading encrypted syscall stubs at runtime rather than compile time.

---

## Completed ✓

- ✓ **GUI Tooling (PyQt)**
- ✓ **Validation / Compatibility / Verification Checks**
- ✓ **Dynamic Obfuscation Engine**
- ✓ **Stub Mapper**
- ✓ **CMake Build Script**
- ✓ **Modularize BuildTools & Wrapper**
- ✓ **Initial Public Release**
- ✓ **Added Backup/Restore Function**
