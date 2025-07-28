# Contributing to SysCaller

Thank you for your interest in contributing to **SysCaller**!

SysCaller has evolved significantly through v1.0.0, v1.1.0, and v1.2.0. The project is now in a more mature state with a complete C++ Qt based GUI (Bind), comprehensive multi language bindings, and a stable core architecture.

---

## What You *Can* Contribute Right Now

I welcome PRs and improvements for the following:

### Core SysCaller SDK
- **Syscall Constants & Definitions**  
  Add new constants or improve existing ones in the constants headers (`SysCaller/Wrapper/include/Sys/sysConstants.h`, `SysCallerK/Wrapper/include/SysK/sysConstants_k.h`) or other definitions in related header files.

- **New Syscalls**  
  Add support for additional Windows syscalls that aren't currently implemented.

- **Kernel Mode Enhancements**  
  Improve the SysCallerK kernel mode library functionality and compatibility.
  
### Bind (GUI) Contributions
With v1.2.0, the GUI has been completely rewritten in C++ Qt and is now much more stable. I'm now accepting:

- **Bug Fixes** for the Bind GUI

- **Performance Optimizations**

- **Minor UI/UX Improvements** (layout tweaks, accessibility improvements)

- **New Features** that align with the existing design patterns

### Examples & Bindings
- **Examples**  
  Add usage examples (in `Bindings/Examples/`) for different use cases:
  - Kernel Mode use
  - Driver safe syscall usage
  - Any use case that demonstrates SysCaller's capabilities

- **Language Bindings**  
  Create binding examples for additional programming languages beyond the current C, C++, C#, Rust, Python, Go, and Nim support.
  > Tip: Any language with C bindings is SysCaller compatible!

### Documentation & Guides
- **Documentation**  
  Improvements to `README.md` or the `Wiki`, inline comments, or new markdown files (such as guides, tutorials, or technical explanations).

- **Translations**  
  If you want to contribute translations for SysCaller outside of English, I'm all for it.

### Build System & Infrastructure
- **CMake Improvements**  
  Enhance the CMake build system, especially for kernel mode and GUI builds.

---

## What I'm *Not* Accepting (Yet)

### Major GUI Redesigns
While Bind is now stable, major architectural changes to the GUI are not currently needed. The current Qt based design serves the project well.

### Experimental Features
Features that would significantly change the core API or break existing functionality are not currently being accepted.

---

## Development Guidelines

### Code Style
- Follow the existing code style in the respective directories
- Add appropriate comments for complex logic
- Ensure all code builds cleanly on Windows 10/11 x64

### Pull Request Process
1. Fork the repo and create a feature branch
2. Make your changes with clear and focused commits
3. Test your changes thoroughly
4. Update documentation if needed
5. Submit a PR with:
   - A clear title
   - A concise description of what was changed and why

### Testing Requirements
- Ensure your changes work with both user mode (SysCaller) and kernel mode (SysCallerK) where applicable
- Test with the Bind GUI if your changes affect the build process
- Verify that existing examples still work correctly

---

## Getting Started

> Note: SysCaller targets Windows 10/11 x64. Other platforms/architectures (like ARM or Linux) wont be supported.

1. **Clone the repository:**
   ```sh
   git clone https://github.com/micREsoft/SysCaller.git
   cd SysCaller
   ```

2. **Set up your development environment:**
Building Bind:
   - Install Visual Studio 2019+ with MSVC v142 toolset
   - Install Qt 5.12 for Bind development
   - Install vcpkg and required dependencies (`cmark`, `pe-parse`)
   - requires **C++ 20**

Building SysCaller/SysCallerK:
   - Install Visual Studio 2022
   - Install Windows SDK for SysCaller
   - Install Windows WDK for SysCallerK
   - requires **C++ 17 or later**

3. **Build the project:**
   - Open `SysCaller.sln` for core libraries
   - Open `Bind/Bind.sln` for the GUI

4. **Choose an area to contribute** from the sections above

---

## Thank You

SysCaller has grown from a simple syscall library to a comprehensive SDK with a modern GUI and multi language support. Your contributions help make it even better for the community!

Even if you're not submitting code, opening issues, discussions, or suggesting improvements is incredibly valuable. If you're unsure whether something is worth contributing, just ask in the [Discussions](https://github.com/micREsoft/SysCaller/discussions) - I'm open to ideas and collaboration!

---

<i>SysCaller - Bridging the gap between user mode and kernel mode.</i>
