# Contributing to SysCaller

Thank you for your interest in contributing to **SysCaller**! A syscall SDK for stealthy, cross version Windows development with a focus on obfuscation, offset validation, and low level control.

I'm currently in *active development*, especially around the **GUI/BuildTools**, so some parts of the repo are open for contributions, while others are in a "suggestions only" phase.

---

## What You *Can* Contribute Right Now

I welcome PRs and improvements for the following:

- **Syscall Constants & Definitions**  
  Add new constants or improve existing ones in the constants header (`Wrapper/include/Sys/sysConstants.h`) or other definitions in related header files.

- **Examples**  
  Add usage examples (in `Examples/`) for different use cases:
  - Custom shellcode runners
  - Process hollowing
  - Kernel mode use
  - Driver safe syscall usage
  - Anything that is an example SysCaller is lacking

- **Docs**  
  Improvements to `README.md`, inline comments, or new markdown files (such as guides or other explanations).

- **Translations**  
  If you want to contribute to different translations for SysCaller outside of english I am all for it.

- **Bindings**
  If you know another language like Rust, GO, Python etc then making Bindings for SysCaller to work with other languages is totally possible! 

---

## What I'm *Not* Accepting (Yet)

### GUI Contributions (for now)

The **BuildTools GUI** is under fast and iterative development. UI elements, modes, and backend logic are changing frequently.

> That said, **GUI suggestions and feature ideas are more than welcome**!  
Feel free to open a **Discussion** or GitHub Issue with:
- UX ideas or layout improvements
- Feature requests (e.g. “Add an offset diffing view” or “Support custom junk stub patterns”)
- Bug reports

Once the GUI reaches a more stable design, GUI contributions will be opened up via issues labeled `GUI: Help Wanted`.

---

## General Guidelines

- Fork the repo and make your changes in a dedicated branch.
- Keep pull requests focused on a single fix or feature.
- Format your code consistently.
- Document your changes when appropriate.
- Make sure your changes **build cleanly** on Windows 10/11 x64 (Visual Studio or CMake).

---

## Thank You

SysCaller is a passion project, and your contributions help make it better. Even if you're not submitting code, opening issues, discussions, or suggesting syscall improvements is incredibly valuable!

If you're unsure whether something is worth contributing, just ask in the [Discussions](https://github.com/WindowsAPI/SysCaller/discussions) I'm open to ideas and collaboration!

---

<i>SysCaller - Bridging the gap between user mode and kernel mode.</i>
