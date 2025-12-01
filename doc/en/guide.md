# Guide

## How KernelPatch Works

KernelPatch consists of the following components:

### [kptools](/tools/) (C++17)

kptools is the main patching and analysis utility:

- Parses kernel images without source code or symbol information and retrieves offset addresses of arbitrary kernel symbols.
- Patches the kernel image by appending kpimg to the end and writing necessary information to predetermined locations.
- Replaces the kernel's startup location with the starting address of kpimg.
- Extracts and dumps kallsyms symbol tables from kernel images.
- Extracts embedded kernel configuration (ikconfig).
- Displays kernel image metadata and structure.

### [kpimg](/kernel/)

- kpimg is a specially designed ELF.
- kpimg takes over the kernel boot process, performs all kernel dynamic patching, and exports functionality for user use via system calls.
- If you don't need extensive functionalities or want customization, you can separately utilize the code in [kernel/base](/kernel/base).

- [SuperCall](./super-syscall.md)

- [Kernel Inline Hook](./inline-hook.md)

- [Kernel Patch Module](./module.md)

### [kpuser](/user/)

kpuser is the user space header file and library for KernelPatch. You can directly embed kpuser into your program.
