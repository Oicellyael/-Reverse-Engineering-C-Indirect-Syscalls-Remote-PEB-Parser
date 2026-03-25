# -Reverse-Engineering-C-PEB-Ldr-Bypass
C++ implementation for resolving NTDLL function addresses using manual PE header parsing and DJB2 API hashing.
Native-API-Stealth-Resolver

🛡️ Overview
This repository contains a low-level C++ implementation for resolving Windows Native API functions directly from ntdll.dll memory. The project bypasses standard Windows API resolution methods (like GetProcAddress or GetModuleHandle) to demonstrate advanced system internal techniques and anti-analysis patterns.

🚀 Key Features
Dynamic PEB Resolution: Uses x64 Assembly to access the Process Environment Block (PEB) via the gs register (gs:[60h]).

Manual LDR Traversal: Manually navigates the InLoadOrderModuleList to find the base address of ntdll.dll without library calls.

EAT Parsing: Implements a manual parser for the Export Address Table (EAT) of the Portable Executable (PE) format.

API Hashing (DJB2): Utilizes a custom hashing algorithm to resolve functions by hash instead of string literals, effectively removing sensitive strings from the binary and complicating static analysis.

Native API Focused: Specifically designed to resolve NtOpenProcess, NtReadVirtualMemory, and NtWriteVirtualMemory.

🛠️ Technical Implementation
The resolver follows a multi-stage process:

Assembly Layer: GetMyPeb (ASM) retrieves the PEB address.

LDR Layer: Traverses the linked lists in PEB->Ldr to find ntdll.dll.

Header Parsing: Locates the IMAGE_EXPORT_DIRECTORY from the NT Headers.

Hashed Search: Iterates through function names, applying a case-insensitive DJB2 hash, and compares it against target constants.

Address Translation: Maps the function name index to its ordinal and finally to its Relative Virtual Address (RVA).

📁 Project Structure
src/main.cpp: Core logic, EAT parsing, and hashing implementation.

src/asm.asm: x64 Assembly for direct PEB access.

include/asm.h: C++ linkage for assembly procedures.

include/help.h: Custom namespace and global base pointers.

💻 Usage
To resolve a function, provide the pre-calculated DJB2 hash to the resolver:

C++
uintptr_t ntOpen = GetFunctionAddress(0x3F4DD136); // NtOpenProcess
uintptr_t pNtRead = GetFunctionAddress(0x307C3661); // NtReadVirtualMemory
uintptr_t pNtWrite = GetFunctionAddress(0xFAE162D0);// NtWriteVirtualMemory

<img width="1209" height="214" alt="image" src="https://github.com/user-attachments/assets/30832df8-ce50-4719-985f-595de4bdcddf" />

📋 Requirements
Architecture: x64 (Required for gs:[60h] and 64-bit pointers).

Compiler: MSVC (Visual Studio) with MASM (Microsoft Macro Assembler) enabled.
