; Syscall stubs for x64
; These are naked functions that execute syscalls directly

.code

; External syscall numbers (set at runtime in SyscallManager.cpp)
EXTERN g_syscall_NtOpenProcess:DWORD
EXTERN g_syscall_NtReadVirtualMemory:DWORD
EXTERN g_syscall_NtWriteVirtualMemory:DWORD
EXTERN g_syscall_NtAllocateVirtualMemory:DWORD
EXTERN g_syscall_NtFreeVirtualMemory:DWORD
EXTERN g_syscall_NtProtectVirtualMemory:DWORD
EXTERN g_syscall_NtQueryVirtualMemory:DWORD
EXTERN g_syscall_NtCreateThreadEx:DWORD

; NtOpenProcess syscall stub
Syscall_NtOpenProcess PROC
    mov r10, rcx                          ; Save first parameter
    mov eax, DWORD PTR [g_syscall_NtOpenProcess]    ; Load syscall number from memory
    syscall                                ; Execute syscall
    ret
Syscall_NtOpenProcess ENDP

; NtReadVirtualMemory syscall stub
Syscall_NtReadVirtualMemory PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_syscall_NtReadVirtualMemory]
    syscall
    ret
Syscall_NtReadVirtualMemory ENDP

; NtWriteVirtualMemory syscall stub
Syscall_NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_syscall_NtWriteVirtualMemory]
    syscall
    ret
Syscall_NtWriteVirtualMemory ENDP

; NtAllocateVirtualMemory syscall stub
Syscall_NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_syscall_NtAllocateVirtualMemory]
    syscall
    ret
Syscall_NtAllocateVirtualMemory ENDP

; NtFreeVirtualMemory syscall stub
Syscall_NtFreeVirtualMemory PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_syscall_NtFreeVirtualMemory]
    syscall
    ret
Syscall_NtFreeVirtualMemory ENDP

; NtProtectVirtualMemory syscall stub
Syscall_NtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_syscall_NtProtectVirtualMemory]
    syscall
    ret
Syscall_NtProtectVirtualMemory ENDP

; NtCreateThreadEx syscall stub
Syscall_NtCreateThreadEx PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_syscall_NtCreateThreadEx]
    syscall
    ret
Syscall_NtCreateThreadEx ENDP

END