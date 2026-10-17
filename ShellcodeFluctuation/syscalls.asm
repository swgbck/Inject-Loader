.code

EXTERN g_SyscallTable : QWORD
EXTERN SpoofedSyscall : PROC

PUBLIC SysNtAllocateVirtualMemory
PUBLIC SysNtFreeVirtualMemory
PUBLIC SysNtWriteVirtualMemory
PUBLIC SysNtProtectVirtualMemory
PUBLIC SysNtCreateThreadEx
PUBLIC SysNtOpenProcess
PUBLIC SysNtOpenThread
PUBLIC SysNtClose
PUBLIC SysNtQuerySystemInformation
PUBLIC SysNtCreateSection
PUBLIC SysNtMapViewOfSection
PUBLIC SysNtUnmapViewOfSection
PUBLIC SysNtDelayExecution

; SYSCALL_ENTRY = { DWORD ssn; PVOID syscallAddress; } -> 16 bytes com padding em x64.
; Ordem em main.cpp (RESOLVE_ONE):
;  0 NtAllocateVirtualMemory   -> offset   0
;  1 NtFreeVirtualMemory       -> offset  16
;  2 NtWriteVirtualMemory      -> offset  32
;  3 NtProtectVirtualMemory    -> offset  48
;  4 NtCreateThreadEx          -> offset  64
;  5 NtOpenProcess             -> offset  80
;  6 NtClose                   -> offset  96
;  7 NtQuerySystemInformation  -> offset 112
;  8 NtCreateSection           -> offset 128
;  9 NtMapViewOfSection        -> offset 144
; 10 NtUnmapViewOfSection      -> offset 160
; 11 NtDelayExecution          -> offset 176
; 12 NtOpenThread              -> offset 192

SysNtAllocateVirtualMemory PROC
    mov     r10, rcx
    mov     eax, DWORD PTR g_SyscallTable[0]
    syscall
    ret
SysNtAllocateVirtualMemory ENDP

SysNtFreeVirtualMemory PROC
    mov     r10, rcx
    mov     eax, DWORD PTR g_SyscallTable[16]
    syscall
    ret
SysNtFreeVirtualMemory ENDP

SysNtWriteVirtualMemory PROC
    mov     r10, rcx
    mov     eax, DWORD PTR g_SyscallTable[32]
    syscall
    ret
SysNtWriteVirtualMemory ENDP

SysNtProtectVirtualMemory PROC
    mov     r10, rcx
    mov     eax, DWORD PTR g_SyscallTable[48]
    syscall
    ret
SysNtProtectVirtualMemory ENDP

SysNtCreateThreadEx PROC
    mov     r10, rcx
    mov     eax, DWORD PTR g_SyscallTable[64]
    syscall
    ret
SysNtCreateThreadEx ENDP

SysNtOpenProcess PROC
    mov     r10, rcx
    mov     eax, DWORD PTR g_SyscallTable[80]
    syscall
    ret
SysNtOpenProcess ENDP

SysNtClose PROC
    mov     r10, rcx
    mov     eax, DWORD PTR g_SyscallTable[96]
    syscall
    ret
SysNtClose ENDP

SysNtQuerySystemInformation PROC
    mov     r10, rcx
    mov     eax, DWORD PTR g_SyscallTable[112]
    syscall
    ret
SysNtQuerySystemInformation ENDP

SysNtCreateSection PROC
    mov     r10, rcx
    mov     eax, DWORD PTR g_SyscallTable[128]
    syscall
    ret
SysNtCreateSection ENDP

SysNtMapViewOfSection PROC
    mov     r10, rcx
    mov     eax, DWORD PTR g_SyscallTable[144]
    syscall
    ret
SysNtMapViewOfSection ENDP

SysNtUnmapViewOfSection PROC
    mov     r10, rcx
    mov     eax, DWORD PTR g_SyscallTable[160]
    syscall
    ret
SysNtUnmapViewOfSection ENDP

SysNtDelayExecution PROC
    mov     r10, rcx
    mov     eax, DWORD PTR g_SyscallTable[176]
    syscall
    ret
SysNtDelayExecution ENDP

SysNtOpenThread PROC
    mov     r10, rcx
    mov     eax, DWORD PTR g_SyscallTable[192]
    syscall
    ret
SysNtOpenThread ENDP

END
