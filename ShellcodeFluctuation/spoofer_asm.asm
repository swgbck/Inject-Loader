.code

EXTERN g_SpoofCtx:BYTE

PUBLIC SpoofedSyscall
PUBLIC SpoofGetRsp

; offsets de SPOOF_CONTEXT
; +00h ReturnGadget
; +08h GadgetStackFix (ULONG)
; +10h RealReturn
; +18h SpoofedRsp

; Syscall direto
; Apos CALL para SpoofedSyscall:
;   ecx = SSN
;   rdx = ignorado
;   r8  = ignorado
;   r9  = arg1
;   [rsp+00h] = return address
;   [rsp+08h] = shadow
;   [rsp+10h] = shadow
;   [rsp+18h] = shadow
;   [rsp+20h] = shadow
;   [rsp+28h] = arg2
;   [rsp+30h] = arg3
;   [rsp+38h] = arg4
;   [rsp+40h] = arg5
;   [rsp+48h] = arg6
SpoofedSyscall PROC
    ; SSN para eax
    mov     eax, ecx
    
    ; Mapear argumentos 1-4 para registradores
    mov     rcx, r9                      ; arg1
    mov     rdx, QWORD PTR [rsp+28h]     ; arg2
    mov     r8,  QWORD PTR [rsp+30h]     ; arg3
    mov     r9,  QWORD PTR [rsp+38h]     ; arg4
    
    ; r10 = rcx (necessario para syscall no Windows)
    mov     r10, rcx
    
    ; Syscall espera arg5 em [rsp+28h], arg6 em [rsp+30h]
    ; Atualmente estao em [rsp+40h] e [rsp+48h]
    ; Diferenca = 18h, entao sub rsp, 18h
    sub     rsp, 18h
    
    ; Agora [rsp+28h] aponta para onde estava [rsp+40h] = arg5
    
    syscall
    
    add     rsp, 18h
    ret
SpoofedSyscall ENDP

SpoofGetRsp PROC
    mov rax, rsp
    ret
SpoofGetRsp ENDP

END
