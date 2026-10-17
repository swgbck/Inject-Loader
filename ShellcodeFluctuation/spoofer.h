#pragma once
#include "syscalls.h"

typedef struct _SPOOF_CONTEXT {
    PVOID ReturnGadget;    // endereco do "add rsp, N ; ret" no ntdll
    ULONG GadgetStackFix;  // valor do n
    PVOID RealReturn;      // ret original salvo antes de substituir
    PVOID SpoofedRsp;      // ponteiro pro slot que foi modificado
} SPOOF_CONTEXT, *PSPOOF_CONTEXT;

extern "C" SPOOF_CONTEXT g_SpoofCtx;

extern "C" BOOL  InitStackSpoofer();
PVOID FindReturnGadget(PVOID hModule, ULONG* outStackFix);
PVOID FindReturnGadgetByName(const char* moduleName, ULONG* outStackFix);

extern "C" NTSTATUS SpoofedSyscall(DWORD ssn, PVOID syscallAddr, ULONG64 argCount, ...);
