#include "spoofer.h"
#include "strenc.h"

extern "C" SPOOF_CONTEXT g_SpoofCtx = { 0 };

// varre secoes executaveis do modulo procurando "add rsp, N ; ret"
// o N precisa ser >= 0x20 e multiplo de 8 pra nao quebrar o stack
PVOID FindReturnGadget(PVOID hModule, ULONG* outStackFix)
{
    if (!hModule || !outStackFix) return nullptr;

    BYTE* base = (BYTE*)hModule;
    IMAGE_DOS_HEADER*   dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS64* nt  = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    if (nt->Signature != IMAGE_NT_SIGNATURE)  return nullptr;

    IMAGE_SECTION_HEADER* secs = IMAGE_FIRST_SECTION(nt);
    WORD nSecs = nt->FileHeader.NumberOfSections;

    for (WORD s = 0; s < nSecs; s++)
    {
        if (!(secs[s].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

        BYTE* sec  = base + secs[s].VirtualAddress;
        DWORD size = secs[s].Misc.VirtualSize;

        for (DWORD i = 0; i + 5 < size; i++)
        {
            // 48 83 C4 XX C3 -> add rsp, XX ; ret
            if (sec[i] == 0x48 && sec[i+1] == 0x83 &&
                sec[i+2] == 0xC4 && sec[i+4] == 0xC3)
            {
                BYTE n = sec[i+3];
                if (n >= 0x20 && n <= 0x78 && (n & 7) == 0)
                {
                    *outStackFix = (ULONG)n;
                    return (PVOID)(sec + i);
                }
            }
        }
    }

    return nullptr;
}

PVOID FindReturnGadgetByName(const char* moduleName, ULONG* outStackFix)
{
    wchar_t wname[64] = { 0 };
    for (int i = 0; moduleName[i] && i < 63; i++)
        wname[i] = (wchar_t)moduleName[i];

    PVOID hMod = PebGetModuleBase(wname);
    if (!hMod) return nullptr;
    return FindReturnGadget(hMod, outStackFix);
}

// tenta achar gadget no ntdll primeiro, cai pra kernelbase/kernel32 se falhar
extern "C" BOOL InitStackSpoofer()
{
    ULONG fix   = 0;
    PVOID gadget = nullptr;

    gadget = FindReturnGadgetByName(ENC("ntdll.dll"), &fix);
    
    if (!gadget) {
        gadget = FindReturnGadgetByName(ENC("kernelbase.dll"), &fix);
    }
    
    if (!gadget) {
        gadget = FindReturnGadgetByName(ENC("kernel32.dll"), &fix);
    }
    
    if (!gadget) {
        return FALSE;
    }

    g_SpoofCtx.ReturnGadget   = gadget;
    g_SpoofCtx.GadgetStackFix = fix;
    g_SpoofCtx.RealReturn     = nullptr;
    g_SpoofCtx.SpoofedRsp     = nullptr;

    return TRUE;
}
