#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <windows.h>
#include "strenc.h"

#pragma warning(push)
#pragma warning(disable: 4005)

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#pragma warning(pop)

#define SystemProcessInformation 5

typedef LONG NTSTATUS;

#ifndef NT_SUCCESS
#define NT_SUCCESS(st) (((NTSTATUS)(st)) >= 0)
#endif

#ifndef MY_UNICODE_STRING_DEFINED
#define MY_UNICODE_STRING_DEFINED
typedef struct _MY_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} MY_UNICODE_STRING, *PMY_UNICODE_STRING;
#endif

#ifndef MY_OBJECT_ATTRIBUTES_DEFINED
#define MY_OBJECT_ATTRIBUTES_DEFINED
typedef struct _MY_OBJECT_ATTRIBUTES {
    ULONG              Length;
    HANDLE             RootDirectory;
    PMY_UNICODE_STRING ObjectName;
    ULONG              Attributes;
    PVOID              SecurityDescriptor;
    PVOID              SecurityQualityOfService;
} MY_OBJECT_ATTRIBUTES, *PMY_OBJECT_ATTRIBUTES;
#endif

#ifndef MY_CLIENT_ID_DEFINED
#define MY_CLIENT_ID_DEFINED
typedef struct _MY_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} MY_CLIENT_ID, *PMY_CLIENT_ID;
#endif

#ifndef MY_PS_ATTRIBUTE_DEFINED
#define MY_PS_ATTRIBUTE_DEFINED
typedef struct _MY_PS_ATTRIBUTE {
    ULONG_PTR Attribute;
    SIZE_T    Size;
    union {
        ULONG_PTR Value;
        PVOID     ValuePtr;
    };
    PSIZE_T ReturnLength;
} MY_PS_ATTRIBUTE, *PMY_PS_ATTRIBUTE;

typedef struct _MY_PS_ATTRIBUTE_LIST {
    SIZE_T          TotalLength;
    MY_PS_ATTRIBUTE Attributes[1];
} MY_PS_ATTRIBUTE_LIST, *PMY_PS_ATTRIBUTE_LIST;
#endif

#ifndef MY_SYSTEM_PROCESS_INFORMATION_DEFINED
#define MY_SYSTEM_PROCESS_INFORMATION_DEFINED

typedef struct _MY_SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG         WaitTime;
    PVOID         StartAddress;
    MY_CLIENT_ID  ClientId;
    LONG          Priority;
    LONG          BasePriority;
    ULONG         ContextSwitchCount;
    ULONG         ThreadState;
    ULONG         WaitReason;
    ULONG         Pad;
} MY_SYSTEM_THREAD_INFORMATION, *PMY_SYSTEM_THREAD_INFORMATION;

typedef struct _MY_SYSTEM_PROCESS_INFORMATION {
    ULONG             NextEntryOffset;
    ULONG             NumberOfThreads;
    LARGE_INTEGER     WorkingSetPrivateSize;
    ULONG             HardFaultCount;
    ULONG             NumberOfThreadsHighWatermark;
    ULONGLONG         CycleTime;
    LARGE_INTEGER     CreateTime;
    LARGE_INTEGER     UserTime;
    LARGE_INTEGER     KernelTime;
    MY_UNICODE_STRING ImageName;
    LONG              BasePriority;
    HANDLE            UniqueProcessId;
    HANDLE            InheritedFromUniqueProcessId;
    ULONG             HandleCount;
    ULONG             SessionId;
    ULONG_PTR         UniqueProcessKey;
    SIZE_T            PeakVirtualSize;
    SIZE_T            VirtualSize;
    ULONG             PageFaultCount;
    ULONG             Pad1;
    SIZE_T            PeakWorkingSetSize;
    SIZE_T            WorkingSetSize;
    SIZE_T            QuotaPeakPagedPoolUsage;
    SIZE_T            QuotaPagedPoolUsage;
    SIZE_T            QuotaPeakNonPagedPoolUsage;
    SIZE_T            QuotaNonPagedPoolUsage;
    SIZE_T            PagefileUsage;
    SIZE_T            PeakPagefileUsage;
    SIZE_T            PrivatePageCount;
    LARGE_INTEGER     ReadOperationCount;
    LARGE_INTEGER     WriteOperationCount;
    LARGE_INTEGER     OtherOperationCount;
    LARGE_INTEGER     ReadTransferCount;
    LARGE_INTEGER     WriteTransferCount;
    LARGE_INTEGER     OtherTransferCount;
} MY_SYSTEM_PROCESS_INFORMATION, *PMY_SYSTEM_PROCESS_INFORMATION;
#endif

typedef struct _SYSCALL_ENTRY {
    DWORD ssn;
    PVOID syscallAddress;
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

inline PVOID PebGetModuleBase(const wchar_t* modName)
{
    typedef struct _PEB_LDR_DATA_INTERNAL {
        ULONG      Length;
        BOOLEAN    Initialized;
        PVOID      SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
    } PEB_LDR_DATA_INTERNAL;

    typedef struct _LDR_DATA_TABLE_ENTRY_INTERNAL {
        LIST_ENTRY        InLoadOrderLinks;
        LIST_ENTRY        InMemoryOrderLinks;
        LIST_ENTRY        InInitializationOrderLinks;
        PVOID             DllBase;
        PVOID             EntryPoint;
        ULONG             SizeOfImage;
        MY_UNICODE_STRING FullDllName;
        MY_UNICODE_STRING BaseDllName;
    } LDR_DATA_TABLE_ENTRY_INTERNAL;

#if defined(_WIN64)
    BYTE* peb = (BYTE*)__readgsqword(0x60);
    if (!peb) return nullptr;
    PEB_LDR_DATA_INTERNAL* ldr = *(PEB_LDR_DATA_INTERNAL**)(peb + 0x18);
#else
    BYTE* peb = (BYTE*)__readfsdword(0x30);
    if (!peb) return nullptr;
    PEB_LDR_DATA_INTERNAL* ldr = *(PEB_LDR_DATA_INTERNAL**)(peb + 0x0C);
#endif

    if (!ldr) return nullptr;

    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    LIST_ENTRY* cur = head->Flink;

    while (cur && cur != head)
    {
        LDR_DATA_TABLE_ENTRY_INTERNAL* entry = (LDR_DATA_TABLE_ENTRY_INTERNAL*)cur;
        
        if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0 && entry->DllBase)
        {
            const wchar_t* a = modName;
            const wchar_t* b = entry->BaseDllName.Buffer;
            BOOL match = TRUE;
            
            while (*a && *b)
            {
                wchar_t ca = (*a >= L'A' && *a <= L'Z') ? (*a + 32) : *a;
                wchar_t cb = (*b >= L'A' && *b <= L'Z') ? (*b + 32) : *b;
                if (ca != cb) { match = FALSE; break; }
                a++; b++;
            }
            
            if (match && *a == 0)
            {
                return entry->DllBase;
            }
        }
        cur = cur->Flink;
    }
    return nullptr;
}

inline PVOID PebGetProcAddr(PVOID moduleBase, const char* funcName)
{
    if (!moduleBase || !funcName) return nullptr;

    BYTE* base = (BYTE*)moduleBase;
    IMAGE_DOS_HEADER*   dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS64* nt  = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);

    DWORD expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRva) return nullptr;

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + expRva);
    DWORD* names  = (DWORD*)(base + exp->AddressOfNames);
    WORD*  ords   = (WORD*) (base + exp->AddressOfNameOrdinals);
    DWORD* funcs  = (DWORD*)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++)
    {
        const char* name = (const char*)(base + names[i]);
        const char* a = funcName;
        const char* b = name;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == 0 && *b == 0)
            return (PVOID)(base + funcs[ords[i]]);
    }
    return nullptr;
}

extern "C" NTSTATUS SysNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
extern "C" NTSTATUS SysNtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
extern "C" NTSTATUS SysNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
extern "C" NTSTATUS SysNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
extern "C" NTSTATUS SysNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PMY_OBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PMY_PS_ATTRIBUTE_LIST AttributeList);
extern "C" NTSTATUS SysNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PMY_OBJECT_ATTRIBUTES ObjectAttributes, PMY_CLIENT_ID ClientId);
extern "C" NTSTATUS SysNtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PMY_OBJECT_ATTRIBUTES ObjectAttributes, PMY_CLIENT_ID ClientId);
extern "C" NTSTATUS SysNtClose(HANDLE Handle);
extern "C" NTSTATUS SysNtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

extern "C" NTSTATUS SysNtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, PMY_OBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
extern "C" NTSTATUS SysNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, ULONG InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
extern "C" NTSTATUS SysNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);
extern "C" NTSTATUS SysNtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);

BOOL InitializeSyscalls();

#endif
