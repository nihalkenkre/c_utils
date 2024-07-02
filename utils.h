#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>

typedef struct _client_id
{
    HANDLE hUniqueProcess;
    HANDLE hUniqueThread;
} UTILS_CLIENT_ID, *PUTILS_CLIENT_ID;

typedef struct _peb_ldr_data
{
    BYTE DumUtils[32];
    LIST_ENTRY InMemoryOrderModuleList;
} UTILS_PEB_LDR_DATA;

typedef struct _peb
{
    BYTE DumUtils[16];
    PVOID64 ImageBaseAddress;
    UTILS_PEB_LDR_DATA *Ldr;
} UTILS_PEB;

typedef struct _unicode_string
{
    USHORT Length;
    USHORT MaxLength;
    PWSTR Buffer;
} UTILS_UNICODE_STRING, *PUTILS_UNICODE_STRING;

typedef struct _ldr_data_table_entry
{
#ifdef _M_X64
    BYTE DumUtils[48];
    PVOID64 pvDllBase;
    PVOID64 EntryPoint;
    DWORD64 SizeOfImage;
#else
    BYTE DumUtils[24];
    PVOID pvDllBase;
    PVOID EntryPoint;
    DWORD32 SizeOfImage;
#endif
    UTILS_UNICODE_STRING FullDllName;
    UTILS_UNICODE_STRING BaseDllName;
} UTILS_LDR_DATA_TABLE_ENTRY;

typedef struct _object_attributes
{
    ULONG Length;
    HANDLE RootDirectory;
    PUTILS_UNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} UTILS_OBJECT_ATTRIBUTES, *PUTILS_OBJECT_ATTRIBUTES;

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2,
} UTILS_SECTION_INHERIT,
    *PUTILS_SECTION_INHERIT;

#ifdef UTILS_IMPLEMENTATION

HMODULE UtilsGetKernelModuleHandle(void);
LPVOID UtilsGetProcAddressByName(HMODULE hModule, PCSTR cProcName);

void UtilsMemCpy(LPCVOID lpvSrc, LPVOID lpvDst, SIZE_T nBytes)
{
    for (SIZE_T i = 0; i < nBytes; ++i)
    {
        ((BYTE *)lpvDst)[i] = ((BYTE *)lpvSrc)[i];
    }
}

void UtilsMemSet(LPVOID lpvMem, BYTE value, SIZE_T nBytes)
{
    for (SIZE_T i = 0; i < nBytes; ++i)
    {
        ((BYTE *)lpvMem)[i] = value;
    }
}

SIZE_T UtilsStrLen(PCSTR str)
{
    SIZE_T strlen = 0;
    while (*str++ != 0)
    {
        ++strlen;
    }

    return strlen;
}

SIZE_T UtilsWStrLen(PCWSTR wstr)
{
    SIZE_T wstrlen = 0;
    while (*wstr++ != 0)
    {
        ++wstrlen;
    }

    return wstrlen;
}

void UtilsStrCpy(PCSTR sSrc, PSTR sDst)
{
    SIZE_T i = 0;
    while (sSrc[i] != 0)
    {
        sDst[i] = sSrc[i];
        ++i;
    }
    sDst[i] = sSrc[i]; // copy trailing 0
}

void UtilsWStrCpy(PCWSTR sSrc, PWSTR sDst)
{
    SIZE_T i = 0;
    while (sSrc[i] != 0)
    {
        sDst[i] = sSrc[i];
        ++i;
    }
    sDst[i] = sSrc[i]; // copy trailing 0
}

void UtilsWStrCpyA(PCWSTR wsSrc, PSTR sDst)
{
    SIZE_T i = 0;
    while (wsSrc[i] != 0)
    {
        sDst[i] = (CHAR)wsSrc[i];
        ++i;
    }
    sDst[i] = (CHAR)wsSrc[i]; // copy trailing 0
}

void UtilsAStrCpyW(PCSTR sSrc, PWSTR wsDst)
{
    SIZE_T i = 0;
    while (sSrc[i] != 0)
    {
        wsDst[i] = sSrc[i];
        ++i;
    }
    wsDst[i] = sSrc[i]; // coy trailing 0
}

BOOL UtilsStrCmpAW(PCSTR sStr1, PCWSTR sStr2)
{
    SIZE_T i = 0;

    while (sStr1[i] == sStr2[i])
    {
        if (sStr1[i] == 0 && sStr2[i] == 0)
        {
            return TRUE;
        }
        ++i;
    }

    return FALSE;
}

BOOL UtilsStrCmpiAW(PCSTR sStr1, PCWSTR sStr2)
{
    BOOL bAreEqual = TRUE;

    for (SIZE_T i = 0; i < UtilsStrLen(sStr1); ++i)
    {
        if (sStr1[i] != sStr2[i])
        {
            if (sStr1[i] < sStr2[i])
            {
                if ((sStr1[i] + 32) != sStr2[i])
                {
                    bAreEqual = FALSE;
                    break;
                }
            }
            else if (sStr2[i] < sStr2[i])
            {
                if ((sStr2[i] + 32) != sStr1[i])
                {
                    bAreEqual = FALSE;
                    break;
                }
            }
        }
    }

    return bAreEqual;
}

BOOL UtilsStrCmpAA(PCSTR sStr1, PCSTR sStr2)
{
    SIZE_T i = 0;

    while (sStr1[i] == sStr2[i])
    {
        if (sStr1[i] == 0 && sStr2[i] == 0)
        {
            return TRUE;
        }
        ++i;
    }

    return FALSE;
}

BOOL UtilsStrCmpiAA(PCSTR sStr1, PCSTR sStr2)
{
    BOOL bAreEqual = TRUE;

    for (SIZE_T i = 0; i < UtilsStrLen(sStr1); ++i)
    {
        if (sStr1[i] != sStr2[i])
        {
            if (sStr1[i] < sStr2[i])
            {
                if ((sStr1[i] + 32) != sStr2[i])
                {
                    bAreEqual = FALSE;
                    break;
                }
            }
            else if (sStr2[i] < sStr1[i])
            {
                if ((sStr2[i] + 32) != sStr1[i])
                {
                    bAreEqual = FALSE;
                    break;
                }
            }
        }
    }

    return bAreEqual;
}

LPVOID UtilsStrChr(PCSTR sStr, int iCh)
{
    SIZE_T i = 0;

    while (sStr[i] != 0)
    {
        if (sStr[i] == iCh)
            return (LPVOID)(sStr + i);

        ++i;
    }

    return (LPVOID)-1;
}

BOOL UtilsStrContains(PCSTR sFindInStr, PCSTR sFindStr)
{

    return FALSE;
}

void UtilsXor(BYTE *data, SIZE_T data_len, BYTE *key, SIZE_T key_len)
{
    DWORD32 j = 0;

    for (SIZE_T i = 0; i < data_len; ++i)
    {
        if (j == key_len)
            j = 0;

        BYTE bInput = 0;

        for (BYTE b = 0; b < 8; ++b)
        {
            BYTE data_bit_i = _bittest((LONG *)&data[i], b);
            BYTE key_bit_j = _bittest((LONG *)&key[j], b);

            BYTE bit_xor = (data_bit_i != key_bit_j) << b;

            bInput |= bit_xor;
        }

        data[i] = bInput;

        ++j;
    }
}

PSTR UtilsStrDup(PCSTR sStr)
{
    SIZE_T sStrLen = UtilsStrLen(sStr);

    HMODULE hKernel = UtilsGetKernelModuleHandle();

    char cGetProcAddress[] = {0x47, 0x65, 0x74, 0x50, 0x72, 0x6f, 0x63, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0};
    FARPROC(WINAPI * pGetProcAddress)
    (HMODULE hModule, LPCSTR lpProcName) = UtilsGetProcAddressByName(hKernel, cGetProcAddress);

    char cVirtualAlloc[] = {0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6c, 0x41, 0x6c, 0x6c, 0x6f, 0x63, 0};
    LPVOID(WINAPI * pVirtualAlloc)
    (/*Optional*/ LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = pGetProcAddress(hKernel, cVirtualAlloc);

    PSTR sDup = pVirtualAlloc(0, sStrLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    for (SIZE_T c = 0; c < sStrLen; ++c)
    {
        sDup[c] = sStr[c];
    }

    return sDup;
}

LONG RVAToOffset(DWORD rva, IMAGE_SECTION_HEADER *SectionHeaders, WORD SectionHeaderCount)
{
    for (WORD id = 0; id < SectionHeaderCount; ++id)
    {
        if (rva >= SectionHeaders[id].VirtualAddress && rva < SectionHeaders[id].VirtualAddress + SectionHeaders[id].SizeOfRawData)
        {
            return rva - SectionHeaders[id].VirtualAddress + SectionHeaders[id].PointerToRawData;
        }
    }

    return -1;
}

BOOL IsImportDescriptorZero(IMAGE_IMPORT_DESCRIPTOR ImportDirectory)
{
    return ImportDirectory.OriginalFirstThunk == 0 &&
           ImportDirectory.TimeDateStamp == 0 &&
           ImportDirectory.ForwarderChain == 0 &&
           ImportDirectory.Name == 0 &&
           ImportDirectory.FirstThunk == 0;
}

DWORD FindTargetProcessID(PSTR sTargetName)
{
    DWORD dwRetVal = -1;

    HMODULE hKernel = UtilsGetKernelModuleHandle();

    char cGetProcAddress[] = {0x47, 0x65, 0x74, 0x50, 0x72, 0x6f, 0x63, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0};
    FARPROC(WINAPI * pGetProcAddress)
    (HMODULE hModule, LPCSTR lpProcName) = UtilsGetProcAddressByName(hKernel, cGetProcAddress);

    char cCreateToolhelp32Snapshot[] = {0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x6f, 0x6f, 0x6c, 0x68, 0x65, 0x6c, 0x70, 0x33, 0x32, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0};
    HANDLE(WINAPI * pCreateToolhelp32Snapshot)
    (DWORD dwFlags, DWORD th32ProcessID) = pGetProcAddress(hKernel, cCreateToolhelp32Snapshot);

    HANDLE hSnapShot = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapShot == INVALID_HANDLE_VALUE)
    {
        return dwRetVal;
    }

    PROCESSENTRY32 ProcessEntry;
    ProcessEntry.dwSize = sizeof(PROCESSENTRY32);

    char cProcess32First[] = {0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x33, 0x32, 0x46, 0x69, 0x72, 0x73, 0x74, 0};
    BOOL(WINAPI * pProcess32First)
    (HANDLE hSnapshot, LPPROCESSENTRY32 lppe) = pGetProcAddress(hKernel, cProcess32First);

    if (!pProcess32First(hSnapShot, &ProcessEntry))
    {
        goto shutdown;
    }

    char cProcess32Next[] = {0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x33, 0x32, 0x4e, 0x65, 0x78, 0x74, 0};
    BOOL(WINAPI * pProcess32Next)
    (HANDLE hSnapshot, LPPROCESSENTRY32 lppe) = pGetProcAddress(hKernel, cProcess32Next);

    while (pProcess32Next(hSnapShot, &ProcessEntry))
    {
        if (UtilsStrCmpiAA(sTargetName, ProcessEntry.szExeFile))
        {
            return ProcessEntry.th32ProcessID;
        }
    }

shutdown:

    char cCloseHandle[] = {0x43, 0x6c, 0x6f, 0x73, 0x65, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0};
    BOOL(WINAPI * pCloseHandle)
    (HANDLE hObject) = pGetProcAddress(hKernel, cCloseHandle);

    pCloseHandle(hSnapShot);

    return dwRetVal;
}

HANDLE FindProcessThread(DWORD dwPid)
{
    HMODULE hKernel = UtilsGetKernelModuleHandle();

    char cGetProcAddress[] = {0x47, 0x65, 0x74, 0x50, 0x72, 0x6f, 0x63, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0};
    FARPROC(WINAPI * pGetProcAddress)
    (HMODULE hModule, LPCSTR lpProcName) = UtilsGetProcAddressByName(hKernel, cGetProcAddress);

    char cCreateToolhelp32Snapshot[] = {0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x6f, 0x6f, 0x6c, 0x68, 0x65, 0x6c, 0x70, 0x33, 0x32, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0};
    HANDLE(WINAPI * pCreateToolhelp32Snapshot)
    (DWORD dwFlags, DWORD th32ProcessID) = pGetProcAddress(hKernel, cCreateToolhelp32Snapshot);

    HANDLE hSnapShot = pCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (hSnapShot == NULL)
    {
        goto shutdown;
    }

    THREADENTRY32 ThreadEntry;
    ThreadEntry.dwSize = sizeof(THREADENTRY32);

    char cThread32First[] = {0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x33, 0x32, 0x46, 0x69, 0x72, 0x73, 0x74, 0};
    BOOL(WINAPI * pThread32First)
    (HANDLE hSnapshot, LPTHREADENTRY32 lppe) = pGetProcAddress(hKernel, cThread32First);

    if (!pThread32First(hSnapShot, &ThreadEntry))
    {
        goto shutdown;
    }

    char cThread32Next[] = {0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x33, 0x32, 0x46, 0x69, 0x72, 0x73, 0x74, 0};
    BOOL(WINAPI * pThread32Next)
    (HANDLE hSnapshot, LPTHREADENTRY32 lppe) = pGetProcAddress(hKernel, cThread32Next);

    while (pThread32Next(hSnapShot, &ThreadEntry))
    {
        if (ThreadEntry.th32OwnerProcessID == dwPid)
        {
            char cOpenThread[] = {0x4f, 0x70, 0x65, 0x6e, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0};
            HANDLE(WINAPI * pOpenThread)
            (DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadID) = pGetProcAddress(hKernel, cOpenThread);

            return pOpenThread(THREAD_ALL_ACCESS, FALSE, ThreadEntry.th32ThreadID);
        }
    }

shutdown:
    return NULL;
}

HMODULE UtilsGetKernelModuleHandle(void)
{
#ifdef _M_X64
    PEB *pPeb = (PEB *)__readgsqword(0x60);
#else
    PEB *pPeb = (PEB *)__readfsdword(0x30);
#endif

    LIST_ENTRY *FirstListEntry = &pPeb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY *CurrentListEntry = FirstListEntry->Flink;

    char cKernelDLL[] = {0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c, 0};

    while (CurrentListEntry != FirstListEntry)
    {
        UTILS_LDR_DATA_TABLE_ENTRY *TableEntry = (UTILS_LDR_DATA_TABLE_ENTRY *)((ULONG_PTR)CurrentListEntry - sizeof(LIST_ENTRY));

        if (UtilsStrCmpiAW(cKernelDLL, TableEntry->BaseDllName.Buffer))
        {
            return (HMODULE)TableEntry->pvDllBase;
        }

        CurrentListEntry = CurrentListEntry->Flink;
    }

    return NULL;
}

LPVOID UtilsGetProcAddressByName(HMODULE ulModuleAddr, PCSTR sProcName)
{
    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)ulModuleAddr;
    IMAGE_NT_HEADERS *NTHeaders = (IMAGE_NT_HEADERS *)(ulModuleAddr + DosHeader->e_lfanew);

    IMAGE_DATA_DIRECTORY ExportDataDirectory = NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY *ExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(ulModuleAddr + ExportDataDirectory.VirtualAddress);

    DWORD *AddressOfFunctions = (DWORD *)(ulModuleAddr + ExportDirectory->AddressOfFunctions);
    DWORD *AddressOfNames = (DWORD *)(ulModuleAddr + ExportDirectory->AddressOfNames);
    WORD *AddressOfNameOridinals = (WORD *)(ulModuleAddr + ExportDirectory->AddressOfNameOrdinals);

    ULONG_PTR lpvProcAddr = 0;
    for (DWORD n = 0; n < ExportDirectory->NumberOfNames; ++n)
    {
        if (UtilsStrCmpiAA(sProcName, (PSTR)(ulModuleAddr + AddressOfNames[n])))
        {
            lpvProcAddr = (ULONG_PTR)ulModuleAddr + (ULONG_PTR)AddressOfFunctions[AddressOfNameOridinals[n]];
            break;
        }
    }

    // Code to get address of forwarded functions
    // Redundant since function pointers can be got by GetProcAddress, which in turn is got by the code above these comments, and it is
    // always available in kernel32.dll
    // Fun to code
    // if ((lpvProcAddr > (ulModuleAddr + ExportDataDirectory.VirtualAddress)) && (lpvProcAddr <= (ulModuleAddr + ExportDataDirectory.VirtualAddress + ExportDataDirectory.Size)))
    // {
    //     CHAR DLLFunctionName[256];
    //     UtilsStrCpy(DLLFunctionName, lpvProcAddr);
    //     PSTR FunctionName = UtilsStrChr(DLLFunctionName, '.');

    //     *FunctionName = 0;
    //     ++FunctionName;

    //     HMODULE ForwardedDLL = pLoadLibraryA(DLLFunctionName);
    //     lpvProcAddr = UtilsGetProcAddressByName((BYTE *)ForwardedDLL, FunctionName);
    // }

    return (LPVOID)lpvProcAddr;
}

#endif // UITLS_IMPLEMENTATION