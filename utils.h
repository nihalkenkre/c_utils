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

typedef struct _sprinf_args
{
    SIZE_T argsCount;
    DWORD64 args[32];
} SPRINTF_ARGS, *PSPRINTF_ARGS;

#ifdef UTILS_IMPLEMENTATION

ULONG_PTR UtilsGetKernelModuleHandle(void);
LPVOID UtilsGetProcAddressByName(ULONG_PTR hModule, PCSTR cProcName);
BOOL UtilsWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

HANDLE UtilsGetStdHandle(DWORD nStdHandle)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    CHAR cGetStdHandle[] = {0x47, 0x65, 0x74, 0x53, 0x74, 0x64, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0};
    HANDLE(WINAPI * pGetStdHandle)
    (DWORD nStdHandle) = UtilsGetProcAddressByName(ulKernel, cGetStdHandle);

    return pGetStdHandle(nStdHandle);
}

BOOL UtilsWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOveralapped)
{
    ULONG_PTR uiKernel = UtilsGetKernelModuleHandle();

    CHAR cWriteFile[] = {0x57, 0x72, 0x69, 0x74, 0x65, 0x46, 0x69, 0x6c, 0x65, 0};
    BOOL(WINAPI * pWriteFile)
    (HANDLE hFile, LPCVOID lpbuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) = UtilsGetProcAddressByName(uiKernel, cWriteFile);

    return pWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOveralapped);
}

HANDLE UtilsCreateToolhelp32Snapshot(DWORD dwFlags, DWORD dwTh32ProcessID)
{
    ULONG_PTR hKernel = UtilsGetKernelModuleHandle();

    CHAR cCreateToolhelp32Snapshot[] = {0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x6f, 0x6f, 0x6c, 0x68, 0x65, 0x6c, 0x70, 0x33, 0x32, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0};
    HANDLE(WINAPI * pCreateToolhelp32Snapshot)
    (DWORD dwFlags, DWORD th32ProcessID) = UtilsGetProcAddressByName(hKernel, cCreateToolhelp32Snapshot);

    return pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
}

BOOL UtilsProcess32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
{
    ULONG_PTR hKernel = UtilsGetKernelModuleHandle();

    CHAR cProcess32First[] = {0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x33, 0x32, 0x46, 0x69, 0x72, 0x73, 0x74, 0};
    BOOL(WINAPI * pProcess32First)
    (HANDLE hSnapshot, LPPROCESSENTRY32 lppe) = UtilsGetProcAddressByName(hKernel, cProcess32First);

    return pProcess32First(hSnapshot, lppe);
}

BOOL UtilsProcess32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
{
    ULONG_PTR hKernel = UtilsGetKernelModuleHandle();

    CHAR cProcess32Next[] = {0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x33, 0x32, 0x4e, 0x65, 0x78, 0x74, 0};
    BOOL(WINAPI * pProcess32Next)
    (HANDLE hSnapshot, LPPROCESSENTRY32 lppe) = UtilsGetProcAddressByName(hKernel, cProcess32Next);

    return pProcess32Next(hSnapshot, lppe);
}

BOOL UtilsCloseHandle(HANDLE hHandle)
{
    ULONG_PTR hKernel = UtilsGetKernelModuleHandle();

    CHAR cCloseHandle[] = {0x43, 0x6c, 0x6f, 0x73, 0x65, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0};
    BOOL(WINAPI * pCloseHandle)
    (HANDLE hObject) = UtilsGetProcAddressByName(hKernel, cCloseHandle);

    return pCloseHandle(hHandle);
}

HANDLE UtilsOpenThread(DWORD dwDesiredAccess, BOOL bInherhitHandle, DWORD dwThreadID)
{
    ULONG_PTR hKernel = UtilsGetKernelModuleHandle();

    CHAR cOpenThread[] = {0x4f, 0x70, 0x65, 0x6e, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0};
    HANDLE(WINAPI * pOpenThread)
    (DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadID) = UtilsGetProcAddressByName(hKernel, cOpenThread);

    return pOpenThread(dwDesiredAccess, bInherhitHandle, dwThreadID);
}

HANDLE UtilsLoadLibraryA(LPCSTR lpLibFileName)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    CHAR cLoadLibraryA[] = {0x4c, 0x6f, 0x61, 0x64, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x41, 0};
    HMODULE(WINAPI * pLoadLibrary)
    (LPCSTR lpLibFileName) = UtilsGetProcAddressByName(ulKernel, cLoadLibraryA);

    return pLoadLibrary(lpLibFileName);
}

LPVOID UtilsVirtualAlloc(PVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    ULONG_PTR hKernel = UtilsGetKernelModuleHandle();

    CHAR cVirtualAlloc[] = {0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6c, 0x41, 0x6c, 0x6c, 0x6f, 0x63, 0};
    LPVOID(WINAPI * pVirtualAlloc)
    (PVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = UtilsGetProcAddressByName(hKernel, cVirtualAlloc);

    return pVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL UtilsVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    ULONG_PTR hKernel = UtilsGetKernelModuleHandle();

    CHAR cVirtualFree[] = {0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6c, 0x46, 0x72, 0x65, 0x65, 0};
    BOOL(WINAPI * pVirtualFree)
    (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) = UtilsGetProcAddressByName(hKernel, cVirtualFree);

    return pVirtualFree(lpAddress, 0, MEM_RELEASE);
}

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

SIZE_T UtilsStrCpy(PCSTR sSrc, PSTR sDst)
{
    SIZE_T i = 0;
    while (sSrc[i] != 0)
    {
        sDst[i] = sSrc[i];
        ++i;
    }
    sDst[i] = sSrc[i]; // copy trailing 0

    return i;
}

SIZE_T UtilsWStrCpy(PCWSTR sSrc, PWSTR sDst)
{
    SIZE_T i = 0;
    while (sSrc[i] != 0)
    {
        sDst[i] = sSrc[i];
        ++i;
    }
    sDst[i] = sSrc[i]; // copy trailing 0

    return i;
}

SIZE_T UtilsWStrCpyA(PCWSTR wsSrc, PSTR sDst)
{
    SIZE_T i = 0;
    while (wsSrc[i] != 0)
    {
        sDst[i] = (CHAR)wsSrc[i];
        ++i;
    }
    sDst[i] = (CHAR)wsSrc[i]; // copy trailing 0

    return i;
}

SIZE_T UtilsAStrCpyW(PCSTR sSrc, PWSTR wsDst)
{
    SIZE_T i = 0;
    while (sSrc[i] != 0)
    {
        wsDst[i] = sSrc[i];
        ++i;
    }
    wsDst[i] = sSrc[i]; // coy trailing 0

    return i;
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

PCSTR UtilsStrStr(PCSTR sFindInStr, PCSTR sFindStr)
{
    PCSTR offset = NULL;

    for (SIZE_T i = 0; sFindInStr[i] != 0; ++i)
    {
        for (SIZE_T j = 0; sFindStr[j] != 0; ++j)
        {
            if (sFindInStr[i] == sFindStr[j])
            {
                if (offset == NULL)
                    offset = sFindInStr + i;

                ++i;
            }
            else
            {
                offset = NULL;
                break;
            }
        }
        if (offset != NULL)
        {
            return offset;
        }
    }

    return 0;
}

PCWSTR UtilsWStrWStr(PCWSTR sFindInStr, PCWSTR sFindStr)
{
    PCWSTR offset = NULL;

    for (SIZE_T i = 0; sFindInStr[i] != 0; ++i)
    {
        for (SIZE_T j = 0; sFindStr[j] != 0; ++j)
        {
            if (sFindInStr[i] == sFindStr[j])
            {
                if (offset == NULL)
                    offset = sFindInStr + i;

                ++i;
            }
            else
            {
                offset = NULL;
                break;
            }
        }
        if (offset != NULL)
        {
            return offset;
        }
    }

    return 0;
}

void UtilsStrAppend(PSTR sStr, PSTR sApp)
{
    PSTR sDst = sStr + UtilsStrLen(sStr);

    UtilsStrCpy(sApp, sDst);
}

void UtilsWStrAppend(PWSTR wsStr, PWSTR wsApp)
{
    PWSTR wsDst = wsStr + UtilsWStrLen(wsStr);

    UtilsWStrCpy(wsApp, wsDst);
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

    PSTR sDup = (PSTR)UtilsVirtualAlloc(0, sStrLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    for (SIZE_T c = 0; c < sStrLen; ++c)
    {
        sDup[c] = sStr[c];
    }

    return sDup;
}

void UtilsSprintf(PSTR pBuffer, PSTR pString, SPRINTF_ARGS sprintfArgs)
{
    SIZE_T stringIndex = 0;
    SIZE_T bufferIndex = 0;
    SIZE_T argIndex = 0;

    while (pString[stringIndex] != 0)
    {
        if (pString[stringIndex] == '%')
        {
            if (pString[stringIndex + 1] == 's')
            {
                if (pString[stringIndex + 2] == 'b')
                {
                    PCSTR arg = (PCSTR)sprintfArgs.args[argIndex];

                    bufferIndex += UtilsStrCpy(arg, pBuffer + bufferIndex);
                }
                else if (pString[stringIndex + 2] == 'w')
                {
                    PCWSTR arg = (PCWSTR)sprintfArgs.args[argIndex];

                    bufferIndex += UtilsWStrCpyA(arg, pBuffer + bufferIndex);
                }

                stringIndex += 3;
                ++argIndex;
                continue;
            }
            else if (pString[stringIndex + 1] == 'd')
            {
                CHAR tempString[32];
                INT64 tempStringIndex = 0;

                DWORD64 arg = (DWORD64)sprintfArgs.args[argIndex];

                if (arg == 0)
                {
                    pBuffer[bufferIndex++] = 0x30;
                }
                else
                {
                    while (arg > 0)
                    {
                        tempString[tempStringIndex++] = arg % 10 + 48;
                        arg /= 10;
                    }

                    while (--tempStringIndex >= 0)
                    {
                        pBuffer[bufferIndex++] = tempString[tempStringIndex];
                    }
                }

                stringIndex += 2;
                ++argIndex;
                continue;
            }
            else if (pString[stringIndex + 1] == 'x')
            {
                CHAR tempString[32];
                UtilsMemSet(tempString, 0, 32);

                INT64 tempStringIndex = 0;
                CHAR cHexDigits[] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0};
                DWORD64 arg = (DWORD64)sprintfArgs.args[argIndex];
                DWORD64 dwMask = 0xF;

                if (arg == 0)
                {
                    pBuffer[bufferIndex++] = 0x30;
                }
                else
                {
                    while (arg > 0)
                    {
                        tempString[tempStringIndex++] = cHexDigits[arg & dwMask];
                        arg >>= 4;
                    }

                    pBuffer[bufferIndex++] = '0';
                    pBuffer[bufferIndex++] = 'x';
                    while (--tempStringIndex >= 0)
                    {
                        pBuffer[bufferIndex++] = tempString[tempStringIndex];
                    }
                }

                stringIndex += 2;
                ++argIndex;
                continue;
            }
        }
        else
        {
            pBuffer[bufferIndex++] = pString[stringIndex];
        }
        ++stringIndex;
    }

    pBuffer[bufferIndex] = pString[stringIndex]; // copy trailing zero
}

void UtilsWSprintf(PWSTR pBuffer, PWSTR pString, SPRINTF_ARGS sprintfArgs)
{
    SIZE_T stringIndex = 0;
    SIZE_T bufferIndex = 0;
    SIZE_T argIndex = 0;

    while (pString[stringIndex] != 0)
    {
        if (pString[stringIndex] == '%')
        {
            if (pString[stringIndex + 1] == 's')
            {
                if (pString[stringIndex + 2] == 'b')
                {
                    PCSTR arg = (PCSTR)sprintfArgs.args[argIndex];

                    bufferIndex += UtilsAStrCpyW(arg, pBuffer + bufferIndex);
                }
                else if (pString[stringIndex + 2] == 'w')
                {
                    PCWSTR arg = (PCWSTR)sprintfArgs.args[argIndex];

                    bufferIndex += UtilsWStrCpy(arg, pBuffer + bufferIndex);
                }

                stringIndex += 3;
                ++argIndex;
                continue;
            }
            else if (pString[stringIndex + 1] == 'd')
            {
                WCHAR tempString[32];
                INT64 tempStringIndex = 0;

                DWORD64 arg = (DWORD64)sprintfArgs.args[argIndex];

                if (arg == 0)
                {
                    pBuffer[bufferIndex++] = 0x30;
                }
                else
                {
                    while (arg > 0)
                    {
                        tempString[tempStringIndex++] = arg % 10 + 48;
                        arg /= 10;
                    }

                    while (--tempStringIndex >= 0)
                    {
                        pBuffer[bufferIndex++] = tempString[tempStringIndex];
                    }
                }

                stringIndex += 2;
                ++argIndex;
                continue;
            }
            else if (pString[stringIndex + 1] == 'x')
            {
                WCHAR tempString[32];
                UtilsMemSet(tempString, 0, 32);

                INT64 tempStringIndex = 0;
                CHAR cHexDigits[] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0};
                DWORD64 arg = (DWORD64)sprintfArgs.args[argIndex];
                DWORD64 dwMask = 0xF;

                if (arg == 0)
                {
                    pBuffer[bufferIndex++] = 0x30;
                }
                else
                {
                    while (arg > 0)
                    {
                        tempString[tempStringIndex++] = cHexDigits[arg & dwMask];
                        arg >>= 4;
                    }

                    pBuffer[bufferIndex++] = '0';
                    pBuffer[bufferIndex++] = 'x';
                    while (--tempStringIndex >= 0)
                    {
                        pBuffer[bufferIndex++] = tempString[tempStringIndex];
                    }
                }

                stringIndex += 2;
                ++argIndex;
                continue;
            }
        }
        else
        {
            pBuffer[bufferIndex++] = pString[stringIndex];
        }
        ++stringIndex;
    }

    pBuffer[bufferIndex] = pString[stringIndex]; // copy trailing zero
}

void UtilsPrintConsole(PCSTR pString)
{
    UtilsWriteFile(UtilsGetStdHandle(-11), pString, (DWORD)UtilsStrLen(pString), NULL, NULL);
}

void UtilsWPrintConsole(PCWSTR pWString)
{
    UtilsWriteFile(UtilsGetStdHandle(-11), pWString, (DWORD)UtilsWStrLen(pWString) * sizeof(WCHAR), NULL, NULL);
}

DWORD UtilsFindTargetProcessID(PSTR sTargetName)
{
    DWORD dwRetVal = -1;

    HANDLE hSnapshot = UtilsCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return dwRetVal;
    }

    PROCESSENTRY32 ProcessEntry;
    ProcessEntry.dwSize = sizeof(PROCESSENTRY32);

    if (!UtilsProcess32First(hSnapshot, &ProcessEntry))
    {
        goto shutdown;
    }

    do
    {
        if (UtilsStrCmpiAA(sTargetName, ProcessEntry.szExeFile))
        {
            UtilsCloseHandle(hSnapshot);
            return ProcessEntry.th32ProcessID;
        }
    } while (UtilsProcess32Next(hSnapshot, &ProcessEntry));

shutdown:

    UtilsCloseHandle(hSnapshot);
    return dwRetVal;
}


ULONG_PTR UtilsGetKernelModuleHandle(void)
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
            return (ULONG_PTR)TableEntry->pvDllBase;
        }

        CurrentListEntry = CurrentListEntry->Flink;
    }

    return 0;
}

LPVOID UtilsGetProcAddressByName(ULONG_PTR ulModuleAddr, PCSTR sProcName)
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
        if (UtilsStrCmpiAA(sProcName, (PCSTR)(ulModuleAddr + AddressOfNames[n])))
        {
            lpvProcAddr = ulModuleAddr + (ULONG_PTR)AddressOfFunctions[AddressOfNameOridinals[n]];
            break;
        }
    }

    if ((lpvProcAddr > (ulModuleAddr + ExportDataDirectory.VirtualAddress)) && (lpvProcAddr <= (ulModuleAddr + ExportDataDirectory.VirtualAddress + ExportDataDirectory.Size)))
    {
        CHAR DLLFunctionName[256];
        UtilsStrCpy(DLLFunctionName, (PSTR)lpvProcAddr);
        PSTR FunctionName = UtilsStrChr(DLLFunctionName, '.');

        *FunctionName = 0;
        ++FunctionName;

        HMODULE ForwardedDLL = UtilsLoadLibraryA(DLLFunctionName);
        lpvProcAddr = (ULONG_PTR)UtilsGetProcAddressByName((ULONG_PTR)ForwardedDLL, FunctionName);
    }

    return (LPVOID)lpvProcAddr;
}

#endif // UITLS_IMPLEMENTATION