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
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} UTILS_LDR_DATA_TABLE_ENTRY;

typedef struct _object_attributes
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
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
ULONG_PTR UtilsGetNtdllModuleHandle(void);
LPVOID UtilsGetProcAddressByName(ULONG_PTR ulModule, PCSTR cProcName);
LPVOID UtilsGetProcAddressByHash(ULONG_PTR ulModule, DWORD64 dwProcNameHash);
BOOL UtilsWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
DWORD64 UtilsStrHash(PCSTR sString);
DWORD64 UtilsWStrHash(PCWSTR wsString);

HANDLE UtilsGetStdHandle(DWORD nStdHandle)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    HANDLE(WINAPI * pGetStdHandle)
    (DWORD nStdHandle) = UtilsGetProcAddressByHash(ulKernel, 0x12a2e2919);

    return pGetStdHandle(nStdHandle);
}

HANDLE UtilsOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    HANDLE(WINAPI * pOpenProcess)
    (DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) = UtilsGetProcAddressByHash(ulKernel, 0x1055647d1);

    return pOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

BOOL UtilsReadFile(HANDLE hFile, LPVOID lpvBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    BOOL(WINAPI * pReadFile)
    (HANDLE hFile, LPVOID lpvBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) = UtilsGetProcAddressByHash(ulKernel, 0x98cecdc9);

    return pReadFile(hFile, lpvBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

BOOL UtilsWriteFile(HANDLE hFile, LPCVOID lpcvBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOveralapped)
{
    ULONG_PTR uiKernel = UtilsGetKernelModuleHandle();

    BOOL(WINAPI * pWriteFile)
    (HANDLE hFile, LPCVOID lpbuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) = UtilsGetProcAddressByHash(uiKernel, 0xbcb937e0);

    return pWriteFile(hFile, lpcvBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOveralapped);
}

BOOL UtilsReadConsoleA(HANDLE hConsoleInput, LPVOID lpvBuffer, DWORD nNumberOfCharsToRead, LPDWORD lpNumberOfCharsRead, LPVOID pInputControl)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    BOOL(WINAPI * pReadConsoleA)
    (HANDLE hConsoleInput, LPVOID lpvBuffer, DWORD nNumberOfCharsToRead, LPDWORD lpNumberOfCharsRead, LPVOID pInputControl) = UtilsGetProcAddressByHash(ulKernel, 0x105413518);

    return pReadConsoleA(hConsoleInput, lpvBuffer, nNumberOfCharsToRead, lpNumberOfCharsRead, pInputControl);
}

BOOL UtilsWriteConsoleA(HANDLE hConsoleOuput, const VOID *lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    BOOL(WINAPI * pWriteConsoleA)
    (HANDLE hConsoleOuput, const VOID *lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved) = UtilsGetProcAddressByHash(ulKernel, 0x130258647);

    return pWriteConsoleA(hConsoleOuput, lpBuffer, nNumberOfCharsToWrite, lpNumberOfCharsWritten, lpReserved);
}

HANDLE UtilsCreateToolhelp32Snapshot(DWORD dwFlags, DWORD dwTh32ProcessID)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    HANDLE(WINAPI * pCreateToolhelp32Snapshot)
    (DWORD dwFlags, DWORD th32ProcessID) = UtilsGetProcAddressByHash(ulKernel, 0x25a8b264b);

    return pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
}

BOOL UtilsProcess32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    BOOL(WINAPI * pProcess32First)
    (HANDLE hSnapshot, LPPROCESSENTRY32 lppe) = UtilsGetProcAddressByHash(ulKernel, 0xe89fc008);

    return pProcess32First(hSnapshot, lppe);
}

BOOL UtilsProcess32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    BOOL(WINAPI * pProcess32Next)
    (HANDLE hSnapshot, LPPROCESSENTRY32 lppe) = UtilsGetProcAddressByHash(ulKernel, 0xe834bc0e);

    return pProcess32Next(hSnapshot, lppe);
}

BOOL UtilsCloseHandle(HANDLE hHandle)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    BOOL(WINAPI * pCloseHandle)
    (HANDLE hObject) = UtilsGetProcAddressByHash(ulKernel, 0x10d2135e1);

    return pCloseHandle(hHandle);
}

HANDLE UtilsOpenThread(DWORD dwDesiredAccess, BOOL bInherhitHandle, DWORD dwThreadID)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    HANDLE(WINAPI * pOpenThread)
    (DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadID) = UtilsGetProcAddressByHash(ulKernel, 0xa43a3bd3);

    return pOpenThread(dwDesiredAccess, bInherhitHandle, dwThreadID);
}

HANDLE UtilsLoadLibraryA(LPCSTR lpLibFileName)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    HMODULE(WINAPI * pLoadLibrary)
    (LPCSTR lpLibFileName) = UtilsGetProcAddressByHash(ulKernel, 0xfa4b3d17);

    return pLoadLibrary(lpLibFileName);
}

LPVOID UtilsVirtualAlloc(PVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    LPVOID(WINAPI * pVirtualAlloc)
    (PVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = UtilsGetProcAddressByHash(ulKernel, 0x138374e18);

    return pVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

LPVOID UtilsVirtualAllocEx(HANDLE hProcess, PVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    LPVOID(WINAPI * pVirtualAllocEx)
    (HANDLE hProcess, PVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = UtilsGetProcAddressByHash(ulKernel, 0x1387cc618);

    return pVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL UtilsWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    BOOL(WINAPI * pWriteProcessMemory)
    (HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten) = UtilsGetProcAddressByHash(ulKernel, 0x16e0035c5);

    return pWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

DWORD UtilsResumeThread(HANDLE hThread)
{
    ULONG_PTR hKernel = UtilsGetKernelModuleHandle();

    DWORD(WINAPI * pResumeThread)
    (HANDLE hHandle) = UtilsGetProcAddressByHash(hKernel, 0x132302941);

    return pResumeThread(hThread);
}

BOOL UtilsVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    BOOL(WINAPI * pVirtualFree)
    (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) = UtilsGetProcAddressByHash(ulKernel, 0x13e3043ba);

    return pVirtualFree(lpAddress, 0, MEM_RELEASE);
}

BOOL UtilsVirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    BOOL(WINAPI * pVirtualFreeEx)
    (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) = UtilsGetProcAddressByHash(ulKernel, 0x13e30bbff);

    return pVirtualFreeEx(hProcess, lpAddress, 0, MEM_RELEASE);
}

INT UtilsWideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUseDefaultChar)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    INT(WINAPI * pWideCharToMultiByte)
    (UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUseDefaultChar) = UtilsGetProcAddressByHash(ulKernel, 0x1d529e18e);

    return pWideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUseDefaultChar);
}

HANDLE UtilsCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwSharedMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    HANDLE(WINAPI * pCreateFileA)
    (LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwSharedMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = UtilsGetProcAddressByHash(ulKernel, 0xb84410ca);

    return pCreateFileA(lpFileName, dwDesiredAccess, dwSharedMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE UtilsCreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    HANDLE(WINAPI * pCreateFileMappingA)
    (HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName) = UtilsGetProcAddressByHash(ulKernel, 0x19514a399);

    return pCreateFileMappingA(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
}

HANDLE UtilsMapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    LPVOID(WINAPI * pMapViewOfFile)
    (HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap) = UtilsGetProcAddressByHash(ulKernel, 0x11d0db611);

    return pMapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
}

BOOL UtilsUnmapViewOfFile(LPCVOID lpBaseAddress)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    BOOL(WINAPI * pUnmapViewOfFile)
    (LPCVOID lpBaseAddress) = UtilsGetProcAddressByHash(ulKernel, 0x1a680a20c);

    return pUnmapViewOfFile(lpBaseAddress);
}

HANDLE UtilsCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();

    HANDLE(WINAPI * pCreateRemoteThread)
    (HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) = UtilsGetProcAddressByHash(ulKernel, 0x17a110290);

    return pCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

HANDLE UtilsGetModuleHandleA(LPCSTR lpModuleName)
{
    ULONG_PTR hKernel = UtilsGetKernelModuleHandle();

    HMODULE(WINAPI * pGetModuleHandleA)
    (LPCSTR lpModuleName) = UtilsGetProcAddressByHash(hKernel, 0x1807eb068);

    return pGetModuleHandleA(lpModuleName);
}

PVOID UtilsImageDirectoryEntryToDataEx(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, PULONG Size, PIMAGE_SECTION_HEADER *FoundHeader)
{
    CHAR cDbgHelp[] = {0x44, 0x62, 0x67, 0x48, 0x65, 0x6c, 0x70, 0};
    HMODULE hDbgHelp = UtilsLoadLibraryA(cDbgHelp);

    PVOID(WINAPI * pImageDirectoryEntryToDataEx)
    (PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, PULONG Size, PIMAGE_SECTION_HEADER * FoundHeader) = UtilsGetProcAddressByHash((ULONG_PTR)hDbgHelp, 0x2cb8ad77e);

    return pImageDirectoryEntryToDataEx(Base, MappedAsImage, DirectoryEntry, Size, FoundHeader);
}

BOOL UtilsVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpfOldProtect)
{
    ULONG_PTR hKernel = UtilsGetKernelModuleHandle();

    BOOL(WINAPI * pVirtualProtect)
    (LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpfOldProtect) = UtilsGetProcAddressByHash(hKernel, 0x13e9dc729);

    return pVirtualProtect(lpAddress, dwSize, flNewProtect, lpfOldProtect);
}

BOOL UtilsVirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpfOldProtect)
{
    ULONG_PTR hKernel = UtilsGetKernelModuleHandle();

    BOOL(WINAPI * pVirtualProtectEx)
    (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpfOldProtect) = UtilsGetProcAddressByHash(hKernel, 0x1a1ae98a1);

    return pVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpfOldProtect);
}

void UtilsSleep(DWORD dwMilliseconds)
{
    ULONG_PTR hKernel = UtilsGetKernelModuleHandle();

    void(WINAPI * pSleep)(DWORD dwMilliseconds) = UtilsGetProcAddressByHash(hKernel, 0x536cd565);

    pSleep(dwMilliseconds);
}

void UtilsOutputDebugStringA(LPCSTR lpOutputString)
{
    ULONG_PTR hKernel = UtilsGetKernelModuleHandle();

    void(WINAPI * pOutputDebugStringA)(LPCSTR lpOutputString) = UtilsGetProcAddressByHash(hKernel, 0x19c38ca96);

    pOutputDebugStringA(lpOutputString);
}

void UtilsOutputDebugStringW(LPCWSTR lpOutputString)
{
    ULONG_PTR hKernel = UtilsGetKernelModuleHandle();

    void(WINAPI * pOutputDebugStringW)(LPCWSTR lpOutputString) = UtilsGetProcAddressByHash(hKernel, 0x19c38e096);

    pOutputDebugStringW(lpOutputString);
}

NTSTATUS UtilsNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
    ULONG_PTR ulNtdll = UtilsGetNtdllModuleHandle();

    NTSTATUS(NTAPI * pNtQuerySystemInformation)
    (SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) = UtilsGetProcAddressByHash(ulNtdll, 0x27e7f8a62);

    return pNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
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

    SIZE_T i = 0;
    while (sStr1[i] != 0)
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

        ++i;
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

    SIZE_T i = 0;
    while (sStr1[i] != 0)
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

        ++i;
    }

    return bAreEqual;
}

BOOL UtilsStrCmpiWW(PCWSTR wsStr1, PCWSTR wsStr2)
{
    BOOL bAreEqual = TRUE;

    SIZE_T i = 0;
    while (wsStr1[i] != 0)
    {
        if (wsStr1[i] != wsStr2[i])
        {
            if (wsStr1[i] < wsStr2[i])
            {
                if ((wsStr1[i] + 32) != wsStr2[i])
                {
                    bAreEqual = FALSE;
                    break;
                }
            }
            else if (wsStr2[i] < wsStr1[i])
            {
                if ((wsStr2[i] + 32) != wsStr1[i])
                {
                    bAreEqual = FALSE;
                    break;
                }
            }
        }

        ++i;
    }

    return bAreEqual;
}

BOOL UtilsStrCmpWW(PCWSTR wsStr1, PCWSTR wsStr2)
{
    SIZE_T i = 0;
    while (wsStr1[i] == wsStr2[i])
    {
        if (wsStr1[i] == 0 && wsStr2[i] == 0)
        {
            return TRUE;
        }
        ++i;
    }

    return FALSE;
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
                else
                {
                    continue;
                }

                stringIndex += 3;
                ++argIndex;
                continue;
            }
            else if (pString[stringIndex + 1] == 'U')
            {
                PUNICODE_STRING puString = (PUNICODE_STRING)sprintfArgs.args[argIndex];
                bufferIndex += UtilsWStrCpyA(puString->Buffer, pBuffer + bufferIndex);

                stringIndex += 2;
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
            else if (pString[stringIndex + 1] == 'U')
            {
                PUNICODE_STRING puString = (PUNICODE_STRING)sprintfArgs.args[argIndex];
                bufferIndex += UtilsWStrCpy(puString->Buffer, pBuffer + bufferIndex);

                stringIndex += 2;
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

DWORD UtilsFindTargetPIDByName(PSTR sTargetName)
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

DWORD UtilsFindTargetPIDByHash(DWORD64 dwProcNameHash)
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
        DWORD64 dwHash = UtilsStrHash(ProcessEntry.szExeFile);
        if (dwProcNameHash == dwHash)
        {
            UtilsCloseHandle(hSnapshot);
            return ProcessEntry.th32ProcessID;
        }
    } while (UtilsProcess32Next(hSnapshot, &ProcessEntry));

shutdown:

    UtilsCloseHandle(hSnapshot);
    return dwRetVal;
}

ULONG_PTR UtilsGetNtdllModuleHandle(void)
{
#ifdef _M_X64
    PEB *pPeb = (PEB *)__readgsqword(0x60);
#else
    PEB *pPeb = (PEB *)__readfsdword(0x30);
#endif

    LIST_ENTRY *FirstListEntry = &pPeb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY *CurrentListEntry = FirstListEntry->Flink;

    DWORD64 dwNtdllHash = 0xdaa334d8;

    while (CurrentListEntry != FirstListEntry)
    {
        UTILS_LDR_DATA_TABLE_ENTRY *TableEntry = (UTILS_LDR_DATA_TABLE_ENTRY *)((ULONG_PTR)CurrentListEntry - sizeof(LIST_ENTRY));

        DWORD64 dwHash = UtilsWStrHash(TableEntry->BaseDllName.Buffer);
        if (dwHash == dwNtdllHash)
        {
            return (ULONG_PTR)TableEntry->pvDllBase;
        }

        CurrentListEntry = CurrentListEntry->Flink;
    }

    return 0;
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

    DWORD64 dwKernelHash = 0xbed5d1cc;

    while (CurrentListEntry != FirstListEntry)
    {
        UTILS_LDR_DATA_TABLE_ENTRY *TableEntry = (UTILS_LDR_DATA_TABLE_ENTRY *)((ULONG_PTR)CurrentListEntry - sizeof(LIST_ENTRY));

        DWORD64 dwHash = UtilsWStrHash(TableEntry->BaseDllName.Buffer);
        if (dwHash == dwKernelHash)
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
        CHAR DLLName[256];
        UtilsStrCpy((PCSTR)lpvProcAddr, DLLName);
        PSTR FunctionName = UtilsStrChr(DLLName, '.');

        *FunctionName = 0;
        ++FunctionName;

        HMODULE ForwardedDLL = UtilsLoadLibraryA(DLLName);
        lpvProcAddr = (ULONG_PTR)UtilsGetProcAddressByName((ULONG_PTR)ForwardedDLL, FunctionName);
    }

    return (LPVOID)lpvProcAddr;
}

LPVOID UtilsGetProcAddressByHash(ULONG_PTR ulModuleAddr, DWORD64 dwProcNameHash)
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
        DWORD64 dwHash = UtilsStrHash((PCSTR)(ulModuleAddr + AddressOfNames[n]));
        if (dwProcNameHash == dwHash)
        {
            lpvProcAddr = ulModuleAddr + (ULONG_PTR)AddressOfFunctions[AddressOfNameOridinals[n]];
            break;
        }
    }

    if ((lpvProcAddr > (ulModuleAddr + ExportDataDirectory.VirtualAddress)) && (lpvProcAddr <= (ulModuleAddr + ExportDataDirectory.VirtualAddress + ExportDataDirectory.Size)))
    {
        CHAR DLLName[256];
        UtilsStrCpy((PCSTR)lpvProcAddr, DLLName);
        PSTR FunctionName = UtilsStrChr(DLLName, '.');

        *FunctionName = 0;
        ++FunctionName;

        HMODULE ForwardedDLL = UtilsLoadLibraryA(DLLName);
        lpvProcAddr = (ULONG_PTR)UtilsGetProcAddressByName((ULONG_PTR)ForwardedDLL, FunctionName);
    }

    return (LPVOID)lpvProcAddr;
}

DWORD64 UtilsStrHash(PCSTR sString)
{
    SIZE_T sStrlen = UtilsStrLen(sString);
    UINT64 i = 0;
    DWORD64 dwHash = 0;

    while (i < sStrlen)
    {
        DWORD64 dwCurrentFold = sString[i];
        dwCurrentFold <<= 8;

        if (i + 1 < sStrlen)
        {
            dwCurrentFold |= sString[i + 1];
            dwCurrentFold <<= 8;
        }

        if (i + 2 < sStrlen)
        {
            dwCurrentFold |= sString[i + 2];
            dwCurrentFold <<= 8;
        }

        if (i + 3 < sStrlen)
        {
            dwCurrentFold |= sString[i + 3];
        }

        dwHash += dwCurrentFold;

        i += 4;
    }

    return dwHash;
}

DWORD64 UtilsWStrHash(PCWSTR wsString)
{
    SIZE_T wsStrlen = UtilsWStrLen(wsString);
    UINT64 i = 0;
    DWORD64 dwHash = 0;

    while (i < wsStrlen)
    {
        DWORD64 dwCurrentFold = wsString[i];
        dwCurrentFold <<= 8;

        if (i + 1 < wsStrlen)
        {
            dwCurrentFold |= wsString[i + 1];
            dwCurrentFold <<= 8;
        }

        if (i + 2 < wsStrlen)
        {
            dwCurrentFold |= wsString[i + 2];
            dwCurrentFold <<= 8;
        }

        if (i + 3 < wsStrlen)
        {
            dwCurrentFold |= wsString[i + 3];
        }

        dwHash += dwCurrentFold;

        i += 4;
    }

    return dwHash;
}
#endif // UITLS_IMPLEMENTATION