#define UTILS_IMPLEMENTATION
#include "../utils.h"

#include <stdio.h>

int main()
{
    UINT32 bSrcMem = 0xDEADBEEF;
    UINT32 bDstMem[128];

    UtilsMemCpy((LPCVOID)&bSrcMem, (LPVOID)(bDstMem + 120), sizeof(UINT32));

    UtilsMemSet((LPVOID)bDstMem, 0, sizeof(bDstMem));

    CHAR str[] = {'N', 'i', 'h', 'a', 'l', 0};
    SIZE_T sStrLen = UtilsStrLen((PCSTR)str);

    WCHAR wstr[] = {'S', 'h', 'r', 'u', 't', 'i', 0};
    sStrLen = UtilsWStrLen(wstr);

    CHAR dst[128];
    UtilsStrCpy((PCSTR)str, dst);

    WCHAR wdst[128];
    UtilsWStrCpy((PCWSTR)wstr, wdst);

    UtilsWStrCpyA(wstr, dst);
    UtilsAStrCpyW(str, wdst);

    CHAR str1[] = {'D', 'u', 'd', 'Y', 'a', 0};
    CHAR str2[] = {'D', 'u', 'd', 'y', 'a', 0};
    WCHAR wstr1[] = {'D', 'u', 'd', 'Y', 'a', 0};

    BOOL bAreEqual = UtilsStrCmpAW(str1, wstr1);
    bAreEqual = UtilsStrCmpiAW(str1, wstr1);
    bAreEqual = UtilsStrCmpAA(str1, str2);
    bAreEqual = UtilsStrCmpiAA(str1, str2);

    CHAR sFindInStr[] = {'F', 'i', 'n', 'F', 'i', 'f', 's', 't', 'r', 0};
    CHAR sFindStr[] = {'n', 'F', 'i', 0};

    PCSTR sStrStr = UtilsStrStr(sFindInStr, sFindStr);

    WCHAR wsFindInStr[] = {'F', 'i', 'n', 'F', 'i', 'f', 's', 't', 'r', 0};
    WCHAR wsFindStr[] = {'n', 'F', 'i', 0};

    PCWSTR wsStrStr = UtilsWStrWStr(wsFindInStr, wsFindStr);

    UtilsStrAppend(dst, sFindInStr);
    UtilsWStrAppend(wdst, wsFindStr);

    CHAR cSprintfBuffer[128];
    CHAR cString[] = {'M', 'y', '\n', 'N', 'a', 'm', 'e', ':', ' ', '%', 's', 'w', ' ', 'K', 'e', 'n', 'k', 'r', 'e', '\n', 'A', 'g', 'e', ':', ' ', '%', 'x', '\n', 0};
    CHAR cName[] = {'N', 'i', 'h', 'a', 'l', 0};
    WCHAR wcName[] = {'N', 'i', 'h', 'a', 'l', 0};
    DWORD64 uiAge = 0xDEADBEEFBABECAFE;

    SPRINTF_ARGS sprintfArgs;
    sprintfArgs.argsCount = 2;
    sprintfArgs.args[0] = wcName;
    sprintfArgs.args[1] = uiAge;

    UtilsSprintf(cSprintfBuffer, cString, sprintfArgs);

    WCHAR wcSprintfBuffer[128];
    WCHAR wcString[] = {'M', 'y', '\n', 'N', 'a', 'm', 'e', ':', ' ', '%', 's', 'b', ' ', 'K', 'e', 'n', 'k', 'r', 'e', '\n', 'A', 'g', 'e', ':', ' ', '%', 'x', '\n', 0};

    sprintfArgs.argsCount = 2;
    sprintfArgs.args[0] = cName;
    sprintfArgs.args[1] = uiAge;

    UtilsWSprintf(wcSprintfBuffer, wcString, sprintfArgs);

    UtilsWriteFile(UtilsGetStdHandle(STD_OUTPUT_HANDLE), cSprintfBuffer, (DWORD)UtilsStrLen(cSprintfBuffer), NULL, NULL);
    UtilsWriteFile(UtilsGetStdHandle(STD_OUTPUT_HANDLE), wcSprintfBuffer, (DWORD)UtilsWStrLen(wcSprintfBuffer) * sizeof(WCHAR), NULL, NULL);

    DWORD dwTargetPid = UtilsFindTargetPIDByName((CHAR[]){'n', 'o', 't', 'e', 'p', 'a', 'd', '.', 'e', 'x', 'e', 0});

    DWORD64 dwHash = UtilsStrHash((CHAR[]){'n', 'o', 't', 'e', 'p', 'a', 'd', '.', 'e', 'x', 'e', 0});
    dwTargetPid = UtilsFindTargetPIDByHash(0x144493d93);

    ULONG_PTR ulKernel = UtilsGetKernelModuleHandle();
    LPVOID lpvProcAddr = UtilsGetProcAddressByHash(ulKernel, 0x138374e18);
    lpvProcAddr = UtilsGetProcAddressByHash(ulKernel, 0x1055647d1);
    lpvProcAddr = UtilsGetProcAddressByHash(ulKernel, 0x25290982b);

    ULONG_PTR ulNtdll = UtilsGetNtdllModuleHandle();

    DWORD dwBytes = 0;
    CHAR cInput[MAX_PATH];

    UtilsWriteConsoleA(UtilsGetStdHandle(STD_OUTPUT_HANDLE), "1 or 2: ", 10, &dwBytes, NULL);
    UtilsReadConsoleA(UtilsGetStdHandle(STD_INPUT_HANDLE), cInput, MAX_PATH, &dwBytes, NULL);

    return 0;
}
