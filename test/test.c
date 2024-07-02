#define UTILS_IMPLEMENTATION
#include "../utils.h"

int main()
{
    HANDLE hKernel = UtilsGetKernelModuleHandle();

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

    return 0;
}
