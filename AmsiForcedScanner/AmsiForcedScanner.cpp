#include "AmsiForcedScanner.h"
#include <stdio.h>

static BOOL (WINAPI * TrueReadProcessMemory)(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) = ReadProcessMemory;
static BOOL (WINAPI * TrueWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) = WriteProcessMemory;
static BOOL (WINAPI * TrueVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) = VirtualProtect;
static BOOL (WINAPI * TrueVirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) = VirtualProtectEx;
static BOOL (WINAPI * TrueVirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) = VirtualFree;
static BOOL (WINAPI * TrueVirtualFreeEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) = VirtualFreeEx;

BOOL Scan(PVOID buffer, ULONG length)
{
    HRESULT hResult = NULL;
    HAMSICONTEXT amsiContext = NULL;
    HAMSISESSION amsiSession = NULL;
    AMSI_RESULT amsiResult = AMSI_RESULT_CLEAN;

    ZeroMemory(&amsiContext, sizeof(amsiContext));
    ZeroMemory(&amsiSession, sizeof(amsiSession));

    hResult = AmsiInitialize(L"AmsiForcedScanner", &amsiContext);
    if (hResult != S_OK || amsiContext == NULL) {
        OutputDebugStringW(L"AmsiForcedScanner - ERROR!\n");
        return FALSE;
    }

    hResult = AmsiOpenSession(amsiContext, &amsiSession);
    if (hResult != S_OK || amsiSession == NULL) {
        OutputDebugStringW(L"AmsiOpenSession - ERROR!\n");
        return FALSE;
    }

    printf("p = %p, s = %d : ", buffer, length);
    hResult = AmsiScanBuffer(amsiContext, buffer, length, L"System Memory", amsiSession, &amsiResult);
    printf("END!\n");
    if (hResult != S_OK) {
        OutputDebugStringW(L"AmsiScanBuffer - ERROR!\n");
        return FALSE;
    }

    AmsiCloseSession(amsiContext, amsiSession);
    AmsiUninitialize(amsiContext);

    return TRUE;
}
BOOL HookedReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
    BOOL ret = TrueReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    if (ret != 0) {
        Scan((PVOID) lpBaseAddress, (ULONG) nSize);
    }

    return ret;
}
BOOL HookedWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
    BOOL ret = TrueWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    if (ret != 0) {
        Scan((PVOID) lpBuffer, (ULONG) nSize);
    }

    return ret;
}
BOOL HookedVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    BOOL ret = TrueVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
    if (ret != 0) {
        Scan((PVOID) lpAddress, (ULONG) dwSize);
    }

    return ret;
}
BOOL HookedVirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    BOOL ret = TrueVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
    if (ret != 0) {
        Scan((PVOID) lpAddress, (ULONG) dwSize);
    }

    return ret;
}
BOOL HookedVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    Scan((PVOID) lpAddress, (ULONG) dwSize);
    BOOL ret = TrueVirtualFree(lpAddress, dwSize, dwFreeType);

    return ret;
}
BOOL HookedVirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    Scan((PVOID) lpAddress, (ULONG) dwSize);
    BOOL ret = TrueVirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType);

    return ret;
}

int Init()
{
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueReadProcessMemory, HookedReadProcessMemory);
        DetourAttach(&(PVOID&)TrueWriteProcessMemory, HookedWriteProcessMemory);
        DetourAttach(&(PVOID&)TrueVirtualProtect, HookedVirtualProtect);
        DetourAttach(&(PVOID&)TrueVirtualProtectEx, HookedVirtualProtectEx);
        DetourAttach(&(PVOID&)TrueVirtualFree, HookedVirtualFree);
        DetourAttach(&(PVOID&)TrueVirtualFreeEx, HookedVirtualFreeEx);
        DetourTransactionCommit();
        break;
    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueReadProcessMemory, HookedReadProcessMemory);
        DetourDetach(&(PVOID&)TrueWriteProcessMemory, HookedWriteProcessMemory);
        DetourDetach(&(PVOID&)TrueVirtualProtect, HookedVirtualProtect);
        DetourDetach(&(PVOID&)TrueVirtualProtectEx, HookedVirtualProtectEx);
        DetourDetach(&(PVOID&)TrueVirtualFree, HookedVirtualFree);
        DetourDetach(&(PVOID&)TrueVirtualFreeEx, HookedVirtualFreeEx);
        DetourTransactionCommit();
        break;
    }
    return TRUE;
}
