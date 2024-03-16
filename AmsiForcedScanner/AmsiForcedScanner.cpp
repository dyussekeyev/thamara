#include "AmsiForcedScanner.h"
#include <stdio.h>

static BOOL (WINAPI * TrueReadProcessMemory)(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) = ReadProcessMemory;
static BOOL (WINAPI * TrueWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) = WriteProcessMemory;
static BOOL (WINAPI * TrueVirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) = VirtualFree;
static BOOL (WINAPI * TrueVirtualFreeEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) = VirtualFreeEx;

void Attach();
void Detach();

BOOL Scan(PVOID buffer, ULONG length, LPCWSTR contentName)
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
    hResult = AmsiScanBuffer(amsiContext, buffer, length, contentName, amsiSession, &amsiResult);
    printf("END!\n");
    if (hResult != S_OK) {
        OutputDebugStringW(L"AmsiScanBuffer - ERROR!\n");
        return FALSE;
    }

    AmsiCloseSession(amsiContext, amsiSession);
    AmsiUninitialize(amsiContext);

    return TRUE;
}

BOOL CheckRead(LPVOID lpAddress)
{
    MEMORY_BASIC_INFORMATION MemoryBasicInformation;
    DWORD dwProtect;

    if (VirtualQuery(lpAddress, &MemoryBasicInformation, sizeof(MemoryBasicInformation)) != 0)
    {
        dwProtect = MemoryBasicInformation.Protect;

        switch (dwProtect)
        {
            printf("\nswitch = %x\n", dwProtect);

            case PAGE_EXECUTE_READ:
                return TRUE;
                break;
            case PAGE_EXECUTE_READWRITE:
                return TRUE;
                break;
        }
    }

    return FALSE;
}

BOOL HookedReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
    printf("HookedReadProcessMemory %d\n", nSize);
    BOOL ret = TrueReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    if (ret != 0) {
        Detach();
        Scan((PVOID)lpBaseAddress, (ULONG)nSize, L"ReadProcessMemory");
        Attach();

    }

    return ret;
}

BOOL HookedWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
    printf("HookedWriteProcessMemory %d\n", nSize);
    BOOL ret = TrueWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    if (ret != 0) {
        Detach();
        Scan((PVOID)lpBaseAddress, (ULONG)nSize, L"WriteProcessMemory");
        Attach();
    }

    return ret;
}

BOOL HookedVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    if (CheckRead(lpAddress))
    {
        printf("HookedVirtualFree %d\n", dwSize);
        Detach();
        Scan((PVOID)lpAddress, (ULONG)dwSize, L"VirtualFree");
        Attach();
    }

    BOOL ret = TrueVirtualFree(lpAddress, dwSize, dwFreeType);

    return ret;
}

BOOL HookedVirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    if (CheckRead(lpAddress))
    {
        printf("HookedVirtualFreeEx %d\n", dwSize);
        Detach();
        Scan((PVOID)lpAddress, (ULONG)dwSize, L"VirtualFreeEx");
        Attach();
    }

    BOOL ret = TrueVirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType);

    return ret;
}

int Init()
{
    return 0;
}

void Attach()
{
    DetourAttach(&(PVOID&)TrueReadProcessMemory, HookedReadProcessMemory);
    DetourAttach(&(PVOID&)TrueWriteProcessMemory, HookedWriteProcessMemory);
    DetourAttach(&(PVOID&)TrueVirtualFree, HookedVirtualFree);
    DetourAttach(&(PVOID&)TrueVirtualFreeEx, HookedVirtualFreeEx);
}

void Detach()
{
    DetourDetach(&(PVOID&)TrueReadProcessMemory, HookedReadProcessMemory);
    DetourDetach(&(PVOID&)TrueWriteProcessMemory, HookedWriteProcessMemory);
    DetourDetach(&(PVOID&)TrueVirtualFree, HookedVirtualFree);
    DetourDetach(&(PVOID&)TrueVirtualFreeEx, HookedVirtualFreeEx);
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
        Attach();
        DetourTransactionCommit();
        break;
    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        Detach();
        DetourTransactionCommit();
        break;
    }
    return TRUE;
}
