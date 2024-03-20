#include "AmsiForcedScanner.h"
#include <stdio.h>

BOOL ScanBuffer(PVOID buffer, ULONG length, LPCWSTR contentName)
{
    HRESULT hResult = NULL;
    HAMSICONTEXT amsiContext = NULL;
    HAMSISESSION amsiSession = NULL;
    AMSI_RESULT amsiResult = AMSI_RESULT_CLEAN;
    WCHAR appName[MAX_PATH];

    if (GetModuleFileNameW(NULL, appName, MAX_PATH) == 0)
    {
        OutputDebugStringW(L"GetModuleFileNameW - ERROR!\n");
        return FALSE;
    }

    ZeroMemory(&amsiContext, sizeof(amsiContext));
    ZeroMemory(&amsiSession, sizeof(amsiSession));

    hResult = AmsiInitialize(appName, &amsiContext);
    if (hResult != S_OK || amsiContext == NULL)
    {
        OutputDebugStringW(L"AmsiForcedScanner - ERROR!\n");
        return FALSE;
    }

    hResult = AmsiOpenSession(amsiContext, &amsiSession);
    if (hResult != S_OK || amsiSession == NULL)
    {
        OutputDebugStringW(L"AmsiOpenSession - ERROR!\n");
        return FALSE;
    }

    hResult = AmsiScanBuffer(amsiContext, buffer, length, contentName, amsiSession, &amsiResult);
    if (hResult != S_OK)
    {
        OutputDebugStringW(L"AmsiScanBuffer - ERROR!\n");
        return FALSE;
    }

    AmsiCloseSession(amsiContext, amsiSession);
    AmsiUninitialize(amsiContext);

    return TRUE;
}

BOOL ScanString(LPCWSTR string, LPCWSTR contentName)
{
    HRESULT hResult = NULL;
    HAMSICONTEXT amsiContext = NULL;
    HAMSISESSION amsiSession = NULL;
    AMSI_RESULT amsiResult = AMSI_RESULT_CLEAN;

    ZeroMemory(&amsiContext, sizeof(amsiContext));
    ZeroMemory(&amsiSession, sizeof(amsiSession));

    hResult = AmsiInitialize(L"AmsiForcedScanner", &amsiContext);
    if (hResult != S_OK || amsiContext == NULL)
    {
        OutputDebugStringW(L"AmsiForcedScanner - ERROR!\n");
        return FALSE;
    }

    hResult = AmsiOpenSession(amsiContext, &amsiSession);
    if (hResult != S_OK || amsiSession == NULL)
    {
        OutputDebugStringW(L"AmsiOpenSession - ERROR!\n");
        return FALSE;
    }

    hResult = AmsiScanString(amsiContext, string, contentName, amsiSession, &amsiResult);
    if (hResult != S_OK)
    {
        OutputDebugStringW(L"AmsiScanString - ERROR!\n");
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
            case PAGE_EXECUTE_READ:
                return TRUE;
                break;
            case PAGE_EXECUTE_READWRITE:
                return TRUE;
                break;
            case PAGE_READONLY:
                return TRUE;
                break;
            case PAGE_READWRITE:
                return TRUE;
                break;
            default:
                return FALSE;
        }
    }

    return FALSE;
}

BOOL GetVirtualSize(LPVOID lpAddress)
{
    MEMORY_BASIC_INFORMATION MemoryBasicInformation;
    SIZE_T RegionSize = 0;

    if (VirtualQuery(lpAddress, &MemoryBasicInformation, sizeof(MemoryBasicInformation)) != 0)
    {
        RegionSize = MemoryBasicInformation.RegionSize;
    }

    return RegionSize;
}

NTSTATUS HookedNtWriteVirtualMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
    NTSTATUS ret = TrueNtWriteVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    CHAR DbgMsg[1024];

    if (ret == 0)
    {
        if (CheckRead((LPVOID) lpBuffer))
        {
            sprintf_s(DbgMsg, 1023, "HookedNtWriteVirtualMemory: nSize = %d\n", nSize);
            OutputDebugStringA(DbgMsg);
            ScanBuffer((PVOID) lpBuffer, (ULONG) nSize, L"NtWriteVirtualMemory");
        }
    }

    return ret;
}

NTSTATUS HookedNtReadVirtualMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
    NTSTATUS ret = TrueNtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    CHAR DbgMsg[1024];

    if (ret == 0)
    {
        if (CheckRead((LPVOID) lpBaseAddress))
        {
            sprintf_s(DbgMsg, 1023, "HookedNtReadVirtualMemory: nSize = %d\n", nSize);
            OutputDebugStringA(DbgMsg);

            ScanBuffer((PVOID) lpBaseAddress, (ULONG) nSize, L"NtReadVirtualMemory");
        }
    }

    return ret;
}

NTSTATUS HookedRtlDecompressBuffer(USHORT CompressionFormat, PUCHAR UncompressedBuffer, ULONG UncompressedBufferSize, PUCHAR CompressedBuffer, ULONG CompressedBufferSize, PULONG FinalUncompressedSize)
{
    NTSTATUS ret = TrueRtlDecompressBuffer(CompressionFormat, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, FinalUncompressedSize);
    CHAR DbgMsg[1024];

    if (ret == 0)
    {
        sprintf_s(DbgMsg, 1023, "HookedRtlDecompressBuffer: *FinalUncompressedSize = %d\n", *FinalUncompressedSize);
        OutputDebugStringA(DbgMsg);

        ScanBuffer((PVOID) UncompressedBuffer, *FinalUncompressedSize, L"RtlDecompressBuffer");
    }

    return ret;
}

NTSTATUS HookedRtlCompressBuffer(USHORT CompressionFormatAndEngine, PUCHAR UncompressedBuffer, ULONG UncompressedBufferSize, PUCHAR CompressedBuffer, ULONG CompressedBufferSize, ULONG UncompressedChunkSize, PULONG FinalCompressedSize, PVOID WorkSpace)
{
    NTSTATUS ret = TrueRtlCompressBuffer(CompressionFormatAndEngine, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, UncompressedChunkSize, FinalCompressedSize, WorkSpace);
    CHAR DbgMsg[1024];

    if (ret == 0)
    {
        sprintf_s(DbgMsg, 1023, "HookedRtlCompressBuffer: UncompressedBufferSize = %d\n", UncompressedBufferSize);
        OutputDebugStringA(DbgMsg);

        ScanBuffer((PVOID) UncompressedBuffer, UncompressedBufferSize, L"RtlCompressBuffer");
    }

    return ret;
}



int Init()
{
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (DetourIsHelperProcess())
    {
        return TRUE;
    }

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueNtWriteVirtualMemory, HookedNtWriteVirtualMemory);
        DetourAttach(&(PVOID&)TrueNtReadVirtualMemory, HookedNtReadVirtualMemory);
        DetourAttach(&(PVOID&)TrueRtlDecompressBuffer, HookedRtlDecompressBuffer);
        DetourAttach(&(PVOID&)TrueRtlCompressBuffer, HookedRtlCompressBuffer);
        DetourTransactionCommit();
        break;
    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueNtWriteVirtualMemory, HookedNtWriteVirtualMemory);
        DetourDetach(&(PVOID&)TrueNtReadVirtualMemory, HookedNtReadVirtualMemory);
        DetourDetach(&(PVOID&)TrueRtlDecompressBuffer, HookedRtlDecompressBuffer);
        DetourDetach(&(PVOID&)TrueRtlCompressBuffer, HookedRtlCompressBuffer);
        DetourTransactionCommit();
        break;
    }
    return TRUE;
}
