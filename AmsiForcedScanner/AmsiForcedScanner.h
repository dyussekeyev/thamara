#pragma once

#include <windows.h>
#include <winternl.h>
#include <amsi.h>
#include "detours.h"

typedef NTSTATUS (WINAPI * NTWRITEVIRTUALMEMORY) (HANDLE ProcessHandle, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
typedef NTSTATUS (WINAPI * NTREADVIRTUALMEMORY) (HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
typedef NTSTATUS (WINAPI * RTLDECOMPRESSBUFFER) (USHORT CompressionFormat, PUCHAR UncompressedBuffer, ULONG UncompressedBufferSize, PUCHAR CompressedBuffer, ULONG CompressedBufferSize, PULONG FinalUncompressedSize);
typedef NTSTATUS (WINAPI * RTLCOMPRESSBUFFER) (USHORT CompressionFormatAndEngine, PUCHAR UncompressedBuffer, ULONG UncompressedBufferSize, PUCHAR CompressedBuffer, ULONG CompressedBufferSize, ULONG UncompressedChunkSize, PULONG FinalCompressedSize, PVOID WorkSpace);

NTWRITEVIRTUALMEMORY TrueNtWriteVirtualMemory = (NTWRITEVIRTUALMEMORY) GetProcAddress(GetModuleHandle(L"ntdll"), "NtWriteVirtualMemory");
NTREADVIRTUALMEMORY TrueNtReadVirtualMemory = (NTREADVIRTUALMEMORY) GetProcAddress(GetModuleHandle(L"ntdll"), "NtReadVirtualMemory");
RTLDECOMPRESSBUFFER TrueRtlDecompressBuffer = (RTLDECOMPRESSBUFFER)GetProcAddress(GetModuleHandle(L"ntdll"), "RtlDecompressBuffer");
RTLCOMPRESSBUFFER TrueRtlCompressBuffer = (RTLCOMPRESSBUFFER)GetProcAddress(GetModuleHandle(L"ntdll"), "RtlCompressBuffer");
