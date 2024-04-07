#pragma once

#include <windows.h>
#include <amsi.h>
#include <stdio.h>

typedef NTSTATUS (WINAPI * RTLCOMPRESSBUFFER) (USHORT CompressionFormatAndEngine, PUCHAR UncompressedBuffer, ULONG UncompressedBufferSize, PUCHAR CompressedBuffer, ULONG CompressedBufferSize, ULONG UncompressedChunkSize, PULONG FinalCompressedSize, PVOID WorkSpace);
typedef NTSTATUS (WINAPI * RTLDECOMPRESSBUFFER) (USHORT CompressionFormat, PUCHAR UncompressedBuffer, ULONG UncompressedBufferSize, PUCHAR CompressedBuffer, ULONG CompressedBufferSize, PULONG FinalUncompressedSize);
typedef NTSTATUS (WINAPI * RTLGETCOMPRESSIONWORKSPACESIZE) (USHORT CompressionFormatAndEngine, PULONG CompressBufferWorkSpaceSize, PULONG CompressFragmentWorkSpaceSize);

RTLCOMPRESSBUFFER RtlCompressBuffer = (RTLCOMPRESSBUFFER) GetProcAddress(GetModuleHandle(L"ntdll"), "RtlCompressBuffer");
RTLDECOMPRESSBUFFER RtlDecompressBuffer = (RTLDECOMPRESSBUFFER) GetProcAddress(GetModuleHandle(L"ntdll"), "RtlDecompressBuffer");
RTLGETCOMPRESSIONWORKSPACESIZE RtlGetCompressionWorkSpaceSize = (RTLGETCOMPRESSIONWORKSPACESIZE) GetProcAddress (GetModuleHandle(L"ntdll"), "RtlGetCompressionWorkSpaceSize");
