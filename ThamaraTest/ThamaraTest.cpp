#include "ThamaraTest.h"

const unsigned char binary[] = { 0xFE, 0xED, 0xBA, 0xBE, 0xDE, 0xAD, 0xC0, 0xDE, 0xFA, 0xCE, 0xB0, 0x0C };

BOOL Scan(PVOID buffer, ULONG length)
{
	HRESULT hResult = NULL;
	HAMSICONTEXT amsiContext = NULL;
	HAMSISESSION amsiSession = NULL;
	AMSI_RESULT amsiResult = AMSI_RESULT_CLEAN;

	ZeroMemory(&amsiContext, sizeof(amsiContext));
	ZeroMemory(&amsiSession, sizeof(amsiSession));

	hResult = AmsiInitialize(L"AmsiTest", &amsiContext);
	if (hResult != S_OK || amsiContext == NULL) {
		return FALSE;
	}

	hResult = AmsiOpenSession(amsiContext, &amsiSession);
	if (hResult != S_OK || amsiSession == NULL) {
		return FALSE;
	}

	hResult = AmsiScanBuffer(amsiContext, buffer, length, L"Native Amsi Test", amsiSession, &amsiResult);
	if (hResult != S_OK) {
		return FALSE;
	}

	AmsiCloseSession(amsiContext, amsiSession);
	AmsiUninitialize(amsiContext);

	return TRUE;
}

int main()
{
	PBYTE pmem = NULL;
	PBYTE pmemex = NULL;
	SIZE_T binary_size = sizeof(binary);
	DWORD flOldProtect;
	SIZE_T NumberOfBytesRead;

	// LoadLibrary
#if defined (_WIN64)
	LoadLibraryW(L"AmsiForcedScanner64.dll");
#elif defined (_WIN32)
	LoadLibraryW(L"AmsiForcedScanner32.dll");
#endif
	
	// create new mem 1
	pmem = (PBYTE) VirtualAlloc(NULL, binary_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pmem == NULL)
	{
		printf("VirtualAlloc - Error!\n");
		return 1;
	}
	else
	{
		printf("VirtualAlloc - OK! Size = %d, Ptr = %p\n", binary_size, pmem);
	}

	// create new mem 2
	pmemex = (PBYTE)VirtualAllocEx(GetCurrentProcess(), NULL, binary_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pmemex == NULL)
	{
		printf("VirtualAllocEx - Error!\n");
		return 1;
	}
	else
	{
		printf("VirtualAllocEx - OK! Size = %d, Ptr = %p\n", binary_size, pmemex);
	}

	// copy to new memory
	CopyMemory(pmem, binary, binary_size);
	CopyMemory(pmemex, binary, binary_size);
	printf("CopyMemory!\n");

	// VirtualProtect
	if ((VirtualProtect(pmem, binary_size, PAGE_EXECUTE_READWRITE, &flOldProtect) == NULL))
	{
		printf("VirtualProtect - Error!\n");
		return 1;
	}
	else
	{
		printf("VirtualProtect - OK! Size = %d, Ptr = %p\n", binary_size, pmem);
	}

	// VirtualProtectEx
	if ((VirtualProtectEx(GetCurrentProcess(), pmemex, binary_size, PAGE_EXECUTE_READWRITE, &flOldProtect) == NULL))
	{
		printf("VirtualProtectEx - Error!\n");
		return 1;
	}
	else
	{
		printf("VirtualProtectEx - OK! Size = %d, Ptr = %p\n", binary_size, pmemex);
	}

	// ReadProcessMemory
	if ((ReadProcessMemory(GetCurrentProcess(), pmem, pmemex, binary_size, &NumberOfBytesRead) == NULL))
	{
		printf("ReadProcessMemory - Error!\n");
		return 1;
	}
	else
	{
		printf("ReadProcessMemory - OK! Size = %d, Ptr[In] = %p, Ptr[Out] = %p\n", binary_size, pmem, pmemex);
	}

	// WriteProcessMemory
	if ((WriteProcessMemory(GetCurrentProcess(), pmem, pmemex, binary_size, &NumberOfBytesRead) == NULL))
	{
		printf("WriteProcessMemory - Error!\n");
		return 1;
	}
	else
	{
		printf("WriteProcessMemory - OK! Size = %d, Ptr[To] = %p, Ptr[From] = %p\n", binary_size, pmem, pmemex);
	}

	// Check AMSI
	if (Scan(pmem, binary_size) == FALSE)
	{
		printf("Check AMSI - Error!\n");
		return 1;
	}
	else
	{
		printf("Check AMSI - OK!\n");
	}

	// RtlCompressBuffer
	ULONG FinalCompressedSize;
	MEMORY_BASIC_INFORMATION MemoryBasicInformation;
	ULONG CompressBufferWorkSpaceSize;
	ULONG CompressFragmentWorkSpaceSize;

	VirtualQuery(pmemex, &MemoryBasicInformation, sizeof(MemoryBasicInformation));
	RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM, &CompressBufferWorkSpaceSize, &CompressFragmentWorkSpaceSize);
	PVOID WorkSpace = malloc(CompressBufferWorkSpaceSize);

	if (RtlCompressBuffer(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM, (PUCHAR) binary, sizeof(binary), pmemex, MemoryBasicInformation.RegionSize, 4096, &FinalCompressedSize, WorkSpace))
	{
		printf("RtlCompressBuffer - Error!\n");
		return 1;
	}
	else
	{
		printf("RtlCompressBuffer - OK! UncompressedBufferSize = %d, FinalCompressedSize = %d\n", sizeof(binary), FinalCompressedSize);
	}

	// RtlDecompressBuffer
	ULONG FinalUncompressedSize;
	VirtualQuery(pmem, &MemoryBasicInformation, sizeof(MemoryBasicInformation));

	if (RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM, pmem, MemoryBasicInformation.RegionSize, pmemex, FinalCompressedSize, &FinalUncompressedSize))
	{
		printf("RtlDecompressBuffer - Error!\n");
		return 1;
	}
	else
	{
		printf("RtlDecompressBuffer - OK! CompressedBufferSize = %d, FinalUncompressedSize = %d\n", FinalCompressedSize, FinalUncompressedSize);
	}

	// VirtualFree
	if ((VirtualFree(pmem, 0, MEM_RELEASE) == NULL))
	{
		printf("VirtualFree - Error!\n");
		return 1;
	}
	else
	{
		printf("VirtualFree - OK! Size = %d, Ptr = %p\n", binary_size, pmem);
	}

	// VirtualFreeEx
	if ((VirtualFreeEx(GetCurrentProcess(), pmemex, 0, MEM_RELEASE) == NULL))
	{
		printf("VirtualFreeEx - Error!\n");
		return 1;
	}
	else
	{
		printf("VirtualFreeEx - OK! Size = %d, Ptr = %p\n", binary_size, pmemex);
	}

	return 0;
}
