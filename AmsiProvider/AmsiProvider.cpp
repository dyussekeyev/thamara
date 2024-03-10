#include "AmsiProvider.h"

using namespace Microsoft::WRL;

HMODULE GL_hModule = 0;
BOOL GL_found = false;
WCHAR* GL_rule_id = NULL;
WCHAR* GL_sha1 = NULL;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        GL_hModule = hModule;
        DisableThreadLibraryCalls(hModule);
        Module<InProc>::GetModule().Create();
        break;
    case DLL_PROCESS_DETACH:
        Module<InProc>::GetModule().Terminate();
        break;
    }
    return TRUE;
}

int callback_scan(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
{
    int wchars_num = 0;

    switch (message)
    {
    case CALLBACK_MSG_RULE_MATCHING:
        YR_RULE* rule = (YR_RULE*)message_data;

        GL_found = true;

        wchars_num = MultiByteToWideChar(CP_UTF8, 0, rule->identifier, -1, NULL, 0);
        GL_rule_id = new wchar_t[wchars_num];
        MultiByteToWideChar(CP_UTF8, 0, rule->identifier, -1, GL_rule_id, wchars_num);

        break;
    }

    return CALLBACK_CONTINUE;
}

static inline char hex_digit(unsigned int n)
{
    if (n < 10) return '0' + n;
    if (n < 16) return 'a' + (n - 10);
    abort();
}

std::string encode_bytes(const unsigned char* bytes, size_t len)
{
    std::string rv;
    rv.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        rv.push_back(hex_digit((bytes[i] & 0xF0) >> 4));
        rv.push_back(hex_digit((bytes[i] & 0x0F) >> 0));
    }
    return rv;
}

BOOL calc_sha1(BYTE *pbBuffer, DWORD dwBufferLen)
{
    BOOL bResult = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbData = 0;
    DWORD cbHash = 0;
    DWORD cbHashObject = 0;
    PBYTE pbHash = NULL;
    PBYTE pbHashObject = NULL;
    std::string sha1;
    int wchars_num = 0;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
    pbHashObject = (PBYTE) HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (pbHashObject == NULL)
        goto finish;
    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
    pbHash = (PBYTE) HeapAlloc(GetProcessHeap(), 0, cbHash);
    if (pbHash == NULL)
        goto finish;
    status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
    status = BCryptHashData(hHash, pbBuffer, dwBufferLen, 0);
    status = BCryptFinishHash(hHash, pbHash, cbHash, 0);

    sha1 = encode_bytes(pbHash, cbHash);
    wchars_num = MultiByteToWideChar(CP_UTF8, 0, sha1.c_str(), -1, NULL, 0);
    GL_sha1 = new wchar_t[wchars_num];
    MultiByteToWideChar(CP_UTF8, 0, sha1.c_str(), -1, GL_sha1, wchars_num);

    bResult = TRUE;
finish:
    if (hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);
    if (hHash)
        BCryptDestroyHash(hHash);
    if (pbHashObject)
        HeapFree(GetProcessHeap(), 0, pbHashObject);
    if (pbHash)
        HeapFree(GetProcessHeap(), 0, pbHash);

    return bResult;
}

HRESULT CopyAttribute(
    _In_ const void* resultData,
    _In_ size_t resultSize,
    _In_ ULONG bufferSize,
    _Out_writes_bytes_to_(bufferSize, *actualSize) PBYTE buffer,
    _Out_ ULONG* actualSize)
{
    *actualSize = (ULONG)resultSize;
    if (bufferSize < resultSize)
    {
        return E_NOT_SUFFICIENT_BUFFER;
    }
    memcpy_s(buffer, bufferSize, resultData, resultSize);
    return S_OK;
}

#pragma region COM server boilerplate
HRESULT WINAPI DllCanUnloadNow()
{
    return Module<InProc>::GetModule().Terminate() ? S_OK : S_FALSE;
}

STDAPI DllGetClassObject(_In_ REFCLSID rclsid, _In_ REFIID riid, _Outptr_ LPVOID FAR* ppv)
{
    return Module<InProc>::GetModule().GetClassObject(rclsid, riid, ppv);
}
#pragma endregion

// Simple RAII class to ensure memory is freed.
template<typename T>
class HeapMemPtr
{
public:
    HeapMemPtr() { }
    HeapMemPtr(const HeapMemPtr& other) = delete;
    HeapMemPtr(HeapMemPtr&& other) : p(other.p) { other.p = nullptr; }
    HeapMemPtr& operator=(const HeapMemPtr& other) = delete;
    HeapMemPtr& operator=(HeapMemPtr&& other) {
        auto t = p; p = other.p; other.p = t;
    }

    ~HeapMemPtr()
    {
        if (p) HeapFree(GetProcessHeap(), 0, p);
    }

    HRESULT Alloc(size_t size)
    {
        p = reinterpret_cast<T*>(HeapAlloc(GetProcessHeap(), 0, size));
        return p ? S_OK : E_OUTOFMEMORY;
    }

    T* Get() { return p; }
    operator bool() { return p != nullptr; }

private:
    T* p = nullptr;
};

class
    DECLSPEC_UUID("2A6BC572-04F9-4689-B963-757454F8A017")
    ThamaraProvider : public RuntimeClass<RuntimeClassFlags<ClassicCom>, IAntimalwareProvider, FtmBase>
{
public:
    IFACEMETHOD(Scan)(_In_ IAmsiStream * stream, _Out_ AMSI_RESULT * result) override;
    IFACEMETHOD_(void, CloseSession)(_In_ ULONGLONG session) override;
    IFACEMETHOD(DisplayName)(_Outptr_ LPWSTR* displayName) override;

private:
    // We assign each Scan request a unique number for logging purposes.
    LONG m_requestNumber = 0;
};

template<typename T>
T GetFixedSizeAttribute(_In_ IAmsiStream* stream, _In_ AMSI_ATTRIBUTE attribute)
{
    T result;

    ULONG actualSize;
    if (SUCCEEDED(stream->GetAttribute(attribute, sizeof(T), reinterpret_cast<PBYTE>(&result), &actualSize)) &&
        actualSize == sizeof(T))
    {
        return result;
    }
    return T();
}

HeapMemPtr<wchar_t> GetStringAttribute(_In_ IAmsiStream* stream, _In_ AMSI_ATTRIBUTE attribute)
{
    HeapMemPtr<wchar_t> result;

    ULONG allocSize;
    ULONG actualSize;
    if (stream->GetAttribute(attribute, 0, nullptr, &allocSize) == E_NOT_SUFFICIENT_BUFFER &&
        SUCCEEDED(result.Alloc(allocSize)) &&
        SUCCEEDED(stream->GetAttribute(attribute, allocSize, reinterpret_cast<PBYTE>(result.Get()), &actualSize)) &&
        actualSize <= allocSize)
    {
        return result;
    }
    return HeapMemPtr<wchar_t>();
}

HRESULT ThamaraProvider::Scan(_In_ IAmsiStream* stream, _Out_ AMSI_RESULT* result)
{
    *result = AMSI_RESULT_NOT_DETECTED;
    LONG requestNumber = InterlockedIncrement(&m_requestNumber);
    WCHAR logstring[1000] = { 0 };

    // Init libyara
    YR_COMPILER* compiler = NULL;
    YR_RULES* rules = NULL;
    HANDLE fd_rules = NULL;
    HANDLE hFile = NULL;
    SYSTEMTIME st;
    wchar_t datetime[200] = L"";

    auto appName = GetStringAttribute(stream, AMSI_ATTRIBUTE_APP_NAME);
    auto contentName = GetStringAttribute(stream, AMSI_ATTRIBUTE_CONTENT_NAME);
    auto contentSize = GetFixedSizeAttribute<ULONGLONG>(stream, AMSI_ATTRIBUTE_CONTENT_SIZE);
    auto session = GetFixedSizeAttribute<ULONGLONG>(stream, AMSI_ATTRIBUTE_SESSION);
    auto contentAddress = GetFixedSizeAttribute<PBYTE>(stream, AMSI_ATTRIBUTE_CONTENT_ADDRESS);

    yr_initialize();
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
    {
        goto finish;
    }
    fd_rules = CreateFileW(L"C:\\ProgramData\\Thamara\\rules.yar", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (fd_rules == INVALID_HANDLE_VALUE)
    {
        goto finish;
    }
    if (yr_compiler_add_fd(compiler, fd_rules, NULL, NULL) != 0)
    {
        goto finish;
    }
    if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS)
    {
        goto finish;
    }

    // Scan memory buffer
    if (yr_rules_scan_mem(rules, (uint8_t*)contentAddress, contentSize, 0, callback_scan, NULL, 0) != ERROR_SUCCESS)
    {
        goto finish;
    }

    if (GL_found == true)
    {
        GL_found = false;

        GetSystemTime(&st);
        swprintf_s(datetime, 200, L"%d.%02d.%02d %02d:%02d:%02d.%03d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

        if (calc_sha1(contentAddress, contentSize))
        {
            swprintf_s(logstring, 999, L"datetime=\"%s\" appName=\"%s\" contentName=\"%s\" rule_id=\"%s\" sha1=\"%s\"\r\n", datetime, appName.Get(), contentName.Get(), GL_rule_id, GL_sha1);
        }
        else {
            swprintf_s(logstring, 999, L"datetime=\"%s\" appName=\"%s\" contentName=\"%s\" rule_id=\"%s\" sha1=\"ERROR\"\r\n", datetime, appName.Get(), contentName.Get(), GL_rule_id);
        }

        hFile = CreateFile(L"C:\\ProgramData\\Thamara\\amsi.log", FILE_APPEND_DATA, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile)
        {
            WriteFile(hFile, logstring, wcslen(logstring) * 2 + 2, NULL, NULL);
        }
    }

finish:
    if (hFile)
    {
        CloseHandle(hFile);
    }
    if (fd_rules)
    {
        CloseHandle(fd_rules);
    }    
    if (rules)
    {
        yr_rules_destroy(rules);
    }
    if (compiler)
    {
        yr_compiler_destroy(compiler);
    }
    yr_finalize();

    return S_OK;
}

void ThamaraProvider::CloseSession(_In_ ULONGLONG session)
{
}

HRESULT ThamaraProvider::DisplayName(_Outptr_ LPWSTR* displayName)
{
    *displayName = const_cast<LPWSTR>(L"Thamara AMSI Provider");
    return S_OK;
}

CoCreatableClass(ThamaraProvider);

#pragma region Install / uninstall

HRESULT SetKeyStringValue(_In_ HKEY key, _In_opt_ PCWSTR subkey, _In_opt_ PCWSTR valueName, _In_ PCWSTR stringValue)
{
    LONG status = RegSetKeyValue(key, subkey, valueName, REG_SZ, stringValue, (wcslen(stringValue) + 1) * sizeof(wchar_t));
    return HRESULT_FROM_WIN32(status);
}

STDAPI DllRegisterServer()
{
    wchar_t modulePath[MAX_PATH];
    if (GetModuleFileName(GL_hModule, modulePath, ARRAYSIZE(modulePath)) >= ARRAYSIZE(modulePath))
    {
        return E_UNEXPECTED;
    }

    // Create a standard COM registration for our CLSID.
    // The class must be registered as "Both" threading model
    // and support multithreaded access.
    wchar_t clsidString[40];
    if (StringFromGUID2(__uuidof(ThamaraProvider), clsidString, ARRAYSIZE(clsidString)) == 0)
    {
        return E_UNEXPECTED;
    }

    wchar_t keyPath[200];
    HRESULT hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls", clsidString);
    if (FAILED(hr)) return hr;

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, L"ThamaraProvider");
    if (FAILED(hr)) return hr;

    hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls\\InProcServer32", clsidString);
    if (FAILED(hr)) return hr;

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, modulePath);
    if (FAILED(hr)) return hr;

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, L"ThreadingModel", L"Both");
    if (FAILED(hr)) return hr;

#if defined (_WIN64)
    hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Microsoft\\AMSI\\Providers\\%ls", clsidString);
    if (FAILED(hr)) return hr;
    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, L"ThamaraProvider");
    if (FAILED(hr)) return hr;
#elif defined (_WIN32)
    hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\WOW6432Node\\Microsoft\\AMSI\\Providers\\%ls", clsidString);
    if (FAILED(hr)) return hr;
    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, L"ThamaraProvider");
    if (FAILED(hr)) return hr;
#endif

    return S_OK;
}

STDAPI DllUnregisterServer()
{
    wchar_t clsidString[40];
    if (StringFromGUID2(__uuidof(ThamaraProvider), clsidString, ARRAYSIZE(clsidString)) == 0)
    {
        return E_UNEXPECTED;
    }

    // Unregister this CLSID as an anti-malware provider.
    wchar_t keyPath[200];

#if defined (_WIN64)
    HRESULT hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Microsoft\\AMSI\\Providers\\%ls", clsidString);
    if (FAILED(hr)) return hr;
    LONG status = RegDeleteTree(HKEY_LOCAL_MACHINE, keyPath);
    if (status != NO_ERROR && status != ERROR_PATH_NOT_FOUND) return HRESULT_FROM_WIN32(status);
#elif defined (_WIN32)
    HRESULT hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\WOW6432Node\\Microsoft\\AMSI\\Providers\\%ls", clsidString);
    if (FAILED(hr)) return hr;
    LONG status = RegDeleteTree(HKEY_LOCAL_MACHINE, keyPath);
    if (status != NO_ERROR && status != ERROR_PATH_NOT_FOUND) return HRESULT_FROM_WIN32(status);
#endif

    // Unregister this CLSID as a COM server.
    hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls", clsidString);
    if (FAILED(hr)) return hr;
    status = RegDeleteTree(HKEY_LOCAL_MACHINE, keyPath);
    if (status != NO_ERROR && status != ERROR_PATH_NOT_FOUND) return HRESULT_FROM_WIN32(status);

    return S_OK;
}
#pragma endregion
