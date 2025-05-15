#include <Windows.h>
#include <string>
#include <vector>
#include <iostream>
#include <wbemidl.h>
#include <comdef.h>
#include <sddl.h>

#include "skCrypter.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

namespace hwid_utils
{

    std::string get_wmi_value(const std::wstring& wmiClass, const std::wstring& wmiProperty) {
        std::string result = "";

        HRESULT hres;
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) return result;

        hres = CoInitializeSecurity(NULL, -1, NULL, NULL,
            RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

        IWbemLocator* pLoc = nullptr;
        hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
            IID_IWbemLocator, (LPVOID*)&pLoc);
        if (FAILED(hres)) return result;

        IWbemServices* pSvc = nullptr;
        hres = pLoc->ConnectServer(
            _bstr_t(skCrypt(L"ROOT\\CIMV2")), NULL, NULL, 0, NULL, 0, 0, &pSvc);
        if (FAILED(hres)) return result;

        hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
        if (FAILED(hres)) return result;

        IEnumWbemClassObject* pEnumerator = nullptr;
        hres = pSvc->ExecQuery(
            bstr_t(skCrypt("WQL")),
            bstr_t(std::wstring(skCrypt(L"SELECT ").decrypt() + wmiProperty + skCrypt(L" FROM ").decrypt() + wmiClass).c_str()),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL, &pEnumerator);

        if (FAILED(hres)) return result;

        IWbemClassObject* pclsObj = nullptr;
        ULONG uReturn = 0;
        if (pEnumerator) {
            pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (uReturn) {
                VARIANT vtProp;
                pclsObj->Get(wmiProperty.c_str(), 0, &vtProp, 0, 0);
                result = _bstr_t(vtProp.bstrVal);
                VariantClear(&vtProp);
                pclsObj->Release();
            }
            pEnumerator->Release();
        }

        pSvc->Release();
        pLoc->Release();
        CoUninitialize();

        return result;
    }
    std::string get_user_cid() {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return {};

        DWORD size = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &size);
        std::vector<BYTE> buffer(size);
        if (!GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) return {};

        SID* sid = reinterpret_cast<SID*>(((TOKEN_USER*)buffer.data())->User.Sid);
        LPSTR sidString = nullptr;
        ConvertSidToStringSidA(sid, &sidString);

        std::string result = sidString ? sidString : "";
        LocalFree(sidString);
        CloseHandle(token);
        return result;
    }

    std::vector<std::string> get_disk_serials() {
        std::vector<std::string> result;
        HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) return result;

        CoInitializeSecurity(NULL, -1, NULL, NULL,
            RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

        IWbemLocator* pLoc = nullptr;
        CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
            IID_IWbemLocator, (LPVOID*)&pLoc);

        IWbemServices* pSvc = nullptr;
        pLoc->ConnectServer(
            _bstr_t(skCrypt(L"ROOT\\CIMV2")), NULL, NULL, 0, NULL, 0, 0, &pSvc);

        CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

        IEnumWbemClassObject* pEnumerator = nullptr;
        pSvc->ExecQuery(
            bstr_t(skCrypt("WQL")),
            bstr_t(skCrypt("SELECT SerialNumber FROM Win32_PhysicalMedia")),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL, &pEnumerator);

        IWbemClassObject* pclsObj = nullptr;
        ULONG uReturn = 0;

        while (pEnumerator && pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn) == S_OK) {
            VARIANT vtProp;
            pclsObj->Get(skCrypt(L"SerialNumber"), 0, &vtProp, 0, 0);
            if (vtProp.vt == VT_BSTR && vtProp.bstrVal != nullptr)
                result.emplace_back(_bstr_t(vtProp.bstrVal));
            VariantClear(&vtProp);
            pclsObj->Release();
        }

        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return result;
    }

    std::string get_gpu_serial() {
        return get_wmi_value(skCrypt(L"Win32_VideoController").decrypt(), skCrypt(L"PNPDeviceID").decrypt()); // или "DeviceID"
    }

    std::vector<std::string> get_ram_serial() {
        std::vector<std::string> serials;
        HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) return serials;

        CoInitializeSecurity(NULL, -1, NULL, NULL,
            RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

        IWbemLocator* pLoc = nullptr;
        CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
            IID_IWbemLocator, (LPVOID*)&pLoc);

        IWbemServices* pSvc = nullptr;
        pLoc->ConnectServer(
            _bstr_t(skCrypt(L"ROOT\\CIMV2")), NULL, NULL, 0, NULL, 0, 0, &pSvc);

        CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

        IEnumWbemClassObject* pEnumerator = nullptr;
        pSvc->ExecQuery(
            bstr_t(skCrypt("WQL")),
            bstr_t(skCrypt("SELECT SerialNumber FROM Win32_PhysicalMemory")),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL, &pEnumerator);

        IWbemClassObject* pclsObj = nullptr;
        ULONG uReturn = 0;

        while (pEnumerator && pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn) == S_OK) {
            VARIANT vtProp;
            pclsObj->Get(skCrypt(L"SerialNumber"), 0, &vtProp, 0, 0);
            if (vtProp.vt == VT_BSTR && vtProp.bstrVal != nullptr)
                serials.emplace_back(_bstr_t(vtProp.bstrVal));
            VariantClear(&vtProp);
            pclsObj->Release();
        }

        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return serials;
    }

    std::string get_cpu_serial() {
        return get_wmi_value(skCrypt(L"Win32_Processor").decrypt(), skCrypt(L"ProcessorId").decrypt());
    }

}
