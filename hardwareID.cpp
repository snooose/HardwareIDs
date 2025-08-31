#include "hardwareID.h"

#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#include <comdef.h>
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")
#include <wincrypt.h>
#include <sstream>
#include <filesystem>
#pragma comment(lib, "advapi32.lib")

#ifndef MIB_IF_TYPE_IEEE80211
#define MIB_IF_TYPE_IEEE80211 71
#endif

// Returns the MAC address of the currently active network adapter (Ethernet or Wi-Fi)
std::wstring GetCurrentNetworkMAC() {
	IP_ADAPTER_INFO AdapterInfo[16];
	DWORD bufLen = sizeof(AdapterInfo);

	if (GetAdaptersInfo(AdapterInfo, &bufLen) != NO_ERROR) {
		return L""; // Failed to get adapter info
	}

	PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
	while (pAdapterInfo) {
		if (pAdapterInfo->Type == MIB_IF_TYPE_ETHERNET || pAdapterInfo->Type == MIB_IF_TYPE_IEEE80211) { // Ethernet or Wi-Fi
			if (pAdapterInfo->IpAddressList.IpAddress.String[0] != '0' && pAdapterInfo->IpAddressList.IpAddress.String[0] != '\0') { // Has an IP address
				wchar_t macAddr[18];
				swprintf_s(macAddr, sizeof(macAddr) / sizeof(wchar_t), L"%02X-%02X-%02X-%02X-%02X-%02X",
					pAdapterInfo->Address[0], pAdapterInfo->Address[1], pAdapterInfo->Address[2],
					pAdapterInfo->Address[3], pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
				return std::wstring(macAddr);
			}
		}
		pAdapterInfo = pAdapterInfo->Next;
	}

	return L""; // Nothing found
}

// Returns the MAC addresses of all network adapters (Ethernet or Wi-Fi)
std::vector<std::wstring> GetAllNetworkMACs() {
	std::vector<std::wstring> macAddresses;
	IP_ADAPTER_INFO AdapterInfo[16];
	DWORD bufLen = sizeof(AdapterInfo);

	if (GetAdaptersInfo(AdapterInfo, &bufLen) != NO_ERROR) {
		return macAddresses; // Failed to get adapter info
	}

	PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
	while (pAdapterInfo) {
		if (pAdapterInfo->Type == MIB_IF_TYPE_ETHERNET || pAdapterInfo->Type == MIB_IF_TYPE_IEEE80211) { // Ethernet or Wi-Fi
			wchar_t macAddr[18];
			swprintf_s(macAddr, sizeof(macAddr) / sizeof(wchar_t), L"%02X-%02X-%02X-%02X-%02X-%02X",
				pAdapterInfo->Address[0], pAdapterInfo->Address[1], pAdapterInfo->Address[2],
				pAdapterInfo->Address[3], pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
			macAddresses.push_back(std::wstring(macAddr));
		}
		pAdapterInfo = pAdapterInfo->Next;
	}

	return macAddresses;
}

// Helper function to query WMI for a specific property
std::wstring QueryWMIProperty(const wchar_t* wmiClass, const wchar_t* property) {
    HRESULT hres;
    std::wstring result;

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return L"";

    hres = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL);
    if (FAILED(hres) && hres != RPC_E_TOO_LATE) {
        CoUninitialize();
        return L"";
    }

    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(
        CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        CoUninitialize();
        return L"";
    }

    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        pLoc->Release();
        CoUninitialize();
        return L"";
    }

    hres = CoSetProxyBlanket(
        pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return L"";
    }

    // Build the query string
    std::wstring query = L"SELECT ";
    query += property;
    query += L" FROM ";
    query += wmiClass;

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(query.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &pEnumerator);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return L"";
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    if (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (uReturn != 0) {
            VARIANT vtProp;
            hr = pclsObj->Get(property, 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                result = vtProp.bstrVal;
            }
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

// Same helper function but grabs all instances of the property in case there are multiple (like multiple drives, etc)
std::vector<std::wstring> QueryWMIPropertyAll(const wchar_t* wmiClass, const wchar_t* property) {
    HRESULT hres;
    std::vector<std::wstring> results;

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return results;

    hres = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL);
    if (FAILED(hres) && hres != RPC_E_TOO_LATE) {
        CoUninitialize();
        return results;
    }

    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(
        CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        CoUninitialize();
        return results;
    }

    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        pLoc->Release();
        CoUninitialize();
        return results;
    }

    hres = CoSetProxyBlanket(
        pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return results;
    }

    std::wstring query = L"SELECT ";
    query += property;
    query += L" FROM ";
    query += wmiClass;

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(query.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &pEnumerator);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return results;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    while (pEnumerator && pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn) == S_OK && uReturn != 0) {
        VARIANT vtProp;
        HRESULT hr = pclsObj->Get(property, 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
            results.push_back(vtProp.bstrVal);
        }
        VariantClear(&vtProp);
        pclsObj->Release();
    }
    if (pEnumerator) pEnumerator->Release();

    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    return results;
}

// Returns the motherboard serial number
std::wstring GetMotherboardSerial() {
    std::wstring serial = QueryWMIProperty(L"Win32_BaseBoard", L"SerialNumber");
    if (serial.empty()) serial = L"UNKNOWN_OR_UNDEFINED_MOBO_SERIAL";
    return serial;
}

// Returns the CPU serial number
std::wstring GetCPUSerial() {
    std::wstring serial = QueryWMIProperty(L"Win32_Processor", L"ProcessorId");
    if (serial.empty()) serial = L"UNKNOWN_OR_UNDEFINED_CPU_SERIAL";
    return serial;
}

// Returns the HDD serial number of the first physical drive in WMI. The drive order can change if a user makes bios changes to boot order, hardware changes, etc
std::wstring GetHDDSerial() {
    std::wstring serial = QueryWMIProperty(L"Win32_PhysicalMedia", L"SerialNumber");
    if (serial.empty()) serial = L"UNKNOWN_OR_UNDEFINED_HDD_SERIAL";
    return serial;
}

std::vector<std::wstring> GetAllHDDSerials() {
    std::vector<std::wstring> serials = QueryWMIPropertyAll(L"Win32_PhysicalMedia", L"SerialNumber");
    if (serials.empty()) serials.push_back(L"UNKNOWN_OR_UNDEFINED_HDD_SERIAL");
    return serials;
}

std::wstring GetMachineGUID() {
    HKEY hKey;
    wchar_t guid[256];
    DWORD bufLen = sizeof(guid);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueEx(hKey, L"MachineGuid", NULL, NULL, (LPBYTE)guid, &bufLen) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return std::wstring(guid);
        }
        RegCloseKey(hKey);
    }
	return L"UNKNOWN_OR_UNDEFINED_MACHINE_GUID";
}

std::vector<std::wstring> GetAllHardwareIDs() {
    std::vector<std::wstring> hardwareIDs;

    std::vector<std::wstring> allNICMACs = GetAllNetworkMACs();
    for (const auto& mac : allNICMACs) {
        if (!mac.empty()) {
            hardwareIDs.push_back(mac);
        }
    }

    std::wstring motherboardSerial = GetMotherboardSerial();
    if (!motherboardSerial.empty()) {
        hardwareIDs.push_back(motherboardSerial);
    }

    std::wstring cpuSerial = GetCPUSerial();
    if (!cpuSerial.empty()) {
        hardwareIDs.push_back(cpuSerial);
    }

    std::vector<std::wstring> allHDDSerials = GetAllHDDSerials();
    for (const auto& serial : allHDDSerials) {
        if (!serial.empty()) {
            hardwareIDs.push_back(serial);
        }
    }
    return hardwareIDs;
}

std::wstring EscapeQuotes(const std::wstring& input) {
    std::wstring output;
    for (wchar_t ch : input) {
        if (ch == L'"' || ch == L'\'') {
            output += L'\\';
        }
        output += ch;
    }
    return output;
}

std::wstring VectorToJsonArray(const std::vector<std::wstring>& vec) {
    std::wstring result = L"[";
    for (size_t i = 0; i < vec.size(); ++i) {
        result += L"\"" + EscapeQuotes(vec[i]) + L"\"";
        if (i != vec.size() - 1) {
            result += L", ";
        }
    }
    result += L"]";
    return result;
}

std::wstring GetAllHardwareIDsJsonArray() {
    std::vector<std::wstring> allHardwareIDs = GetAllHardwareIDs();
    return VectorToJsonArray(allHardwareIDs);
}

std::string SHA256FromWString(const std::wstring& input) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[32];
    DWORD cbHash = 32;
    std::string result;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return "";
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }

    CryptHashData(hHash, reinterpret_cast<const BYTE*>(input.c_str()), input.size() * sizeof(wchar_t), 0);
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        std::ostringstream oss;
        for (DWORD i = 0; i < cbHash; i++)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)rgbHash[i];
        result = oss.str();
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
}

std::wstring GetSystemFingerprintSHA256HashLow() {
    std::wstring allHardwareIDs = GetAllHardwareIDsJson();
    std::string sha256Hash = SHA256FromWString(allHardwareIDs);
    if (sha256Hash.length() < 16) return L"";
    return std::wstring(sha256Hash.begin(), sha256Hash.begin() + 16);
}

std::wstring GetSystemFingerprintSHA256HashHigh() {
    std::wstring networkMAC = GetCurrentNetworkMAC();
    std::wstring motherboardSerial = GetMotherboardSerial();
    std::wstring cpuSerial = GetCPUSerial();
    std::vector<std::wstring> components = { networkMAC, motherboardSerial, cpuSerial };
    std::wstring combined = VectorToJsonArray(components);
    std::string sha256Hash = SHA256FromWString(combined);
    if (sha256Hash.length() < 16) return L"";
    return std::wstring(sha256Hash.begin(), sha256Hash.begin() + 16);
}

std::wstring GetAllHardwareIDsJson() {
    std::wstring currentNICMAC = GetCurrentNetworkMAC();
    std::vector<std::wstring> allNICMACs = GetAllNetworkMACs();
    std::wstring motherboardSerial = GetMotherboardSerial();
    std::wstring cpuSerial = GetCPUSerial();
    std::vector<std::wstring> allHDDSerials = GetAllHDDSerials();

    std::wstringstream ss;
    ss << L"{";
    ss << L"\"CurrentNICMAC\":\"" << EscapeQuotes(currentNICMAC) << L"\",";
    ss << L"\"AllNICMACs\":" << VectorToJsonArray(allNICMACs) << L",";
    ss << L"\"MotherboardSerial\":\"" << EscapeQuotes(motherboardSerial) << L"\",";
    ss << L"\"CPUSerial\":\"" << EscapeQuotes(cpuSerial) << L"\",";
    ss << L"\"AllHDDSerials\":" << VectorToJsonArray(allHDDSerials);
    ss << L"}";
    return ss.str();
}

std::wstring EncodeSHA256Hash(std::wstring string) {
	std::string sha256Hash = SHA256FromWString(string);
    if (sha256Hash.length() < 16) return L"";
    return std::wstring(sha256Hash.begin(), sha256Hash.begin() + 16);
}