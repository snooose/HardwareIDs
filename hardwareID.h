#pragma once
#include <string>
#include <vector>

std::wstring GetCurrentNetworkMAC();
std::vector<std::wstring> GetAllNetworkMACs();
std::wstring GetMotherboardSerial();
std::wstring GetCPUSerial();
std::wstring GetHDDSerial();
std::vector<std::wstring> GetAllHDDSerials();
std::wstring GetMachineGUID();

std::vector<std::wstring> GetAllHardwareIDs();
std::wstring GetAllHardwareIDsJsonArray();
std::wstring GetAllHardwareIDsJson();

std::string SHA256FromWString(const std::wstring& input);

std::wstring GetSystemFingerprintSHA256HashLow();
std::wstring GetSystemFingerprintSHA256HashHigh();

std::wstring EncodeSHA256Hash(std::wstring string);