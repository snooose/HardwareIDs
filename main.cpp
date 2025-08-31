#pragma once
#include <iostream>
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

#include "hardwareID.h"

int main() {
	std::wcout << L"Reading ID's from system..." << std::endl;

	std::wstring machineGUID = GetMachineGUID();
	std::wcout << L"Machine GUID: " << machineGUID << std::endl;

	std::wstring currentNICMAC = GetCurrentNetworkMAC();
	std::wcout << L"Current NIC: " << currentNICMAC << std::endl;

	std::vector<std::wstring> allNICMACs = GetAllNetworkMACs();
	for (const auto& mac : allNICMACs) {
		std::wcout << L"Found NIC: " << mac << std::endl;
	}

	std::wstring motherboardSerial = GetMotherboardSerial();
	std::wcout << L"Motherboard Serial: " << motherboardSerial << std::endl;

	std::wstring cpuSerial = GetCPUSerial();
	std::wcout << L"CPU Serial: " << cpuSerial << std::endl;

	std::wstring hddSerial = GetHDDSerial();
	std::wcout << L"HDD Serial: " << hddSerial << std::endl;
	
	std::vector<std::wstring> allHDDSerials = GetAllHDDSerials();
	for (const auto& serial : allHDDSerials) {
		std::wcout << L"Found HDD Serial: " << serial << std::endl;
	}

	std::vector<std::wstring> allHardwareIDs = GetAllHardwareIDs();
	std::wcerr << std::endl;
	for (const auto& id : allHardwareIDs) {
		std::wcout << L"Found Hardware ID: " << id << std::endl;
	}

	std::wstring allHardwareIDsJsonArray = GetAllHardwareIDsJsonArray();
	std::wcout << L"All Hardware IDs JSON Array: " << allHardwareIDsJsonArray << std::endl;

	std::wstring allHardwareIDsJson = GetAllHardwareIDsJson();
	std::wcout << L"All Hardware IDs JSON: " << allHardwareIDsJson << std::endl;

	std::wcerr << std::endl;

	std::wstring systemFingerprintHashLow = GetSystemFingerprintSHA256HashLow();
	std::wcout << L"System Fingerprint SHA256 Hash Low: " << systemFingerprintHashLow << std::endl;

	std::wstring systemFingerprintHashHigh = GetSystemFingerprintSHA256HashHigh();
	std::wcout << L"System Fingerprint SHA256 Hash High: " << systemFingerprintHashHigh << std::endl;

	std::wstring testHash = EncodeSHA256Hash(L"TestString123");
	std::wcout << L"Test String SHA256 Hash: " << testHash << std::endl;

	std::wcout << L"Press Enter to exit..." << std::endl;
	std::wcin.get();
	return 0;
}
