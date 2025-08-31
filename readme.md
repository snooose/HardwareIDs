# HardwareIDApplication

A Windows C++ application for retrieving unique hardware identifiers and generating system fingerprints.  
This project gathers information such as MAC addresses, motherboard serial, CPU serial, HDD serials, and Machine GUID, and can produce SHA-256 hash fingerprints of the system.

## Features

- Retrieve Machine GUID (Windows unique identifier)
- Retrieve current and all network adapter MAC addresses (Ethernet/Wi-Fi)
- Query motherboard, CPU, and HDD serial numbers via WMI
- Get individual HDD serial or all HDD serials
- Output all hardware IDs as a JSON object or JSON array
- Generate SHA-256 hash fingerprints from hardware IDs
- Custom SHA-256 encoding functionality

## Requirements

- Windows OS
- Visual Studio 2022 (or compatible C++ compiler)
- Windows SDK (for headers/libraries: `iphlpapi`, `wbemuuid`, `advapi32`)
- C++17 or later

## Building

1. Open the solution in Visual Studio.
2. Build the project (all dependencies are standard Windows libraries).

## Usage

The main logic is in `hardwareID.cpp` and provides the following functions:

### Hardware ID Retrieval
- `GetMachineGUID()` - Get Windows Machine GUID. This identifier is unique to each Windows installation, but can change if Windows is reinstalled.
- `GetCurrentNetworkMAC()` - Get MAC address of current network adapter. This is typically the MAC of the active Ethernet or Wi-Fi adapter. Will change if a different adapter is used.
- `GetAllNetworkMACs()` - Get all network adapter MAC addresses. This includes all Ethernet and Wi-Fi adapters on the system.
- `GetMotherboardSerial()` - Get motherboard serial number. This is usually unique to the physical motherboard, but can be missing or generic on some systems. If unavailable, returns L"UNKNOWN_OR_UNDEFINED_MOBO_SERIAL".
- `GetCPUSerial()` - Get CPU serial number. Note that many modern CPUs do not expose a unique serial number, so this may return L"UNKNOWN_OR_UNDEFINED_CPU_SERIAL".
- `GetHDDSerial(  )` - Get primary HDD serial number. This is typically unique to the physical hard drive, but can be missing or generic on some systems. If unavailable, returns L"UNKNOWN_OR_UNDEFINED_HDD_SERIAL". This will only return data of the first physical drive in WMI, and the order can be changed at anytime.
- `GetAllHDDSerials()` - Get all HDD serial numbers. This retrieves serials for all physical drives on the system. Since the order can be changed, this is more reliable than just getting the first drive.

### Data Output
- `GetAllHardwareIDs()` - Get all hardware IDs as vector. Returns a vector of wide strings containing all retrieved hardware IDs. Uses above functions GetAllNetworkMACs, GetMotherboardSerial, GetCPUSerial, and GetAllHDDSerials.
- `GetAllHardwareIDsJson()` - Get all hardware IDs as JSON object. Returns a JSON-formatted wide string containing all retrieved hardware IDs from the above method in key-value pairs.
- `GetAllHardwareIDsJsonArray()` - Get all hardware IDs as JSON array. Returns a JSON-formatted wide string containing all retrieved hardware IDs from the above method in a flat array format.

### Fingerprinting
- `GetSystemFingerprintSHA256HashLow()` - Generate a unique SHA256 hash fingerprint of the system (low reliability). Uses the same data as GetAllHardwareIDs to generate the hash. This fingerprint is less reliable as it contains ID's that are not reliable and or the order can be changed (ie. WMI drives order)
- `GetSystemFingerprintSHA256HashHigh()` - Generate system fingerprint (high reliability).  Uses only GetCurrentNEtworkMAC, GetMotherboardSerial, and GetCPUSerial to generate a more reliable fingerprint. This fingerprint is more reliable as it uses ID's that are more likely to be unique and stable.
- `EncodeSHA256Hash()` - Custom SHA-256 encoding function. Can be leveraged to take any subset of the above commands and generate a SHA-256 hash.

## Example

```cpp
#include "hardwareID.h"
#include <iostream>

int main() {
    std::wcout << L"System Hardware IDs (JSON): " << GetAllHardwareIDsJson() << std::endl;
    std::wcout << L"System Fingerprint (Low): " << GetSystemFingerprintSHA256HashLow() << std::endl;
    std::wcout << L"System Fingerprint (High): " << GetSystemFingerprintSHA256HashHigh() << std::endl;
    return 0;
}
```

## License

This project is provided for educational and informational purposes.
