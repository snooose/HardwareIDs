# HardwareIDApplication

A Windows C++ application for retrieving unique hardware identifiers and generating system fingerprints.  
This project gathers information such as MAC addresses, motherboard serial, CPU serial, and HDD serials, and can produce a SHA-256 hash fingerprint of the system.

## Features

- Retrieve current and all network adapter MAC addresses (Ethernet/Wi-Fi)
- Query motherboard, CPU, and HDD serial numbers via WMI
- Output all hardware IDs as a JSON object or array
- Generate SHA-256 hash fingerprints from hardware IDs

## Requirements

- Windows OS
- Visual Studio (or compatible C++ compiler)
- Windows SDK (for headers/libraries: `iphlpapi`, `wbemuuid`, `advapi32`)
- C++17 or later

## Building

1. Open the solution in Visual Studio.
2. Build the project (all dependencies are standard Windows libraries).

## Usage

The main logic is in `hardwareID.cpp` and can be used to:

- Get MAC addresses:  
  `GetCurrentNetworkMAC()`, `GetAllNetworkMACs()`
- Get serials:  
  `GetMotherboardSerial()`, `GetCPUSerial()`, `GetHDDSerial()`, `GetAllHDDSerials()`
- Get all hardware IDs as JSON:  
  `GetAllHardwareIDsJson()`
- Generate system fingerprint hash:  
  `GetSystemFingerprintSHA256HashLow()`, `GetSystemFingerprintSHA256HashHigh()`

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
