#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <fstream>
#include <stdio.h>
#include <string>
#include <optional>
#include "ManualMapper.hpp"
#include "Utils.hpp"

int main() {
    const char procName[] = "cs2.exe";
    const char* dllPath = "C:\\path\\to\\your\\dll.dll";

    // Get process ID
    const DWORD procId = Utils::getProcId(procName);
    if (procId == Utils::PROCESS_NOT_FOUND) {
        std::cerr << "Process not found: " << procName << "\n";
        return EXIT_FAILURE;
    }
    std::cout << "Found process ID: " << procId << "\n";

    // Resolve DLL
    const auto dllSize = Utils::resolveDll(dllPath);
    if (!dllSize) {
        std::cerr << "Failed to resolve DLL at: " << dllPath << "\n";
        return EXIT_FAILURE;
    }
    std::cout << "DLL size: " << *dllSize << " bytes\n";

    // Elevate privilege
    if (!Utils::ElevatePrivilege(SE_DEBUG_NAME)) {
        std::cerr << "Failed to elevate SE_DEBUG_NAME privilege.\n";
        return EXIT_FAILURE;
    }
    std::cout << "Privilege elevated successfully.\n";

    return EXIT_SUCCESS;
}