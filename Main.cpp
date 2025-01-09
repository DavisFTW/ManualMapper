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
        system("PAUSE");
        return EXIT_FAILURE;
    }
    std::cout << "Found process ID: " << procId << "\n";


    // Elevate privilege
    if (!Utils::ElevatePrivilege(SE_DEBUG_NAME)) {
        std::cerr << "Failed to elevate SE_DEBUG_NAME privilege.\n";
        system("PAUSE");
        return EXIT_FAILURE;
    }
    std::cout << "Privilege elevated successfully.\n";

    HANDLE procHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procId);
    if (!procHandle) {
        DWORD Err = GetLastError();
        std::cerr << "Failed to Open Process ERR: " << Err << std::endl;
        system("PAUSE");
        return EXIT_FAILURE;
    }

    BYTE* pSrcData = nullptr; // Will hold the DLL data
    SIZE_T fileSize = 0;      // Will hold the size of the DLL file

    if (!Utils::LoadDllFile(dllPath, pSrcData, fileSize, procHandle)) {
        printf("Failed to load DLL file.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}