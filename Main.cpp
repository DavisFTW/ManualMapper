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

    std::ifstream File(dllPath, std::ios::binary | std::ios::ate);

    if (File.fail()) {
        printf("Opening the file failed: %X\n", (DWORD)File.rdstate());
        File.close();
        CloseHandle(procHandle);
        system("PAUSE");
        return -5;
    }

    auto FileSize = File.tellg();
    if (FileSize < 0x1000) {
        printf("Filesize invalid.\n");
        File.close();
        CloseHandle(procHandle);
        system("PAUSE");
        return -6;
    }

    // maps the dll into our process we can now close file 
    BYTE* pSrcData = new BYTE[(UINT_PTR)FileSize];  
    if (!pSrcData) {
        printf("Can't allocate dll file.\n");
        File.close();
        CloseHandle(procHandle);
        system("PAUSE");
        return -7;
    }

    File.seekg(0, std::ios::beg);
    File.read((char*)(pSrcData), FileSize);
    File.close();

    const auto mapper = std::make_unique<ManualMapper>(procHandle, pSrcData, FileSize);

    if (!mapper->run()) {
        system("PAUSE");
        std::cerr << "mapper failed\n";
        CloseHandle(procHandle);
        delete[] pSrcData;
    }

    
    CloseHandle(procHandle);
    delete[] pSrcData;
    return EXIT_SUCCESS;
}