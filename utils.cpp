#include "Utils.hpp"
#include <iostream>

namespace Utils {
    const DWORD getProcId(const char* procName) {
        const auto procHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 pe32;
        if (procHandle == INVALID_HANDLE_VALUE || !procHandle) {
            std::cerr << "Failed to create process snapshot.\n";
            return INVALID_HANDLE_ID;  // Error handling
        }

        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(procHandle, &pe32)) {
            std::cerr << "Failed to retrieve the first process.\n";
            CloseHandle(procHandle);
            return INVALID_PROCESS_ID;
        }

        do {
            if (!strcmp(pe32.szExeFile, procName)) {
                CloseHandle(procHandle);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(procHandle, &pe32));

        CloseHandle(procHandle);
        return PROCESS_NOT_FOUND;
    }

    bool LoadDllFile(const char* dllPath, BYTE*& pSrcData, SIZE_T& fileSize, HANDLE procHandle) {
        // Open the file in binary mode and position at the end to get the size
        std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
        if (file.fail()) {
            printf("Opening the file failed: %X\n", (DWORD)file.rdstate());
            file.close();
            CloseHandle(procHandle);
            system("PAUSE");
            return false;
        }

        // Get the size of the file
        fileSize = static_cast<SIZE_T>(file.tellg());
        if (fileSize < 0x1000) {
            printf("Filesize invalid.\n");
            file.close();
            CloseHandle(procHandle);
            system("PAUSE");
            return false;
        }

        // Allocate memory for the DLL data
        pSrcData = new BYTE[fileSize];
        if (!pSrcData) {
            printf("Can't allocate memory for the DLL file.\n");
            file.close();
            CloseHandle(procHandle);
            system("PAUSE");
            return false;
        }

        // Read the file into memory
        file.seekg(0, std::ios::beg);
        file.read(reinterpret_cast<char*>(pSrcData), fileSize);
        file.close();

        return true; // Successfully loaded the file
    }

    bool ElevatePrivilege(const char* privilegeName) {
        HANDLE token = NULL;

        // Open the process token
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
            std::cerr << "Error: Failed to open process token. Error code: " << GetLastError() << "\n";
            return false;
        }

        // Ensure the handle is closed properly
        TOKEN_PRIVILEGES tokenPriv = { 0 };
        tokenPriv.PrivilegeCount = 1;

        // Lookup the LUID for the specified privilege
        if (!LookupPrivilegeValue(NULL, privilegeName, &tokenPriv.Privileges[0].Luid)) {
            std::cerr << "Error: Failed to lookup privilege value for " << privilegeName
                << ". Error code: " << GetLastError() << "\n";
            CloseHandle(token);
            return false;
        }

        tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        // Attempt to adjust the token privileges
        if (!AdjustTokenPrivileges(token, FALSE, &tokenPriv, 0, NULL, NULL)) {
            std::cerr << "Error: Failed to adjust token privileges. Error code: " << GetLastError() << "\n";
            CloseHandle(token);
            return false;
        }

        // Check if the privilege was successfully assigned
        if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
            std::cerr << "Warning: Privilege " << privilegeName << " was not assigned.\n";
            CloseHandle(token);
            return false;
        }

        CloseHandle(token);
        return true; // Success
    }
}
