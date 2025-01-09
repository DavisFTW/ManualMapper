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

    std::optional<std::streampos> resolveDll(const char* dllPath) {
        std::ifstream File(dllPath, std::ios::binary | std::ios::ate);

        if (!File.is_open()) {
            std::cerr << "Error: Could not open file at " << dllPath << "\n";
            return std::nullopt;
        }
        const auto FileSize = File.tellg();

        if (FileSize < 0x1000) {
            std::cerr << "Invalid DLL file\n";
            return std::nullopt;
        }

        return FileSize;
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
