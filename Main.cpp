#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <fstream>
#include <stdio.h>
#include <string>
#include <optional>
#include "ManualMapper.hpp"

constexpr DWORD INVALID_HANDLE_ID   = static_cast<DWORD>(-1);
constexpr DWORD INVALID_PROCESS_ID  = static_cast<DWORD>(-2);
constexpr DWORD PROCESS_NOT_FOUND   = static_cast<DWORD>(-3);

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


// i love optional 
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

int main() {
	const char procName[] = "cs2.exe";
	const char* dllPath = "C:\\Users\\user6900\\Desktop\\Simple-Manual-Map-Injector-master\\hello-world-x64.dll";

    const DWORD procId = getProcId(procName);

    std::cout << "found process at ID: " << procId << std::endl;

    if (ElevatePrivilege(SE_DEBUG_NAME)) {
        std::cout << "SE_DEBUG_NAME privilege elevated successfully.\n";
    }
    else {
        std::cerr << "Failed to elevate SE_DEBUG_NAME privilege.\n";
    }

    const HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procId);

    if (hProc == INVALID_HANDLE_VALUE) {
        const auto err = GetLastError();
        std::cerr << "Handle is invalid HANDLE VALUE " << (DWORD)hProc << "| Last Error code: " << err << std::endl;
        return EXIT_FAILURE;
    }

    const auto dllSize = resolveDll(dllPath);

    if (!dllSize) {
        std::cerr << "Failed to resolve DLL file: " << dllPath << "\n";
        CloseHandle(hProc);
        return EXIT_FAILURE;
    }
 
    return 0;
}
